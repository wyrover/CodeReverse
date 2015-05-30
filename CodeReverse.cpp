////////////////////////////////////////////////////////////////////////////
// CodeReverse.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

const char * const cr_logo =
    "///////////////////////////////////////////////\n"
#ifdef _WIN64
    "// CodeReverse 0.2.6 (64-bit)                //\n"
#else   // ndef _WIN64
    "// CodeReverse 0.2.6 (32-bit)                //\n"
#endif  // ndef _WIN64
    "// https://github.com/katahiromz/CodeReverse //\n"
    "// katayama.hirofumi.mz@gmail.com            //\n"
    "///////////////////////////////////////////////\n";

#define cr_default_stack_size "4KB"

////////////////////////////////////////////////////////////////////////////

void CrShowHelp(void) {
#ifdef _WIN64
    fprintf(stderr,
        " Usage: coderev64 [options] file1.exe [file2.dll ...]\n");
#else
    fprintf(stderr,
        " Usage: coderev [options] file1.exe [file2.dll ...]\n");
#endif
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -a    ANSI mode (not Unicode)\n");
    fprintf(stderr, " -h    dump headers\n");
    fprintf(stderr, " -i    dump import table\n");
    fprintf(stderr, " -e    dump export table\n");
    fprintf(stderr, " -r    dump resource\n");
    fprintf(stderr, " -d    dump delayload info\n");
    fprintf(stderr, " -p    parse input file and do semantic analysis\n");
    fprintf(stderr, " -a    dump disassembly\n");
    fprintf(stderr, " -d    dump decompiled codes\n");
#ifdef _WIN64
    fprintf(stderr, " -m32  32-bit mode\n");
    fprintf(stderr, " -m64  64-bit mode (default)\n");
#else
    fprintf(stderr, " -m32  32-bit mode (default)\n");
    fprintf(stderr, " -m64  64-bit mode\n");
#endif
    fprintf(stderr, " --prefix PREFIX   Wonders API prefix\n");
    fprintf(stderr, " --suffix SUFFIX   Wonders API suffix\n");
    fprintf(stderr, " --wonders VER     Wonders API version (98/Me/2000/XP/Vista/7/8.1)\n");
    fprintf(stderr, " --stack SIZE      stack size (default: " cr_default_stack_size ")\n");
} // CrShowHelp

void CrDumpCommandLine(int argc, char **argv) {
    printf("Command Line:");
    for (int i = 0; i < argc; ++i) {
        if (i == 0) {
            #ifdef _WIN64
                printf(" coderev64");
            #else
                printf(" coderev");
            #endif
        } else {
            if (strchr(argv[i], ' ') || strchr(argv[i], '\t')) {
                printf(" \"%s\"", argv[i]);
            } else {
                printf(" %s", argv[i]);
            }
        }
    }
    printf("\n");
    fflush(stdout);
} // CrDumpCommandLine

std::string CrFormatBytes(CR_Addr64 size) {
    if (size >= 1024 * 1024 * 1024) {
        size /= 1024 * 1024 * 1024;
        return std::to_string(size) + "GB";
    }
    if (size >= 1024 * 1024) {
        size /= 1024 * 1024;
        return std::to_string(size) + "MB";
    }
    if (size >= 1024) {
        size /= 1024;
        return std::to_string(size) + "KB";
    }
    return std::to_string(size) + "B";
}

unsigned long long CrParseBytes(const char *str) {
    unsigned long long bytes = std::strtoull(str, NULL, 0);
    if (strchr(str, 'K') || strchr(str, 'k')) {
        bytes *= 1024;
    } else if (strchr(str, 'M') || strchr(str, 'm')) {
        bytes *= 1024 * 1024;
    } else if (strchr(str, 'G') || strchr(str, 'g')) {
        bytes *= 1024 * 1024 * 1024;
    }
    return bytes;
}

////////////////////////////////////////////////////////////////////////////

/* hacked by katahiromz */
extern "C"
int katahiromz_snprintf(char *buffer, int buf_size, const char *format, ...) {
    va_list va;
    va_start(va, format);
    int n = std::vsnprintf(buffer, buf_size, format, va);
    va_end(va);
    return n;
}

std::string CrGetExePath(void) {
    CHAR szPath[MAX_PATH];
    ::GetModuleFileNameA(NULL, szPath, MAX_PATH);
    char *p = strrchr(szPath, '\\');
    if (p) {
        *p = 0;
    }
    return std::string(szPath);
}

////////////////////////////////////////////////////////////////////////////

enum CR_EXIT_CODE {
    cr_exit_ok = 0,
    cr_exit_cant_load,
    cr_exit_bits_mismatched,
    cr_exit_invalid_option
};

enum CR_MODE_INDEXES {
    cr_MODE_ANSI,
    cr_MODE_DUMP_HEADERS,
    cr_MODE_DUMP_IMPORT,
    cr_MODE_DUMP_EXPORT,
    cr_MODE_DUMP_RESOURCE,
    cr_MODE_DUMP_DELAYLOAD,
    cr_MODE_DUMP_DISASM,
    cr_MODE_DUMP_DECOMPILE,
    cr_MODE_64BIT
};

struct CR_CodeReverse {
    bool                                    m_modes[9];
    std::vector<std::string>                m_files;
    std::vector<shared_ptr<CR_ModuleEx>>    m_modules;
    std::string                             m_prefix;
    std::string                             m_suffix;
    std::string                             m_wonders_ver;
    unsigned long long                      m_stack_size;
    shared_ptr<CR_ErrorInfo>                m_error_info;
    shared_ptr<CR_NameScope>                m_namescope;

    CR_CodeReverse() : m_wonders_ver("8.1") {
        memset(m_modes, 0, sizeof(m_modes));
        m_modes[cr_MODE_ANSI] = false;
        #ifdef _WIN64
            m_modes[cr_MODE_64BIT] = true;
        #else
            m_modes[cr_MODE_64BIT] = false;
        #endif

        m_stack_size = CrParseBytes(cr_default_stack_size);
    }

    int ParseCommandLine(int argc, char **argv);
    int JustDoIt();
    int DoFile(const std::string& file);
}; // struct CR_CodeReverse

int CR_CodeReverse::ParseCommandLine(int argc, char **argv) {
    const char *arg = NULL;
    bool defaulted = true;
    for (int i = 1; i < argc; ++i) {
        arg = argv[i];
        if (lstrcmpiA(arg, "--stack") == 0) {
            ++i;
            m_stack_size = CrParseBytes(argv[i]);
        } else if (lstrcmpiA(arg, "--prefix") == 0) {
            ++i;
            m_prefix = argv[i];
        } else if (lstrcmpiA(arg, "--suffix") == 0) {
            ++i;
            m_suffix = argv[i];
        } else if (lstrcmpiA(arg, "--wonders") == 0) {
            ++i;
            if (lstrcmpiA(argv[i], "98") == 0 ||
                lstrcmpiA(argv[i], "Me") == 0 ||
                lstrcmpiA(argv[i], "2000") == 0 ||
                lstrcmpiA(argv[i], "XP") == 0 ||
                lstrcmpiA(argv[i], "Vista") == 0 ||
                lstrcmpiA(argv[i], "7") == 0 ||
                lstrcmpiA(argv[i], "8.1") == 0)
            {
                m_wonders_ver = argv[i];
            } else {
                fprintf(stderr, "ERROR: Wonders API version must be 98, Me, 2000, XP, Vista, 7 or 8.1.\n");
                return cr_exit_invalid_option;
            }
        } else if (*arg == '-') {
            char ch = arg[1];
            if (ch == 'a' || ch == 'A') {
                m_modes[cr_MODE_ANSI] = true;
            } else if (ch == 'h' || ch == 'H') {
                m_modes[cr_MODE_DUMP_HEADERS] = true;
                defaulted = false;
            } else if (ch == 'i' || ch == 'I') {
                m_modes[cr_MODE_DUMP_IMPORT] = true;
                defaulted = false;
            } else if (ch == 'e' || ch == 'E') {
                m_modes[cr_MODE_DUMP_EXPORT] = true;
                defaulted = false;
            } else if (ch == 'r' || ch == 'R') {
                m_modes[cr_MODE_DUMP_RESOURCE] = true;
                defaulted = false;
            } else if (ch == 'd' || ch == 'D') {
                m_modes[cr_MODE_DUMP_DELAYLOAD] = true;
                defaulted = false;
            } else if (ch == 'p' || ch == 'P') {
                m_modes[cr_MODE_DUMP_DISASM] = true;
                defaulted = false;
            } else if (ch == 'd' || ch == 'D') {
                m_modes[cr_MODE_DUMP_DECOMPILE] = true;
                defaulted = false;
            } else if (strcmp(arg, "-m32") == 0) {
                m_modes[cr_MODE_64BIT] = false;
            } else if (strcmp(arg, "-m64") == 0) {
                m_modes[cr_MODE_64BIT] = true;
            } else {
                fprintf(stderr, "ERROR: invalid option '%s'\n", arg);
                return cr_exit_invalid_option;
            }
        } else {
            m_files.emplace_back(arg);
        }
    }

    if (defaulted) {
        for (int i = 0; i <= cr_MODE_DUMP_DECOMPILE; ++i) {
            m_modes[i] = true;
        }
    }

    if (m_prefix.empty()) {
        m_prefix = CrGetExePath();
        #if defined(_DEBUG) && defined(_MSC_VER)
            #ifdef _WIN64
                m_prefix += "\\..\\..";
            #else
                m_prefix += "\\..";
            #endif
        #endif
        m_prefix += "\\Wonders";
        m_prefix += m_wonders_ver;
        m_prefix += "\\";
    }

    if (m_suffix.empty()) {
        if (m_modes[cr_MODE_ANSI]) {
            if (m_modes[cr_MODE_64BIT]) {
                m_suffix = "-cl-64-a.dat";
            } else {
                m_suffix = "-cl-32-a.dat";
            }
        } else {
            if (m_modes[cr_MODE_64BIT]) {
                m_suffix = "-cl-64-w.dat";
            } else {
                m_suffix = "-cl-32-w.dat";
            }
        }
    }

    return 0;
} // CR_CodeReverse::ParseCommandLine

int CR_CodeReverse::DoFile(const std::string& file) {
    const char *pszModule = file.c_str();
    fprintf(stderr, "Loading module %s...\n", pszModule);

    auto module = make_shared<CR_ModuleEx>();
    if (!module->LoadModule(pszModule)) {
        fprintf(stderr, "ERROR: Cannot load module '%s', LastError = %lu\n",
                pszModule, module->LastError());
        return cr_exit_cant_load;
    }

    if (m_modes[cr_MODE_DUMP_HEADERS]) {
        fprintf(stderr, "Dumping module %s headers...\n", pszModule);
        module->DumpHeaders(stdout);
    }
    if (m_modes[cr_MODE_DUMP_IMPORT]) {
        fprintf(stderr, "Dumping module %s import table...\n", pszModule);
        module->DumpImportSymbols(stdout);
    }
    if (m_modes[cr_MODE_DUMP_EXPORT]) {
        fprintf(stderr, "Dumping module %s export table...\n", pszModule);
        module->DumpExportSymbols(stdout);
    }
    if (m_modes[cr_MODE_DUMP_RESOURCE]) {
        fprintf(stderr, "Dumping module %s resource...\n", pszModule);
        module->DumpResource(stdout);
    }
    if (m_modes[cr_MODE_DUMP_DELAYLOAD]) {
        fprintf(stderr, "Dumping module %s delayload info...\n", pszModule);
        module->DumpDelayLoad(stdout);
    }

    if (module->Is64Bit() && !m_modes[cr_MODE_64BIT]) {
        fprintf(stderr, "ERROR: Bits mismatched.\n");
        fprintf(stderr, "       The module was 64-bit and the mode was 32-bit.\n");
        return cr_exit_bits_mismatched;
    }

    if (!module->Is64Bit() && m_modes[cr_MODE_64BIT]) {
        fprintf(stderr, "ERROR: Bits mismatched.\n");
        fprintf(stderr, "       The module was 32-bit and the mode was 64-bit.\n");
        return cr_exit_bits_mismatched;
    }

    if (m_modes[cr_MODE_64BIT]) {
        fprintf(stderr, "Disassembling...\n");
        module->DisAsm64();
        fprintf(stderr, "Disassembled.\n");

        fprintf(stderr, "Decompiling...\n");
        //module->FixupAsm64();
        module->Decompile64();
        //fprintf(stderr, "Decompiled.\n");

#ifdef _DEBUG
        CrDoTest64(*module.get());
#endif

        if (m_modes[cr_MODE_DUMP_DISASM]) {
            fprintf(stderr, "Dumping disassembly...\n");
            module->DumpDisAsm64(stdout);
            fprintf(stderr, "Dumped.\n");
        }
        if (m_modes[cr_MODE_DUMP_DECOMPILE]) {
            fprintf(stderr, "Dumping decompiled codes...\n");
            module->DumpDecompile64(stdout);
            fprintf(stderr, "Dumped.\n");
        }
    } else {
        fprintf(stderr, "Disassembling...\n");
        module->DisAsm32();
        fprintf(stderr, "Disassembled.\n");

        fprintf(stderr, "Decompiling...\n");
        //module->FixupAsm32();
        module->Decompile32();
        //fprintf(stderr, "Decompiled.\n");

#ifdef _DEBUG
        CrDoTest32(*module.get());
#endif

        if (m_modes[cr_MODE_DUMP_DISASM]) {
            fprintf(stderr, "Dumping disassembly...\n");
            module->DumpDisAsm32(stdout);
            fprintf(stderr, "Dumped.\n");
        }
        if (m_modes[cr_MODE_DUMP_DECOMPILE]) {
            fprintf(stderr, "Dumping decompiled codes...\n");
            module->DumpDecompile32(stdout);
            fprintf(stderr, "Dumped.\n");
        }
    }

    m_modules.emplace_back(module);
    return 0;
} // CR_CodeReverse::DoFile

int CR_CodeReverse::JustDoIt() {
    fprintf(stderr, "stack size: %s (%llu)\n",
            CrFormatBytes(m_stack_size).c_str(), m_stack_size);
    fprintf(stderr, "Wonders API prefix: %s\n", m_prefix.c_str());
    fprintf(stderr, "Wonders API suffix: %s\n", m_suffix.c_str());

#if 0
    m_error_info = make_shared<CR_ErrorInfo>();
    if (m_modes[cr_MODE_64BIT]) {
        fprintf(stderr, "Loading type info...\n");
        m_namescope = make_shared<CR_NameScope>(m_error_info, true);
        if (!m_namescope->LoadFromFiles(m_prefix, m_suffix)) {
            fprintf(stderr, "WARNING: It requires Wonders API.\n");
            fprintf(stderr, "Please download it from http://katahiromz.esy.es/wonders/\n");
        } else {
            fprintf(stderr, "Loaded.\n");
        }
    } else {
        fprintf(stderr, "Loading type info...\n");
        m_namescope = make_shared<CR_NameScope>(m_error_info, false);
        if (!m_namescope->LoadFromFiles(m_prefix, m_suffix)) {
            fprintf(stderr, "WARNING: It requires Wonders API.\n");
            fprintf(stderr, "Please download it from http://katahiromz.esy.es/wonders/\n");
        } else {
            fprintf(stderr, "Loaded.\n");
        }
    }
#else
    fprintf(stderr, "Type info is not available.\n");
#endif

    for (auto& file : m_files) {
        int ret = DoFile(file);
        if (ret) {
            return ret;
        }
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int main(int argc, char **argv) {
    CR_CodeReverse cr;

    puts(cr_logo);

    if (argc <= 1 || strcmp(argv[1], "/?") == 0 ||
        lstrcmpiA(argv[1], "--help") == 0)
    {
        CrShowHelp();
        return cr_exit_ok;
    }

    if (lstrcmpiA(argv[1], "--version") == 0) {
        return cr_exit_ok;
    }

    CrDumpCommandLine(argc, argv);

    int ret = cr.ParseCommandLine(argc, argv);
    if (ret) {
        return ret;
    }

    ret = cr.JustDoIt();
    return ret;
} // main

////////////////////////////////////////////////////////////////////////////
