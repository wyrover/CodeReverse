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
# ifdef __GNUC__
    "// CodeReverse 0.1.9 (64-bit) for gcc        //\n"
# elif defined(_MSC_VER)
    "// CodeReverse 0.1.9 (64-bit) for cl         //\n"
# endif
#else   // ndef _WIN64
# ifdef __GNUC__
    "// CodeReverse 0.1.9 (32-bit) for gcc        //\n"
# elif defined(_MSC_VER)
    "// CodeReverse 0.1.9 (32-bit) for cl         //\n"
# endif
#endif  // ndef _WIN64
    "// https://github.com/katahiromz/CodeReverse //\n"
    "// katayama.hirofumi.mz@gmail.com            //\n"
    "///////////////////////////////////////////////\n";


////////////////////////////////////////////////////////////////////////////
// CR_TriBool - logical value of three states

void CR_TriBool::LogicalAnd(const CR_TriBool& tb1, const CR_TriBool& tb2) {
    if (tb1.m_value == TB_FALSE || tb2.m_value == TB_FALSE)
        m_value = TB_FALSE;
    else if (tb1.m_value == TB_TRUE)
        m_value = tb2.m_value;
    else if (tb2.m_value == TB_TRUE)
        m_value = tb1.m_value;
    else
        m_value = TB_UNKNOWN;
}

void CR_TriBool::LogicalOr(const CR_TriBool& tb1, const CR_TriBool& tb2) {
    if (tb1.m_value == TB_TRUE || tb2.m_value == TB_TRUE)
        m_value = TB_TRUE;
    else if (tb1.m_value == TB_FALSE)
        m_value = tb2.m_value;
    else if (tb2.m_value == TB_FALSE)
        m_value = tb1.m_value;
    else
        m_value = TB_UNKNOWN;
}

void CR_TriBool::Equal(const CR_TriBool& tb1, const CR_TriBool& tb2) {
    if (tb1.m_value == TB_UNKNOWN || tb2.m_value == TB_UNKNOWN) {
        m_value = TB_UNKNOWN;
        return;
    }
    m_value = (tb1.m_value == tb2.m_value ? TB_TRUE : TB_FALSE);
}

////////////////////////////////////////////////////////////////////////////

void CrShowHelp(void) {
#ifdef _WIN64
    fprintf(stderr,
        " Usage: coderev64 [options] exefile.exe\n");
#else
    fprintf(stderr,
        " Usage: coderev [options] exefile.exe\n");
#endif
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -a    ANSI mode (not Unicode)\n");
    fprintf(stderr, " -h    Dump headers\n");
    fprintf(stderr, " -i    Dump import table\n");
    fprintf(stderr, " -e    Dump export table\n");
    fprintf(stderr, " -r    Dump resource\n");
    fprintf(stderr, " -d    Dump delayload info\n");
    fprintf(stderr, " -p    Parse input file and do semantic analysis\n");
    fprintf(stderr, " -a    Dump disassembly\n");
#ifdef _WIN64
    fprintf(stderr, " -32   32-bit mode\n");
    fprintf(stderr, " -64   64-bit mode (default)\n");
#else
    fprintf(stderr, " -32   32-bit mode (default)\n");
    fprintf(stderr, " -64   64-bit mode\n");
#endif
    fprintf(stderr, " --prefix PREFIX   Wonders API prefix\n");
    fprintf(stderr, " --suffix SUFFIX   Wonders API suffix\n");
    fprintf(stderr, " --wonders VER     Wonders API version (98/Me/2000/XP/Vista/7/8.1)\n");
}

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

enum {
    cr_exit_ok = 0,
    cr_exit_cant_load,
    cr_exit_bits_mismatched,
    cr_exit_invalid_option
};

extern "C"
int main(int argc, char **argv) {
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

    enum MODE_INDEXES {
        MODE_ANSI,
        MODE_DUMP_HEADERS,
        MODE_DUMP_IMPORT,
        MODE_DUMP_EXPORT,
        MODE_DUMP_RESOURCE,
        MODE_DUMP_DELAYLOAD,
        MODE_DUMP_DISASM,
        MODE_64BIT
    };

    std::string prefix, suffix, wonders_ver = "8.1";

    bool modes[8];
    memset(modes, 0, sizeof(modes));
    modes[MODE_ANSI] = false;
    #ifdef _WIN64
        modes[MODE_64BIT] = true;
    #else
        modes[MODE_64BIT] = false;
    #endif

    const char *arg = NULL;
    bool defaulted = true;
    for (int i = 1; i < argc; ++i) {
        arg = argv[i];
        if (lstrcmpiA(arg, "--prefix") == 0) {
            ++i;
            prefix = argv[i];
        } else if (lstrcmpiA(arg, "--suffix") == 0) {
            ++i;
            suffix = argv[i];
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
                wonders_ver = argv[i];
            } else {
                fprintf(stderr, "ERROR: Wonders API version must be 98, Me, 2000, XP, Vista, 7 or 8.1.\n");
                return cr_exit_invalid_option;
            }
        } else if (*arg == '-') {
            char ch = arg[1];
            if (ch == 'a' || ch == 'A') {
                modes[MODE_ANSI] = true;
            } else if (ch == 'h' || ch == 'H') {
                modes[MODE_DUMP_HEADERS] = true;
                defaulted = false;
            } else if (ch == 'i' || ch == 'I') {
                modes[MODE_DUMP_IMPORT] = true;
                defaulted = false;
            } else if (ch == 'e' || ch == 'E') {
                modes[MODE_DUMP_EXPORT] = true;
                defaulted = false;
            } else if (ch == 'r' || ch == 'R') {
                modes[MODE_DUMP_RESOURCE] = true;
                defaulted = false;
            } else if (ch == 'd' || ch == 'D') {
                modes[MODE_DUMP_DELAYLOAD] = true;
                defaulted = false;
            } else if (ch == 'p' || ch == 'P') {
                modes[MODE_DUMP_DISASM] = true;
                defaulted = false;
            } else if (strcmp(arg, "-32") == 0 || strcmp(arg, "--32") == 0) {
                modes[MODE_64BIT] = false;
            } else if (strcmp(arg, "-64") == 0 || strcmp(arg, "--64") == 0) {
                modes[MODE_64BIT] = true;
            } else {
                fprintf(stderr, "ERROR: invalid option '%s'\n", arg);
                return cr_exit_invalid_option;
            }
        } else {
            break;
        }
    }

    if (defaulted) {
        for (int i = 0; i <= MODE_DUMP_DISASM; ++i) {
            modes[i] = true;
        }
    }

    if (prefix.empty()) {
        prefix = CrGetExePath();
        #if defined(_DEBUG) && defined(_MSC_VER)
            #ifdef _WIN64
                prefix += "\\..\\..";
            #else
                prefix += "\\..";
            #endif
        #endif
        prefix += "\\Wonders";
        prefix += wonders_ver;
        prefix += "\\";
    }

    if (suffix.empty()) {
        if (modes[MODE_ANSI]) {
            if (modes[MODE_64BIT]) {
                suffix = "-cl-64-a.dat";
            } else {
                suffix = "-cl-32-a.dat";
            }
        } else {
            if (modes[MODE_64BIT]) {
                suffix = "-cl-64-w.dat";
            } else {
                suffix = "-cl-32-w.dat";
            }
        }
    }

    fprintf(stderr, "Wonders API prefix: %s\n", prefix.c_str());
    fprintf(stderr, "Wonders API suffix: %s\n", suffix.c_str());

    const char *pszModule = arg;
    fprintf(stderr, "Loading module %s...\n", pszModule);

    CR_Module module;
    if (!module.LoadModule(pszModule)) {
        fprintf(stderr, "ERROR: Cannot load module '%s', LastError = %lu\n",
                pszModule, module.LastError());
        return cr_exit_cant_load;
    }

    if (modes[MODE_DUMP_HEADERS]) {
        fprintf(stderr, "Dumping module %s headers...\n", pszModule);
        module.DumpHeaders(stdout);
    }
    if (modes[MODE_DUMP_IMPORT]) {
        fprintf(stderr, "Dumping module %s import table...\n", pszModule);
        module.DumpImportSymbols(stdout);
    }
    if (modes[MODE_DUMP_EXPORT]) {
        fprintf(stderr, "Dumping module %s export table...\n", pszModule);
        module.DumpExportSymbols(stdout);
    }
    if (modes[MODE_DUMP_RESOURCE]) {
        fprintf(stderr, "Dumping module %s resource...\n", pszModule);
        module.DumpResource(stdout);
    }
    if (modes[MODE_DUMP_DELAYLOAD]) {
        fprintf(stderr, "Dumping module %s delayload info...\n", pszModule);
        module.DumpDelayLoad(stdout);
    }

    if (module.Is64Bit() && !modes[MODE_64BIT]) {
        fprintf(stderr, "ERROR: Bits mismatched.\n");
        fprintf(stderr, "       The module was 64-bit and the mode was 32-bit.\n");
        return cr_exit_bits_mismatched;
    }

    if (!module.Is64Bit() && modes[MODE_64BIT]) {
        fprintf(stderr, "ERROR: Bits mismatched.\n");
        fprintf(stderr, "       The module was 32-bit and the mode was 64-bit.\n");
        return cr_exit_bits_mismatched;
    }

    shared_ptr<CR_ErrorInfo> error_info = make_shared<CR_ErrorInfo>();

    if (modes[MODE_64BIT]) {
        CR_NameScope namescope(error_info, true);
        fprintf(stderr, "Loading type info...\n");
        if (!namescope.LoadFromFiles(prefix, suffix)) {
            fprintf(stderr, "WARNING: Wonders API is required.\n");
            fprintf(stderr, "Please download it from http://katahiromz.esy.es/wonders/\n");
        } else {
            fprintf(stderr, "Loaded.\n");
        }

        fprintf(stderr, "Disassembling...\n");
        CR_DisAsmInfo64 info;
        module.DisAsm64(info);
        module.FixupAsm64(info);
        fprintf(stderr, "Disassembled.\n");

        if (modes[MODE_DUMP_DISASM]) {
            fprintf(stderr, "Dumping disassembly...\n");
            module.DumpDisAsm64(stdout, info);
            fprintf(stderr, "Dumped.\n");
        }
    } else {
        CR_NameScope namescope(error_info, false);
        fprintf(stderr, "Loading type info...\n");
        if (!namescope.LoadFromFiles(prefix, suffix)) {
            fprintf(stderr, "WARNING: Wonders API is required.\n");
            fprintf(stderr, "Please download it from http://katahiromz.esy.es/wonders/\n");
        } else {
            fprintf(stderr, "Loaded.\n");
        }

        fprintf(stderr, "Disassembling...\n");
        CR_DisAsmInfo32 info;
        module.DisAsm32(info);
        module.FixupAsm32(info);
        fprintf(stderr, "Disassembled.\n");

        if (modes[MODE_DUMP_DISASM]) {
            fprintf(stderr, "Dumping disassembly...\n");
            module.DumpDisAsm32(stdout, info);
            fprintf(stderr, "Dumped.\n");
        }
    }

    return cr_exit_ok;
}

////////////////////////////////////////////////////////////////////////////
