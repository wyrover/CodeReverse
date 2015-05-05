////////////////////////////////////////////////////////////////////////////
// Module.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

CR_Module::CR_Module() :
    m_hFile(INVALID_HANDLE_VALUE),
    m_hFileMapping(NULL),
    m_pFileImage(NULL),
    m_dwFileSize(0),
    m_pLoadedImage(NULL),
    m_pDOSHeader(NULL),
    m_pNTHeaders(NULL),
    m_pFileHeader(NULL),
    m_pOptional32(NULL),
    m_pOptional64(NULL),
    m_dwLastError(ERROR_SUCCESS),
    m_dwHeaderSum(0),
    m_dwCheckSum(0),
    m_pSectionHeaders(NULL),
    m_pDataDirectories(NULL)
{
} // CR_Module::CR_Module

BOOL CR_Module::LoadModule(LPCTSTR pszFileName) {
    m_hFile = ::CreateFile(pszFileName, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        m_dwLastError = ::GetLastError();
        return FALSE;
    }

    m_dwFileSize = ::GetFileSize(m_hFile, NULL);
    if (m_dwFileSize == 0xFFFFFFFF) {
        m_dwLastError = ::GetLastError();
        ::CloseHandle(m_hFile);
        return FALSE;
    }

    m_hFileMapping = ::CreateFileMapping(
        m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m_hFileMapping) {
        m_pFileImage = reinterpret_cast<LPBYTE>(
            ::MapViewOfFile(
                m_hFileMapping, FILE_MAP_READ, 0, 0, m_dwFileSize));
        if (m_pFileImage) {
#ifndef NO_CHECKSUM
            ::CheckSumMappedFile(m_pFileImage, m_dwFileSize,
                &m_dwHeaderSum, &m_dwCheckSum);
#endif
            if (_LoadImage(m_pFileImage)) {
                LoadImportTables();
                LoadExportTable();
                LoadDelayLoad();
                m_strFileName = pszFileName;
                return TRUE;
            } else {
                m_dwLastError = ERROR_INVALID_DATA;
            }
        } else {
            m_dwLastError = ::GetLastError();
        }
        ::CloseHandle(m_hFileMapping);
        m_hFileMapping = NULL;
    } else {
        m_dwLastError = ::GetLastError();
    }

    ::CloseHandle(m_hFile);
    m_hFile = INVALID_HANDLE_VALUE;

    return FALSE;
} // CR_Module::LoadModule

void CR_Module::UnloadModule() {
    if (m_pLoadedImage) {
        ::VirtualFree(m_pLoadedImage, 0, MEM_RELEASE);
        m_pLoadedImage = NULL;
    }

    if (m_pFileImage) {
        ::UnmapViewOfFile(m_pFileImage);
        m_pFileImage = NULL;
    }

    if (m_hFileMapping) {
        ::CloseHandle(m_hFileMapping);
        m_hFileMapping = NULL;
    }

    if (m_hFile != INVALID_HANDLE_VALUE) {
        ::CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }

    m_strFileName.clear();
    m_dwFileSize = 0;
    m_pDOSHeader = NULL;
    m_pNTHeaders = NULL;
    m_pFileHeader = NULL;
    m_pOptional32 = NULL;
    m_pOptional64 = NULL;
    m_dwHeaderSum = 0;
    m_dwCheckSum = 0;
    m_pSectionHeaders = NULL;
    m_pDataDirectories = NULL;

    m_vecImportSymbols.clear();
    m_vecExportSymbols.clear();
    m_vecDelayLoadDescriptors.clear();
    m_mRVAToFuncNameMap.clear();
    m_mFuncNameToRVAMap.clear();
} // CR_Module::UnloadModule

BOOL CR_Module::_LoadImage(LPVOID Data) {
    auto pDOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(Data);
    IMAGE_NT_HEADERS *pNTHeaders;

    // "MZ"
    if (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE && pDOSHeader->e_lfanew) {
        pNTHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(
            reinterpret_cast<LPBYTE>(Data) + pDOSHeader->e_lfanew);
    } else {
        pDOSHeader = NULL;
        pNTHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(Data);
    }
    m_pDOSHeader = pDOSHeader;

    // "PE\0\0"
    if (pNTHeaders->Signature == IMAGE_NT_SIGNATURE)  {
        if (_LoadNTHeaders(pNTHeaders)) {
            m_pLoadedImage = reinterpret_cast<LPBYTE>(
                ::VirtualAlloc(NULL, GetSizeOfImage() + 16,
                               MEM_COMMIT, PAGE_READWRITE));
            assert(m_pLoadedImage);
            if (m_pLoadedImage) {
                CopyMemory(m_pLoadedImage, m_pFileImage, GetSizeOfHeaders());

                DWORD size = NumberOfSections();
                auto Headers = m_pSectionHeaders;
                for (DWORD i = 0; i < size; ++i) {
                    CopyMemory(
                        &m_pLoadedImage[Headers[i].RVA],
                        &m_pFileImage[Headers[i].PointerToRawData],
                        Headers[i].SizeOfRawData);
                }
                return TRUE;
            }
        }
    }

    return FALSE;
} // CR_Module::_LoadImage

BOOL CR_Module::_LoadNTHeaders(LPVOID Data) {
    m_pNTHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(Data);
    auto pFileHeader = &m_pNTHeaders->FileHeader;

    LPBYTE pb;
    switch (pFileHeader->SizeOfOptionalHeader) {
    case sizeof(IMAGE_OPTIONAL_HEADER32):
        m_pFileHeader = pFileHeader;
        m_pOptional32 = &m_pNTHeaders32->OptionalHeader;;
        if (m_pOptional32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return FALSE;

        pb = reinterpret_cast<LPBYTE>(m_pOptional32) +
             pFileHeader->SizeOfOptionalHeader;
        m_pSectionHeaders = reinterpret_cast<REAL_IMAGE_SECTION_HEADER *>(pb);
        m_pDataDirectories =
            reinterpret_cast<REAL_IMAGE_DATA_DIRECTORY *>(
                m_pOptional32->DataDirectory);
        break;

    case sizeof(IMAGE_OPTIONAL_HEADER64):
        m_pFileHeader = pFileHeader;
        m_pOptional64 = &m_pNTHeaders64->OptionalHeader;
        if (m_pOptional64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return FALSE;

        pb = reinterpret_cast<LPBYTE>(m_pOptional64) +
             pFileHeader->SizeOfOptionalHeader;
        m_pSectionHeaders = reinterpret_cast<REAL_IMAGE_SECTION_HEADER *>(pb);
        m_pDataDirectories =
            reinterpret_cast<REAL_IMAGE_DATA_DIRECTORY *>(
                m_pOptional64->DataDirectory);
        break;

    default:
        m_pFileHeader = NULL;
        m_pNTHeaders = NULL;
        m_pOptional32 = NULL;
        m_pOptional64 = NULL;
        return FALSE;
    }

    return TRUE;
} // CR_Module::_LoadNTHeaders

REAL_IMAGE_SECTION_HEADER *CR_Module::CodeSectionHeader() {
    assert(m_pSectionHeaders);
    const DWORD siz = NumberOfSections();
    for (DWORD i = 0; i < siz; ++i) {
        auto pHeader = SectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            return pHeader;
        }
    }
    return NULL;
} // CR_Module::CodeSectionHeader

const REAL_IMAGE_SECTION_HEADER *CR_Module::CodeSectionHeader() const {
    assert(m_pSectionHeaders);
    const DWORD siz = NumberOfSections();
    for (DWORD i = 0; i < siz; ++i) {
        const REAL_IMAGE_SECTION_HEADER *pHeader = SectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            return pHeader;
        }
    }
    return NULL;
} // CR_Module::CodeSectionHeader

BOOL CR_Module::LoadImportTables() {
    if (!_GetImportDllNames(ImportDllNames()))
        return FALSE;

    const DWORD siz = static_cast<DWORD>(ImportDllNames().size());
    for (DWORD i = 0; i < siz; ++i) {
        CR_VecSet<CR_ImportSymbol> symbols;
        if (_GetImportSymbols(i, symbols)) {
            for (auto& symbol : symbols) {
                symbol.iDLL = i;
                MapFuncNameToRVA().emplace(symbol.pszName, symbol.dwRVA);
                MapRVAToFuncName().emplace(symbol.dwRVA, symbol.pszName);
            }
            ImportSymbols().insert(
                ImportSymbols().end(), symbols.begin(), symbols.end());
        }
    }
    return TRUE;
} // CR_Module::LoadImportTables

BOOL CR_Module::LoadExportTable() {
    CR_VecSet<CR_ExportSymbol> symbols;

    if (!_GetExportSymbols(ExportSymbols()))
        return FALSE;

    for (auto& symbol : ExportSymbols()) {
        if (symbol.dwRVA == 0 || symbol.pszForwarded)
            continue;

        MapFuncNameToRVA().emplace(symbol.pszName, symbol.dwRVA);
        MapRVAToFuncName().emplace(symbol.dwRVA, symbol.pszName);
    }

    return TRUE;
} // CR_Module::LoadExportTable

BOOL CR_Module::LoadDelayLoad() {
    if (!IsModuleLoaded())
        return FALSE;

    auto pDir = DataDirectory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
    if (pDir == NULL)
        return FALSE;

    auto pDescrs =
        reinterpret_cast<ImgDelayDescr *>(m_pLoadedImage + pDir->RVA);

    std::size_t i = 0;
    CR_VecSet<ImgDelayDescr> Descrs;
    while (pDescrs[i].rvaHmod) {
        Descrs.push_back(pDescrs[i]);
        i++;
    }

    DelayLoadDescriptors() = Descrs;

    // TODO: load IAT and INT

    return TRUE;
} // CR_Module::LoadDelayLoad

BOOL CR_Module::_GetImportDllNames(CR_Strings& names) {
    names.clear();
    auto descs = ImportDescriptors();
    if (descs == NULL)
        return FALSE;

    for (DWORD i = 0; descs[i].FirstThunk != 0; ++i) {
        names.insert(reinterpret_cast<char *>(GetData(descs[i].Name)));
    }

    return TRUE;
} // CR_Module::_GetImportDllNames

BOOL CR_Module::_GetImportSymbols(
    DWORD dll_index, CR_VecSet<CR_ImportSymbol>& symbols)
{
    symbols.clear();

    DWORD i, j;
    IMAGE_IMPORT_BY_NAME *pIBN;
    auto descs = ImportDescriptors();
    if (descs == NULL || descs[0].OriginalFirstThunk == 0) {
        return FALSE;
    }

    CR_ImportSymbol symbol;
    for (i = 0; descs[i].FirstThunk != 0; ++i) {
        if (dll_index != i) {
            continue;
        }
        if (Is64Bit()) {
            PULONGLONG pIAT64, pINT64;

            pIAT64 = reinterpret_cast<PULONGLONG>(
                static_cast<DWORD_PTR>(descs[i].FirstThunk));
            if (descs[i].OriginalFirstThunk) {
                pINT64 = reinterpret_cast<PULONGLONG>(
                    GetData(descs[i].OriginalFirstThunk));
            } else {
                pINT64 = pIAT64;
            }

            for (j = 0; pINT64[j] != 0; j++) {
                if (pINT64[j] < GetSizeOfImage()) {
                    symbol.dwRVA = descs[i].FirstThunk + j * sizeof(DWORD);

                    if (IMAGE_SNAP_BY_ORDINAL64(pINT64[j])) {
                        symbol.wHint = 0;
                        symbol.Name.wImportByName = 0;
                        symbol.Name.wOrdinal = WORD(IMAGE_ORDINAL64(pINT64[j]));
                    } else {
                        pIBN = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(
                            GetData(DWORD(pINT64[j])));
                        symbol.wHint = pIBN->Hint;
                        symbol.pszName = reinterpret_cast<char *>(pIBN->Name);
                    }
                    symbols.insert(symbol);
                }
            }
        } else {
            LPDWORD pIAT, pINT;     // import address table & import name table
            pIAT = reinterpret_cast<LPDWORD>(
                static_cast<DWORD_PTR>(descs[i].FirstThunk));
            if (descs[i].OriginalFirstThunk) {
                pINT = reinterpret_cast<LPDWORD>(GetData(descs[i].OriginalFirstThunk));
            } else {
                pINT = pIAT;
            }

            for (j = 0; pINT[j] != 0; j++) {
                if (pINT[j] < GetSizeOfImage()) {
                    symbol.dwRVA = descs[i].FirstThunk + j * sizeof(DWORD);

                    if (IMAGE_SNAP_BY_ORDINAL32(pINT[j])) {
                        symbol.wHint = 0;
                        symbol.Name.wImportByName = 0;
                        symbol.Name.wOrdinal = WORD(IMAGE_ORDINAL32(pINT[j]));
                    } else {
                        pIBN = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(GetData(pINT[j]));
                        symbol.wHint = pIBN->Hint;
                        symbol.pszName = reinterpret_cast<char *>(pIBN->Name);
                    }
                    symbols.insert(symbol);
                }
            }
        }
        break;
    }

    return TRUE;
} // CR_Module::_GetImportSymbols

BOOL CR_Module::_GetExportSymbols(CR_VecSet<CR_ExportSymbol>& symbols) {
    symbols.clear();

    auto pDir = ExportDirectory();
    if (pDir == NULL) {
        return FALSE;
    }

    // export address table (EAT)
    LPDWORD pEAT = reinterpret_cast<LPDWORD>(GetData(pDir->AddressOfFunctions));
    // export name pointer table (ENPT)
    LPDWORD pENPT = reinterpret_cast<LPDWORD>(GetData(pDir->AddressOfNames));
    // export ordinal table (EOT)
    LPWORD pEOT = reinterpret_cast<LPWORD>(GetData(pDir->AddressOfNameOrdinals));

    DWORD i, j;
    WORD wOrdinal;
    CR_ExportSymbol symbol;
    for (i = 0; i < pDir->NumberOfNames; ++i) {
        wOrdinal = pEOT[i];
        symbol.dwRVA = pEAT[wOrdinal];
        symbol.pszName = reinterpret_cast<char *>(GetData(pENPT[i]));
        symbol.dwOrdinal = pDir->Base + wOrdinal;
        symbol.pszForwarded = NULL;
        symbols.insert(symbol);
    }

    for (i = 0; i < pDir->NumberOfFunctions; ++i) {
        for (j = 0; j < pDir->NumberOfNames; j++) {
            if (static_cast<DWORD>(pEOT[j]) == i)
                break;
        }
        if (j < pDir->NumberOfNames)
            continue;

        DWORD dw = pEAT[i];
        if (dw == 0)
            continue;

        symbol.pszName = NULL;
        if (RVAInDirEntry(dw, IMAGE_DIRECTORY_ENTRY_EXPORT)) {
            symbol.dwRVA = 0;
            symbol.pszForwarded = reinterpret_cast<char *>(GetData(dw));
        } else {
            symbol.dwRVA = dw;
            symbol.pszForwarded = NULL;
        }
        symbol.dwOrdinal = pDir->Base + i;
        symbols.insert(symbol);
    }

    return TRUE;
} // CR_Module::_GetExportSymbols

const char *CR_Module::FuncNameFromRVA(DWORD RVA) const {
    for (auto& symbol : ExportSymbols()) {
        if (symbol.dwRVA == RVA) {
            return symbol.pszName;
        }
    }
    for (auto& symbol : ImportSymbols()) {
        if (symbol.dwRVA == RVA) {
            return symbol.pszName;
        }
    }
    auto it = MapRVAToFuncName().find(RVA);
    if (it != MapRVAToFuncName().end()) {
        return it->second.c_str();
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// disasm

extern "C"
int32_t disasm(uint8_t *data, char *output, int outbufsize, int segsize,
               int64_t offset, int autosync, uint32_t prefer);

BOOL CR_Module::DisAsmAddr32(
    CR_DecompInfo32& info, CR_Addr32 func, CR_Addr32 va)
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    int len;
    char outbuf[256];
    CR_Addr32 addr;

    // add or retrieve the code function
    auto cf = info.CodeFuncFromAddr(func);
    if (cf == NULL) {
        info.MapAddrToCodeFunc().emplace(func, make_shared<CR_CodeFunc32>());
        cf = info.CodeFuncFromAddr(func);
    }
    assert(cf);
    if (func == va) {
        cf->Addr() = func;
    }

    const REAL_IMAGE_SECTION_HEADER *pCode = CodeSectionHeader();
    assert(pCode);

    DWORD rva = RVAFromVA32(va);
    LPBYTE input = m_pLoadedImage + rva;
    LPBYTE iend = m_pLoadedImage + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend) {
        // add or retrieve op.code
        auto oc = info.OpCodeFromAddr(va);
        if (oc == NULL) {
            info.MapAddrToOpCode().emplace(va, make_shared<CR_OpCode32>());
            oc = info.OpCodeFromAddr(va);
        }
        assert(oc);
        if (oc->FuncAddrs().count(func) > 0)
            break;

        // set op.code address
        oc->Addr() = va;

        // add function address for this op.code
        oc->FuncAddrs().emplace(func);
        if (oc->FuncAddrs().size() > 1) {
            cf->FuncFlags() |= cr_FF_FUNCINFUNC;   // function in function
        }

        // disassemble
        len = disasm(input, outbuf, sizeof(outbuf), 32, va, false, 0);

        // parse insn
        if (!len || input + len > iend) {
            len = 1;
            oc->Name() = "???";
            oc->OpCodeType() = cr_OCT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf->FuncFlags() |= cr_FF_INVALID;
        } else {
            oc->ParseText(outbuf);
        }

        // add asm codes to op.code
        if (oc->Codes().empty()) {
            for (int i = 0; i < len; ++i)
                oc->Codes().emplace_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (oc->OpCodeType()) {
        case cr_OCT_JCC:    // conditional jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_OF_IMM:
                addr = oc->Operand(0)->Value32();
                cf->Jumpers().emplace(va);
                cf->Jumpees().emplace(addr);
                break;

            default: break;
            }
            break;

        case cr_OCT_JMP:    // jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_OF_IMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    addr = oc->Operand(0)->Value32();
                    info.Entrances().emplace(addr);
                    cf->Callers().emplace(addr);

                    auto newcf = info.CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        info.MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc32>());
                        newcf = info.CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().emplace(func);
                } else {
                    addr = oc->Operand(0)->Value32();
                    cf->Jumpers().emplace(va);
                    cf->Jumpees().emplace(addr);
                }
                break;

            case cr_OF_MEMIMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case cr_OCT_CALL:   // call
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_OF_IMM:
                // function call
                addr = oc->Operand(0)->Value32();
                info.Entrances().emplace(addr);
                cf->Callees().emplace(addr);
                {
                    auto newcf = info.CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        info.MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc32>());
                        newcf = info.CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callers().emplace(func);
                }
                break;

            default:
                break;
            }
            break;

        case cr_OCT_RETURN: // return
            if (oc->Operands().size() && oc->Operand(0)->GetOperandType() == cr_OF_IMM) {
                // func is __stdcall
                cf->FuncFlags() |= cr_FF_STDCALL;
                cf->ArgSizeRange().Set(oc->Operand(0)->Value32());
            } else {
                // func is not __stdcall
                cf->FuncFlags() |= cr_FF_NOTSTDCALL;
                if (func == va) {
                    cf->FuncFlags() |= cr_FF_RETURNONLY | cr_FF_CDECL;
                }
            }
            bBreak = TRUE;
            break;

        default:
            break;
        }

        if (bBreak)
            break;

        // move to next position
        input += len;
        va += len;
    }

    return TRUE;
} // CR_Module::DisAsmAddr32

BOOL CR_Module::DisAsmAddr64(CR_DecompInfo64& info, CR_Addr64 func, CR_Addr64 va) {
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // calculate
    int len;
    char outbuf[256];
    CR_Addr64 addr;

    // add or retrieve the code function
    auto cf = info.CodeFuncFromAddr(func);
    if (cf == NULL) {
        info.MapAddrToCodeFunc().emplace(func, make_shared<CR_CodeFunc64>());
        cf = info.CodeFuncFromAddr(func);
    }
    assert(cf);
    if (func == va) {
        cf->Addr() = func;
    }

    auto pCode = CodeSectionHeader();
    assert(pCode);

    DWORD rva = RVAFromVA64(va);
    LPBYTE input = m_pLoadedImage + rva;
    LPBYTE iend = m_pLoadedImage + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend) {
        // add or retrieve op.code
        auto oc = info.OpCodeFromAddr(va);
        if (oc == NULL) {
            info.MapAddrToOpCode().emplace(va, make_shared<CR_OpCode64>());
            oc = info.OpCodeFromAddr(va);
        }
        assert(oc);
        if (oc->FuncAddrs().count(func) > 0)
            break;

        // set op.code address
        oc->Addr() = va;

        // add function address for this op.code
        oc->FuncAddrs().emplace(func);
        if (oc->FuncAddrs().size() > 1) {
            cf->FuncFlags() |= cr_FF_FUNCINFUNC;   // function in function
        }

        // disassemble
        len = disasm(input, outbuf, sizeof(outbuf), 64, va, false, 0);

        // parse insn
        if (!len || input + len > iend) {
            len = 1;
            oc->Name() = "???";
            oc->OpCodeType() = cr_OCT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf->FuncFlags() |= cr_FF_INVALID;
        } else {
            oc->ParseText(outbuf);
        }

        // add asm codes to op.code
        if (oc->Codes().empty()) {
            for (int i = 0; i < len; ++i)
                oc->Codes().emplace_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (oc->OpCodeType()) {
        case cr_OCT_JCC:    // conditional jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_OF_IMM:
                addr = oc->Operand(0)->Value64();
                cf->Jumpers().emplace(va);
                cf->Jumpees().emplace(addr);
                break;

            default:
                break;
            }
            break;

        case cr_OCT_JMP:    // jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_OF_IMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    addr = oc->Operand(0)->Value64();
                    info.Entrances().emplace(addr);
                    cf->Callers().emplace(addr);

                    auto newcf = info.CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        info.MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc64>());
                        newcf = info.CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().emplace(func);
                } else {
                    addr = oc->Operand(0)->Value64();
                    cf->Jumpers().emplace(va);
                    cf->Jumpees().emplace(addr);
                }
                break;

            case cr_OF_MEMIMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case cr_OCT_CALL:   // call
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_OF_IMM:
                // function call
                addr = oc->Operand(0)->Value64();
                info.Entrances().emplace(addr);
                cf->Callees().emplace(addr);
                {
                    auto newcf = info.CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        info.MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc64>());
                        newcf = info.CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callers().emplace(func);
                }
                break;

            default:
                break;
            }
            break;

        case cr_OCT_RETURN: // return
            if (oc->Operands().size() && oc->Operand(0)->GetOperandType() == cr_OF_IMM) {
                cf->ArgSizeRange().Set(oc->Operand(0)->Value64());
            } else {
                if (func == va) {
                    cf->FuncFlags() |= cr_FF_RETURNONLY;
                }
            }
            bBreak = TRUE;
            break;

        default:
            break;
        }

        if (bBreak)
            break;

        // move to next position
        input += len;
        va += len;
    }

    return TRUE;
} // CR_Module::DisAsmAddr64

BOOL CR_Module::DisAsm32(CR_DecompInfo32& info) {
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    // register entrances
    CR_Addr32 va;
    auto RVA = RVAOfEntryPoint();
    va = VA32FromRVA(RVA);
    info.Entrances().emplace(va);
    {
        auto codefunc = make_shared<CR_CodeFunc32>();
        codefunc->Addr() = va;
        codefunc->Name() = "EntryPoint";
        codefunc->ArgSizeRange().Set(0);
        codefunc->FuncFlags() |= cr_FF_CDECL;
        info.MapAddrToCodeFunc().emplace(va, codefunc);
        MapRVAToFuncName().emplace(RVA, codefunc->Name());
        MapFuncNameToRVA().emplace(codefunc->Name(), RVA);
    }

    // exporting functions are entrances
    for (auto& e_symbol : ExportSymbols()) {
        va = VA32FromRVA(e_symbol.dwRVA);

        info.Entrances().emplace(va);
        MapRVAToFuncName().emplace(e_symbol.dwRVA, e_symbol.pszName);
        MapFuncNameToRVA().emplace(e_symbol.pszName, e_symbol.dwRVA);
    }

    // disasm entrances
    {
        std::size_t size;
        CR_Addr32Set addrs;
        do {
            addrs = info.Entrances();
            size = addrs.size();

            for (auto addr : addrs) {
                DisAsmAddr32(info, addr, addr);

                CR_CodeFunc32 *cf = info.CodeFuncFromAddr(addr);
                assert(cf);

                CR_Addr32Set jumpees;
                do {
                    jumpees = cf->Jumpees();
                    for (auto addr2 : jumpees) {
                        DisAsmAddr32(info, addr, addr2);
                    }
                    // cf->Jumpees() may grow in DisAsmAddr32
                } while (jumpees.size() < cf->Jumpees().size());
            }

            // info.Entrances() may grow in DisAsmAddr32
        } while (size < info.Entrances().size());
    }

    return TRUE;
} // CR_Module::DisAsm32

BOOL CR_Module::DisAsm64(CR_DecompInfo64& info) {
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // register entrances
    CR_Addr64 va;
    auto RVA = RVAOfEntryPoint();
    va = VA64FromRVA(RVA);
    info.Entrances().emplace(va);
    {
        auto codefunc = make_shared<CR_CodeFunc64>();
        codefunc->Addr() = va;
        codefunc->Name() = "EntryPoint";
        codefunc->ArgSizeRange().Set(0);
        info.MapAddrToCodeFunc().emplace(va, codefunc);
        MapRVAToFuncName().emplace(RVA, codefunc->Name());
        MapFuncNameToRVA().emplace(codefunc->Name(), RVA);
    }

    // exporting functions are entrances
    for (auto& e_symbol : ExportSymbols()) {
        va = VA64FromRVA(e_symbol.dwRVA);

        info.Entrances().emplace(va);
        MapRVAToFuncName().emplace(e_symbol.dwRVA, e_symbol.pszName);
        MapFuncNameToRVA().emplace(e_symbol.pszName, e_symbol.dwRVA);
    }

    // disasm entrances
    {
        std::size_t size;
        CR_Addr64Set addrs;
        do {
            addrs = info.Entrances();
            size = addrs.size();

            for (auto addr : addrs) {
                DisAsmAddr64(info, addr, addr);

                CR_CodeFunc64 *cf = info.CodeFuncFromAddr(addr);
                assert(cf);

                CR_Addr64Set jumpees;
                do {
                    jumpees = cf->Jumpees();
                    for (auto addr2 : jumpees) {
                        DisAsmAddr64(info, addr, addr2);
                    }
                    // cf->Jumpees() may grow in DisAsmAddr64
                } while (jumpees.size() < cf->Jumpees().size());
            }

            // info.Entrances() may grow in DisAsmAddr64
        } while (size < info.Entrances().size());
    }

    return TRUE;
} // CR_Module::DisAsm64

////////////////////////////////////////////////////////////////////////////

BOOL CR_Module::AnalyzeOperands32(CR_DecompInfo32& info, CR_Addr32 func) {
    return TRUE;
}

BOOL CR_Module::AnalyzeOperands64(CR_DecompInfo64& info, CR_Addr64 func) {
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////

BOOL CR_Module::FixupAsm32(CR_DecompInfo32& info) {
    bool must_retry;
    CR_NameScope& ns = info.NameScope();

retry:;
    must_retry = false;

    for (auto it : info.MapAddrToOpCode()) {
        auto& operands = it.second.get()->Operands();
        for (auto& opr : operands) {
            if (opr.GetOperandType() == cr_OF_MEMIMM) {
                CR_Addr32 addr = opr.Value32();
                auto name = FuncNameFromRVA(addr);
                if (name) {
                    opr.SetFuncName(name);
                    must_retry = true;
                } else {
                    if (AddressInData32(addr)) {
                        opr.Text() = "M" + Cr8Hex(addr);
                    } else if (AddressInCode32(addr)) {
                        opr.Text() = "L" + Cr8Hex(addr);
                    }
                }
            }
        }

        switch (it.second->OpCodeType()) {
        case cr_OCT_JMP:
        case cr_OCT_LOOP:
        case cr_OCT_JCC:
        case cr_OCT_CALL:
            if (operands[0].GetOperandType() == cr_OF_MEMIMM) {
                CR_Addr32 addr = operands[0].Value32();
                const char *pName = FuncNameFromVA32(addr);
                if (pName) {
                    operands[0].SetFuncName(pName);
                    must_retry = true;
                }
            } else if (operands[0].GetOperandType() == cr_OF_IMM) {
                CR_Addr32 addr = operands[0].Value32();
                const char *pName = FuncNameFromVA32(addr);
                if (pName) {
                    if ((operands[0].OperandFlags() & cr_OF_FUNCNAME) == 0) {
                        operands[0].SetFuncName(pName);
                        must_retry = true;
                    }
                } else if (AddressInCode32(addr)) {
                    operands[0].Text() = "L" + Cr8Hex(addr);
                }
            }
            break;

        case cr_OCT_MISC:
            if (it.second->Name() == "mov" ||
                it.second->Name() == "cmp" ||
                it.second->Name() == "test" ||
                it.second->Name() == "and" ||
                it.second->Name() == "sub" ||
                it.second->Name().find("cmov") == 0)
            {
                if (operands[0].Size() == 0)
                    operands[0].Size() = operands[1].Size();
                else if (operands[1].Size() == 0)
                    operands[1].Size() = operands[0].Size();
            } else if (it.second->Name() == "lea") {
                CR_Addr32 addr = operands[1].Value32();
                if (AddressInData32(addr)) {
                    operands[1].Text() = "offset M" + Cr8Hex(addr);
                } else if (AddressInCode32(addr)) {
                    operands[1].Text() = "offset L" + Cr8Hex(addr);
                }
            }
            break;

        default:
            break;
        }
    }

    for (auto it : info.MapAddrToCodeFunc()) {
        CR_CodeFunc32 *cf = it.second.get();
        assert(cf);

        if ((cf->FuncFlags() & cr_FF_JUMPERFUNC) && cf->Name().empty()) {
            CR_Addr32 addr = cf->Addr();
            CR_OpCode32 *oc = info.OpCodeFromAddr(addr);
            assert(oc);
            auto& operands = oc->Operands();
            cf->Name() = std::string("__imp") + operands[0].Text();

            auto RVA = RVAFromVA32(addr);
            MapRVAToFuncName().emplace(RVA, cf->Name());
            MapFuncNameToRVA().emplace(cf->Name(), RVA);
            must_retry = true;

            auto it = ns.MapNameToVarID().find(operands[0].Text());
            if (it != ns.MapNameToVarID().end()) {
                auto vid = it->second;
                auto& var = ns.LogVar(vid);
                auto tid = var.m_typed_value.m_type_id;
                if (ns.IsFuncType(tid)) {
                    auto rtid = ns.ResolveAliasAndCV(tid);
                    auto& rtype = ns.LogType(rtid);
                    auto& func = ns.LogFunc(rtype.m_sub_id);

                    if (rtype.m_flags & TF_CDECL) {
                        cf->FuncFlags() |= cr_FF_CDECL;
                    } else if (rtype.m_flags & TF_STDCALL) {
                        cf->FuncFlags() |= cr_FF_STDCALL;
                    } else if (rtype.m_flags & TF_FASTCALL) {
                        cf->FuncFlags() |= cr_FF_FASTCALL;
                    }

                    if (func.m_ellipsis) {
                        cf->ArgSizeRange().LimitMin(func.m_params.size() * 4);
                    } else {
                        cf->ArgSizeRange().Set(func.m_params.size() * 4);
                    }
                }
            }
        }

        DWORD rva = RVAFromVA32(cf->Addr());
        auto es = ExportSymbolFromRVA(rva);
        if (es && cf->Name() != es->pszName) {
            cf->Name() = es->pszName;
            must_retry = true;
        }
    }

    if (must_retry)
        goto retry;

    return TRUE;
} // CR_Module::FixupAsm32

BOOL CR_Module::FixupAsm64(CR_DecompInfo64& info) {
    bool must_retry;
    CR_NameScope& ns = info.NameScope();

retry:;
    must_retry = false;

    // convert addresses
    for (auto it : info.MapAddrToOpCode()) {
        auto& operands = it.second.get()->Operands();
        for (auto& opr : operands) {
            if (opr.GetOperandType() == cr_OF_MEMIMM) {
                CR_Addr64 addr = opr.Value64();
                auto name = FuncNameFromVA64(addr);
                if (name) {
                    opr.SetFuncName(name);
                    must_retry = true;
                } else {
                    if (AddressInData64(addr)) {
                        opr.Text() = "M" + Cr16Hex(addr);
                    } else if (AddressInCode64(addr)) {
                        opr.Text() = "L" + Cr16Hex(addr);
                    }
                }
            }
        }

        switch (it.second->OpCodeType()) {
        case cr_OCT_JMP:
        case cr_OCT_LOOP:
        case cr_OCT_JCC:
        case cr_OCT_CALL:
            if (operands[0].GetOperandType() == cr_OF_MEMIMM) {
                CR_Addr64 addr = operands[0].Value64();
                const char *pName = FuncNameFromVA64(addr);
                if (pName) {
                    if ((operands[0].OperandFlags() & cr_OF_FUNCNAME) == 0) {
                        operands[0].SetFuncName(pName);
                        must_retry = true;
                    }
                }
            } else if (operands[0].GetOperandType() == cr_OF_IMM) {
                CR_Addr64 addr = operands[0].Value64();
                const char *pName = FuncNameFromVA64(addr);
                if (pName) {
                    operands[0].SetFuncName(pName);
                    must_retry = true;
                } else if (AddressInCode64(addr)) {
                    operands[0].Text() = "L" + Cr16Hex(addr);
                }
            }
            break;

        case cr_OCT_MISC:
            if (it.second->Name() == "mov" || it.second->Name() == "cmp" ||
                it.second->Name() == "test" || it.second->Name() == "and" ||
                it.second->Name() == "sub" || it.second->Name().find("cmov") == 0)
            {
                if (operands[0].Size() == 0)
                    operands[0].Size() = operands[1].Size();
                else if (operands[1].Size() == 0)
                    operands[1].Size() = operands[0].Size();
            } else if (it.second->Name() == "lea") {
                CR_Addr64 addr = operands[1].Value64();
                if (AddressInData64(addr)) {
                    operands[1].Text() = "offset M" + Cr16Hex(addr);
                } else if (AddressInCode64(addr)) {
                    operands[1].Text() = "offset L" + Cr16Hex(addr);
                }
            }
            break;

        default:
            break;
        }
    }

    // fix up jumper functions
    for (auto it : info.MapAddrToCodeFunc()) {
        CR_CodeFunc64 *cf = it.second.get();
        assert(cf);

        if ((cf->FuncFlags() & cr_FF_JUMPERFUNC) && cf->Name().empty()) {
            CR_Addr64 addr = cf->Addr();
            CR_OpCode64 *oc = info.OpCodeFromAddr(addr);
            assert(oc);
            auto& operands = oc->Operands();
            cf->Name() = std::string("__imp") + operands[0].Text();

            auto it = ns.MapNameToVarID().find(operands[0].Text());
            if (it != ns.MapNameToVarID().end()) {
                auto vid = it->second;
                auto& var = ns.LogVar(vid);
                auto tid = var.m_typed_value.m_type_id;
                if (ns.IsFuncType(tid)) {
                    auto rtid = ns.ResolveAliasAndCV(tid);
                    auto& rtype = ns.LogType(rtid);
                    auto& func = ns.LogFunc(rtype.m_sub_id);

                    if (rtype.m_flags & TF_CDECL) {
                        cf->FuncFlags() |= cr_FF_CDECL;
                    } else if (rtype.m_flags & TF_STDCALL) {
                        cf->FuncFlags() |= cr_FF_STDCALL;
                    } else if (rtype.m_flags & TF_FASTCALL) {
                        cf->FuncFlags() |= cr_FF_FASTCALL;
                    }

                    if (func.m_ellipsis) {
                        cf->ArgSizeRange().LimitMin(func.m_params.size() * 8);
                    } else {
                        cf->ArgSizeRange().Set(func.m_params.size() * 8);
                    }
                }
            }

            auto RVA = RVAFromVA64(addr);
            MapRVAToFuncName().emplace(RVA, cf->Name());
            MapFuncNameToRVA().emplace(cf->Name(), RVA);
            must_retry = true;
        }

        DWORD rva = RVAFromVA64(cf->Addr());
        auto es = ExportSymbolFromRVA(rva);
        if (es && cf->Name() != es->pszName) {
            cf->Name() = es->pszName;
            must_retry = true;
        }
    }

    if (must_retry)
        goto retry;

    return TRUE;
} // CR_Module::FixupAsm64

////////////////////////////////////////////////////////////////////////////
// resource

extern "C"
BOOL CALLBACK
CrEnumResLangProc(
    HMODULE hModule,
    LPCTSTR lpszType,
    LPCTSTR lpszName,
    WORD wIDLanguage,
    LPARAM lParam)
{
    std::FILE *fp = reinterpret_cast<std::FILE *>(lParam);
    CHAR szLangName[64];
    DWORD LCID = MAKELCID(wIDLanguage, SORT_DEFAULT);
    if (::GetLocaleInfoA(LCID, LOCALE_SENGLANGUAGE, szLangName, 64)) {
        fprintf(fp, "      Language: %s\n", szLangName);
    } else {
        fprintf(fp, "      Language: #%u\n",
            static_cast<UINT>(static_cast<UINT_PTR>(wIDLanguage)));
    }

    HRSRC hRsrc;
    hRsrc = reinterpret_cast<HRSRC>(
        ::FindResourceEx(hModule, lpszType, lpszName, wIDLanguage));
    DWORD size = ::SizeofResource(hModule, hRsrc);
    fprintf(fp, "        Data size: 0x%08lX (%lu) Bytes\n", size, size);

    return TRUE;
} // CrEnumResLangProc

extern "C"
BOOL CALLBACK
CrEnumResNameProc(
    HMODULE hModule,
    LPCTSTR lpszType,
    LPTSTR lpszName,
    LPARAM lParam)
{
    std::FILE *fp = reinterpret_cast<std::FILE *>(lParam);
    if (IS_INTRESOURCE(lpszName)) {
        fprintf(fp, "    Resource Name: #%u\n",
            static_cast<UINT>(reinterpret_cast<UINT_PTR>(lpszName)));
    } else {
#ifdef _UNICODE
        fprintf(fp, "    Resource Name: %ls\n", lpszName);
#else
        fprintf(fp, "    Resource Name: %s\n", lpszName);
#endif
    }

    ::EnumResourceLanguages(hModule, lpszType, lpszName, CrEnumResLangProc, lParam);
    return TRUE;
} // CrEnumResNameProc

static const char * const cr_res_types[] = {
    NULL,               // 0
    "RT_CURSOR",        // 1
    "RT_BITMAP",        // 2
    "RT_ICON",          // 3
    "RT_MENU",          // 4
    "RT_DIALOG",        // 5
    "RT_STRING",        // 6
    "RT_FONTDIR",       // 7
    "RT_FONT",          // 8
    "RT_ACCELERATOR",   // 9
    "RT_RCDATA",        // 10
    "RT_MESSAGETABLE",  // 11
    "RT_GROUP_CURSOR",  // 12
    NULL,               // 13
    "RT_GROUP_ICON",    // 14
    "RT_VERSION",       // 16
    "RT_DLGINCLUDE",    // 17
    NULL,               // 18
    "RT_PLUGPLAY",      // 19
    "RT_VXD",           // 20
    "RT_ANICURSOR",     // 21
    "RT_ANIICON",       // 22
    "RT_HTML",          // 23
    "RT_MANIFEST",      // 24
};

extern "C"
BOOL CALLBACK
CrEnumResTypeProc(HMODULE hModule, LPTSTR lpszType, LPARAM lParam) {
    std::FILE *fp = reinterpret_cast<std::FILE *>(lParam);
    if (IS_INTRESOURCE(lpszType)) {
        UINT nType = static_cast<UINT>(reinterpret_cast<UINT_PTR>(lpszType));
        UINT size = static_cast<UINT>(sizeof(cr_res_types) / sizeof(cr_res_types[0]));
        if (nType < size && cr_res_types[nType]) {
            fprintf(fp, "  Resource Type: %s\n", cr_res_types[nType]);
        } else {
            fprintf(fp, "  Resource Type: #%u\n", nType);
        }
    } else {
#ifdef _UNICODE
        fprintf(fp, "  Resource Type: %ls\n", lpszType);
#else
        fprintf(fp, "  Resource Type: %s\n", lpszType);
#endif
    }

    ::EnumResourceNames(hModule, lpszType, CrEnumResNameProc, lParam);
    return TRUE;
} // CrEnumResTypeProc

void CR_Module::DumpResource(std::FILE *fp) {
    HINSTANCE hInst = ::LoadLibraryEx(m_strFileName.c_str(), NULL,
                                      LOAD_LIBRARY_AS_DATAFILE);
    if (hInst == NULL)
        return;

    fprintf(fp, "\n### RESOURCE ###\n");
    if (!::EnumResourceTypes(hInst, CrEnumResTypeProc,
                             reinterpret_cast<LONG_PTR>(fp)))
    {
        fprintf(fp, "  No resource data\n");
    }
    ::FreeLibrary(hInst);

    fprintf(fp, "\n");
} // CR_Module::DumpResource

////////////////////////////////////////////////////////////////////////////
// decompiling

BOOL CR_Module::Decompile32(CR_DecompInfo32& info) {
    return FALSE;
}

BOOL CR_Module::Decompile64(CR_DecompInfo64& info) {
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
