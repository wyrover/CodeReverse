#ifndef MODULE_H_
#define MODULE_H_

////////////////////////////////////////////////////////////////////////////
// Module.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// REAL_IMAGE_SECTION_HEADER, REAL_IMAGE_DATA_DIRECTORY

#include <pshpack1.h>
typedef struct _REAL_IMAGE_SECTION_HEADER {
    BYTE        Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD       RVA;    // Not VirtualAddress!
    DWORD       SizeOfRawData;
    DWORD       PointerToRawData;
    DWORD       PointerToRelocations;
    DWORD       PointerToLinenumbers;
    WORD        NumberOfRelocations;
    WORD        NumberOfLinenumbers;
    DWORD       Characteristics;
} REAL_IMAGE_SECTION_HEADER, *PREAL_IMAGE_SECTION_HEADER;
#include <poppack.h>

#include <pshpack1.h>
typedef struct _REAL_IMAGE_DATA_DIRECTORY {
    DWORD RVA;  // Not VirtualAddress!
    DWORD Size;
} REAL_IMAGE_DATA_DIRECTORY, *PREAL_IMAGE_DATA_DIRECTORY;
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////
// CR_ImportSymbol

struct CR_ImportSymbol {
    DWORD               iDLL;
    DWORD               dwRVA;
    WORD                wHint;
    union {
        struct {
            WORD        wImportByName;
            WORD        wOrdinal;
        } Name;
        const char *    pszName;
    };
};

////////////////////////////////////////////////////////////////////////////
// CR_ExportSymbol

struct CR_ExportSymbol {
    DWORD       dwRVA;
    DWORD       dwOrdinal;
    const char *pszName;
    const char *pszForwarded;
};

////////////////////////////////////////////////////////////////////////////
// Module

class CR_Module {
public:
    CR_Module();
    virtual ~CR_Module();

public:
    BOOL LoadModule(LPCTSTR pszFileName);
    void UnloadModule();
    BOOL IsModuleLoaded() const;

public:
    BOOL LoadImportTables();
    BOOL LoadExportTable();
    BOOL LoadDelayLoad();

public:
    BOOL IsDLL() const;
    BOOL IsCUIExe() const;
    BOOL IsGUIExe() const;
    BOOL Is32Bit() const;
    BOOL Is64Bit() const;
    BOOL IsCheckSumValid() const;

    DWORD  GetSizeOfHeaders() const;
    DWORD  GetSizeOfImage() const;
    DWORD  GetBaseOfCode() const;
    LPBYTE GetData(DWORD rva);
    DWORD  RVAOfEntryPoint() const;

    DWORD NumberOfSections() const;
          REAL_IMAGE_SECTION_HEADER *SectionHeader(DWORD index);
    const REAL_IMAGE_SECTION_HEADER *SectionHeader(DWORD index) const;

          REAL_IMAGE_DATA_DIRECTORY *DataDirectory(DWORD index);
    const REAL_IMAGE_DATA_DIRECTORY *DataDirectory(DWORD index) const;

    DWORD LastError() const;

public:
    LPBYTE DirEntryData(DWORD index);
    DWORD DirEntryDataSize(DWORD index) const;
    BOOL RVAInDirEntry(DWORD rva, DWORD index) const;

    BOOL IsValidAddr32(DWORD addr) const;
    BOOL IsValidAddr64(DWORDLONG addr) const;

    BOOL AddressInData32(CR_Addr32 va) const;
    BOOL AddressInData64(CR_Addr64 va) const;

    DWORD RVAFromVA32(DWORD va) const;
    DWORD RVAFromVA64(DWORDLONG va) const;
    DWORD VA32FromRVA(DWORD rva) const;
    DWORDLONG VA64FromRVA(DWORD rva) const;

    IMAGE_IMPORT_DESCRIPTOR *   ImportDescriptors();
    IMAGE_EXPORT_DIRECTORY *    ExportDirectory();
    IMAGE_RESOURCE_DIRECTORY *  ResourceDirectory();

          CR_Strings& ImportDllNames();
    const CR_Strings& ImportDllNames() const;

          CR_VecSet<CR_ImportSymbol>& ImportSymbols();
    const CR_VecSet<CR_ImportSymbol>& ImportSymbols() const;
          CR_VecSet<CR_ExportSymbol>& ExportSymbols();
    const CR_VecSet<CR_ExportSymbol>& ExportSymbols() const;

    const CR_ImportSymbol *ImportSymbolFromRVA(DWORD RVA) const;
    const CR_ExportSymbol *ExportSymbolFromRVA(DWORD RVA) const;

          CR_VecSet<ImgDelayDescr>& DelayLoadDescriptors();
    const CR_VecSet<ImgDelayDescr>& DelayLoadDescriptors() const;

          std::unordered_map<DWORD,std::string>& MapRVAToFuncName();
    const std::unordered_map<DWORD,std::string>& MapRVAToFuncName() const;
          std::unordered_map<std::string,DWORD>& MapFuncNameToRVA();
    const std::unordered_map<std::string,DWORD>& MapFuncNameToRVA() const;

    BOOL AddressInCode32(CR_Addr32 va) const;
    BOOL AddressInCode64(CR_Addr64 va) const;
          REAL_IMAGE_SECTION_HEADER *CodeSectionHeader();
    const REAL_IMAGE_SECTION_HEADER *CodeSectionHeader() const;

    const char *FuncNameFromRVA(DWORD RVA) const;
    const char *FuncNameFromVA32(CR_Addr32 addr) const;
    const char *FuncNameFromVA64(CR_Addr64 addr) const;

public:
    BOOL DisAsmAddr32(CR_DecompInfo32& info, CR_Addr32 func, CR_Addr32 va);
    BOOL DisAsmAddr64(CR_DecompInfo64& info, CR_Addr64 func, CR_Addr64 va);
    BOOL DisAsm32(CR_DecompInfo32& info);
    BOOL DisAsm64(CR_DecompInfo64& info);

    BOOL FixupAsm32(CR_DecompInfo32& info);
    BOOL FixupAsm64(CR_DecompInfo64& info);

    BOOL Decompile32(CR_DecompInfo32& info);
    BOOL Decompile64(CR_DecompInfo64& info);

public:
    void DumpHeaders(std::FILE *fp);
    void DumpImportSymbols(std::FILE *fp);
    void DumpExportSymbols(std::FILE *fp);
    void DumpDelayLoad(std::FILE *fp);
    void DumpResource(std::FILE *fp);

    void _DumpImportSymbols32(std::FILE *fp);
    void _DumpImportSymbols64(std::FILE *fp);
    void _DumpExportSymbols32(std::FILE *fp);
    void _DumpExportSymbols64(std::FILE *fp);
    void _DumpDelayLoad32(std::FILE *fp);
    void _DumpDelayLoad64(std::FILE *fp);

    BOOL DumpDisAsm32(std::FILE *fp, CR_DecompInfo32& info);
    BOOL DumpDisAsm64(std::FILE *fp, CR_DecompInfo64& info);

    BOOL _DumpDisAsmFunc32(std::FILE *fp, CR_DecompInfo32& info, CR_Addr32 func);
    BOOL _DumpDisAsmFunc64(std::FILE *fp, CR_DecompInfo64& info, CR_Addr64 func);

    BOOL DumpDecompile32(std::FILE *fp, CR_DecompInfo32& info);
    BOOL DumpDecompile64(std::FILE *fp, CR_DecompInfo64& info);

protected:
    tstring                         m_strFileName;
    HANDLE                          m_hFile;
    HANDLE                          m_hFileMapping;
    LPBYTE                          m_pFileImage;
    DWORD                           m_dwFileSize;
    LPBYTE                          m_pLoadedImage;
    IMAGE_DOS_HEADER *              m_pDOSHeader;
    union {
        IMAGE_NT_HEADERS *          m_pNTHeaders;
        IMAGE_NT_HEADERS32 *        m_pNTHeaders32;
        IMAGE_NT_HEADERS64 *        m_pNTHeaders64;
    };
    IMAGE_FILE_HEADER *             m_pFileHeader;
    IMAGE_OPTIONAL_HEADER32 *       m_pOptional32;
    IMAGE_OPTIONAL_HEADER64 *       m_pOptional64;
    DWORD                           m_dwLastError;
    DWORD                           m_dwHeaderSum;
    DWORD                           m_dwCheckSum;
    REAL_IMAGE_SECTION_HEADER *     m_pSectionHeaders;
    REAL_IMAGE_DATA_DIRECTORY *     m_pDataDirectories;

    CR_Strings                      m_vecImportDllNames;
    CR_VecSet<CR_ImportSymbol>      m_vecImportSymbols;
    CR_VecSet<CR_ExportSymbol>      m_vecExportSymbols;
    CR_VecSet<ImgDelayDescr>        m_vecDelayLoadDescriptors;

    std::unordered_map<DWORD,std::string> m_mRVAToFuncNameMap;
    std::unordered_map<std::string,DWORD> m_mFuncNameToRVAMap;

    BOOL _LoadImage(LPVOID Data);
    BOOL _LoadNTHeaders(LPVOID Data);
    BOOL _GetImportDllNames(CR_Strings& names);
    BOOL _GetImportSymbols(DWORD dll_index, CR_VecSet<CR_ImportSymbol>& symbols);
    BOOL _GetExportSymbols(CR_VecSet<CR_ExportSymbol>& symbols);
}; // class CR_Module

////////////////////////////////////////////////////////////////////////////
// Dumping.cpp

const char *CrGetTimeStampString(DWORD TimeStamp);
const char *CrGetMachineString(WORD Machine);
const char *CrGetFileCharacteristicsString(WORD w);
const char *CrGetSectionFlagsString(DWORD dw);
const char *CrGetDllCharacteristicsString(WORD w);
const char *CrGetSubsystemString(WORD w);
void CrDumpDataDirectory(std::FILE *fp, LPVOID Data, DWORD index);
void CrDumpDOSHeader(std::FILE *fp, LPVOID Data);
void CrDumpFileHeader(std::FILE *fp, LPVOID Data);
void CrDumpOptionalHeader32(std::FILE *fp, LPVOID Data, DWORD CheckSum);
void CrDumpOptionalHeader64(std::FILE *fp, LPVOID Data, DWORD CheckSum);
void CrDumpSectionHeader(std::FILE *fp, LPVOID Data);
void CrDumpCodes(std::FILE *fp, const CR_DataBytes& codes, int bits);

////////////////////////////////////////////////////////////////////////////

// inline functions
#include "Module_inl.h"

#endif  // ndef MODULE_H_
