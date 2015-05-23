////////////////////////////////////////////////////////////////////////////
// Module_inl.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

inline /*virtual*/ CR_Module::~CR_Module() {
    if (IsModuleLoaded()) {
        UnloadModule();
    }
}

inline BOOL CR_Module::IsModuleLoaded() const {
    return !m_strFileName.empty();
}

inline BOOL CR_Module::Is32Bit() const {
    return m_pOptional32 != NULL;
}

inline BOOL CR_Module::Is64Bit() const {
    return m_pOptional64 != NULL;
}

inline DWORD CR_Module::NumberOfSections() const {
    assert(m_pFileHeader);
    return m_pFileHeader->NumberOfSections;
}

inline DWORD CR_Module::GetSizeOfHeaders() const {
    if (Is64Bit())
        return m_pOptional64->SizeOfHeaders;
    else if (Is32Bit())
        return m_pOptional32->SizeOfHeaders;
    else
        return 0;
}

inline DWORD CR_Module::GetSizeOfImage() const {
    if (Is64Bit())
        return m_pOptional64->SizeOfImage;
    else if (Is32Bit())
        return m_pOptional32->SizeOfImage;
    else
        return 0;
}

inline DWORD CR_Module::LastError() const {
    return m_dwLastError;
}

inline IMAGE_IMPORT_DESCRIPTOR *CR_Module::ImportDescriptors() {
    return reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_IMPORT));
}

inline IMAGE_EXPORT_DIRECTORY *CR_Module::ExportDirectory() {
    return reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_EXPORT));
}

inline IMAGE_RESOURCE_DIRECTORY *CR_Module::ResourceDirectory() {
    return reinterpret_cast<IMAGE_RESOURCE_DIRECTORY *>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_RESOURCE));
}

inline DWORD CR_Module::DirEntryDataSize(DWORD index) const {
    if (m_pDataDirectories == NULL)
        return 0;
    return (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ?
        m_pDataDirectories[index].Size : 0);
}

inline BOOL CR_Module::IsDLL() const {
    if (!IsModuleLoaded())
        return FALSE;

    return (m_pFileHeader->Characteristics & IMAGE_FILE_DLL) != 0;
}

inline LPBYTE CR_Module::GetData(DWORD rva) {
    return (m_pLoadedImage ? m_pLoadedImage + rva : NULL);
}

inline DWORD CR_Module::RVAFromVA32(DWORD va) const {
    assert(m_pOptional32);
    return va - m_pOptional32->ImageBase;
}

inline DWORD CR_Module::RVAFromVA64(DWORDLONG va) const {
    assert(m_pOptional64);
    return (DWORD)(va - m_pOptional64->ImageBase);
}

inline DWORD CR_Module::VA32FromRVA(DWORD rva) const {
    assert(m_pOptional32);
    return m_pOptional32->ImageBase + rva;
}

inline DWORDLONG CR_Module::VA64FromRVA(DWORD rva) const {
    assert(m_pOptional64);
    return m_pOptional64->ImageBase + rva;
}

inline REAL_IMAGE_SECTION_HEADER *CR_Module::SectionHeader(DWORD index) {
    assert(m_pSectionHeaders);
    if (index < NumberOfSections())
        return &m_pSectionHeaders[index];
    return NULL;
}

inline const REAL_IMAGE_SECTION_HEADER *
CR_Module::SectionHeader(DWORD index) const {
    assert(m_pSectionHeaders);
    if (index < NumberOfSections())
        return &m_pSectionHeaders[index];
    return NULL;
}

inline REAL_IMAGE_DATA_DIRECTORY *CR_Module::DataDirectory(DWORD index) {
    assert(m_pDataDirectories);
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    return &m_pDataDirectories[index];
}

inline const REAL_IMAGE_DATA_DIRECTORY *
CR_Module::DataDirectory(DWORD index) const {
    assert(m_pDataDirectories);
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    return &m_pDataDirectories[index];
}

inline BOOL CR_Module::IsCheckSumValid() const {
    assert(IsModuleLoaded());
    if (Is64Bit()) {
        return m_pOptional64->CheckSum == 0 ||
               m_pOptional64->CheckSum == m_dwCheckSum;
    } else if (Is32Bit()) {
        return m_pOptional32->CheckSum == 0 ||
               m_pOptional32->CheckSum == m_dwCheckSum;
    }
    return FALSE;
}

inline LPBYTE CR_Module::DirEntryData(DWORD index) {
    if (m_pDataDirectories && index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        if (m_pDataDirectories[index].RVA && m_pDataDirectories[index].Size) {
            return m_pLoadedImage + m_pDataDirectories[index].RVA;
        }
    }
    return NULL;
}

inline BOOL CR_Module::IsCUIExe() const {
    if (!IsModuleLoaded() || IsDLL())
        return FALSE;

    if (Is64Bit())
        return m_pOptional64->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    else if (Is32Bit())
        return m_pOptional32->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    else
        return FALSE;
}

inline BOOL CR_Module::IsGUIExe() const {
    if (!IsModuleLoaded() || IsDLL())
        return FALSE;

    if (Is64Bit())
        return m_pOptional64->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
    else if (Is32Bit())
        return m_pOptional32->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
    else
        return FALSE;
}

inline BOOL CR_Module::RVAInDirEntry(DWORD rva, DWORD index) const {
    assert(IsModuleLoaded());
    return (
        index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        m_pDataDirectories[index].RVA <= rva &&
        rva < m_pDataDirectories[index].RVA +
              m_pDataDirectories[index].Size);
}

inline BOOL CR_Module::IsValidAddr32(DWORD addr) const {
    if (!Is32Bit())
        return FALSE;
    const DWORD begin = m_pOptional32->ImageBase;
    const DWORD end = begin + m_pOptional32->SizeOfImage;
    return begin <= addr && addr < end;
}

inline BOOL CR_Module::IsValidAddr64(DWORDLONG addr) const {
    if (!Is64Bit())
        return FALSE;
    const DWORDLONG begin = m_pOptional64->ImageBase;
    const DWORDLONG end = begin + m_pOptional64->SizeOfImage;
    return begin <= addr && addr < end;
}

inline DWORD CR_Module::GetBaseOfCode() const {
    if (Is64Bit())
        return m_pOptional64->BaseOfCode;
    else if (Is32Bit())
        return m_pOptional32->BaseOfCode;
    else
        return 0;
}

inline DWORD CR_Module::RVAOfEntryPoint() const {
    if (Is64Bit())
        return m_pOptional64->AddressOfEntryPoint;
    else if (Is32Bit())
        return m_pOptional32->AddressOfEntryPoint;
    else
        return 0;
}

inline std::vector<CR_ImportSymbol>& CR_Module::ImportSymbols() {
    return m_vecImportSymbols;
}

inline const std::vector<CR_ImportSymbol>& CR_Module::ImportSymbols() const {
    return m_vecImportSymbols;
}

inline std::vector<CR_ExportSymbol>& CR_Module::ExportSymbols() {
    return m_vecExportSymbols;
}

inline const std::vector<CR_ExportSymbol>& CR_Module::ExportSymbols() const {
    return m_vecExportSymbols;
}

inline BOOL CR_Module::AddressInData32(CR_Addr32 va) const {
    return (Is32Bit() && IsValidAddr32(va) && !AddressInCode32(va));
}

inline BOOL CR_Module::AddressInData64(CR_Addr64 va) const {
    return (Is64Bit() && IsValidAddr64(va) && !AddressInCode64(va));
}

inline const CR_ImportSymbol *
CR_Module::ImportSymbolFromRVA(DWORD RVA) const {
    for (auto& symbol : ImportSymbols()) {
        if (symbol.dwRVA == RVA) {
            return &symbol;
        }
    }
    return NULL;
}

inline const CR_ExportSymbol *
CR_Module::ExportSymbolFromRVA(DWORD RVA) const {
    for (auto& symbol : ExportSymbols()) {
        if (symbol.dwRVA == RVA) {
            return &symbol;
        }
    }
    return NULL;
}

inline CR_VecSet<ImgDelayDescr>& CR_Module::DelayLoadDescriptors() {
    return m_vecDelayLoadDescriptors;
}

inline const CR_VecSet<ImgDelayDescr>&
CR_Module::DelayLoadDescriptors() const {
    return m_vecDelayLoadDescriptors;
}

inline const char *CR_Module::FuncNameFromVA32(CR_Addr32 addr) const {
    return FuncNameFromRVA(RVAFromVA32(addr));
}

inline const char *CR_Module::FuncNameFromVA64(CR_Addr64 addr) const {
    return FuncNameFromRVA(RVAFromVA64(addr));
}

inline std::unordered_map<DWORD,std::string>&
CR_Module::MapRVAToFuncName() {
    return m_mRVAToFuncNameMap;
}

inline const std::unordered_map<DWORD,std::string>&
CR_Module::MapRVAToFuncName() const {
    return m_mRVAToFuncNameMap;
}

inline std::unordered_map<std::string,DWORD>& CR_Module::MapFuncNameToRVA() {
    return m_mFuncNameToRVAMap;
}

inline const std::unordered_map<std::string,DWORD>&
CR_Module::MapFuncNameToRVA() const {
    return m_mFuncNameToRVAMap;
}

inline CR_Strings& CR_Module::ImportDllNames() {
    return m_vecImportDllNames;
}

inline const CR_Strings& CR_Module::ImportDllNames() const {
    return m_vecImportDllNames;
}

inline BOOL CR_Module::AddressInCode32(CR_Addr32 va) const {
    if (!Is32Bit())
        return FALSE;

    const REAL_IMAGE_SECTION_HEADER *pCode = CodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    const CR_Addr32 begin = m_pOptional32->ImageBase + pCode->RVA;
    const CR_Addr32 end = begin + pCode->Misc.VirtualSize;
    return begin <= va && va < end;
} // CR_Module::AddressInCode32

inline BOOL CR_Module::AddressInCode64(CR_Addr64 va) const {
    if (!Is64Bit())
        return FALSE;

    const REAL_IMAGE_SECTION_HEADER *pCode = CodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    const CR_Addr64 begin = m_pOptional64->ImageBase + pCode->RVA;
    const CR_Addr64 end = begin + pCode->Misc.VirtualSize;
    return begin <= va && va < end;
} // CR_Module::AddressInCode64

////////////////////////////////////////////////////////////////////////////
