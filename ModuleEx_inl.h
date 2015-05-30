////////////////////////////////////////////////////////////////////////////
// ModuleEx_inl.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32

inline CR_DecompInfo32::CR_DecompInfo32() { }

inline CR_DecompInfo32::CR_DecompInfo32(const CR_DecompInfo32& info) :
    m_mAddrToOpCode(info.m_mAddrToOpCode),
    m_sEntrances(info.m_sEntrances),
    m_mAddrToCodeFunc(info.m_mAddrToCodeFunc)
{
}

inline CR_DecompInfo32& CR_DecompInfo32::operator=(const CR_DecompInfo32& info) {
    MapAddrToOpCode() = info.MapAddrToOpCode();
    Entrances() = info.Entrances();
    MapAddrToCodeFunc() = info.MapAddrToCodeFunc();
    return *this;
}

inline /*virtual*/ CR_DecompInfo32::~CR_DecompInfo32() { }

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32 accessors

inline std::map<CR_Addr32, CR_ShdOpCode32>&
CR_DecompInfo32::MapAddrToOpCode() {
    return m_mAddrToOpCode;
}

inline CR_Addr32Set& CR_DecompInfo32::Entrances() {
    return m_sEntrances;
}

inline std::map<CR_Addr32, CR_ShdCodeFunc32>&
CR_DecompInfo32::MapAddrToCodeFunc() {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32 const accessors

inline const std::map<CR_Addr32, CR_ShdOpCode32>&
CR_DecompInfo32::MapAddrToOpCode() const {
    return m_mAddrToOpCode;
}

inline const CR_Addr32Set& CR_DecompInfo32::Entrances() const {
    return m_sEntrances;
}

inline const std::map<CR_Addr32, CR_ShdCodeFunc32>&
CR_DecompInfo32::MapAddrToCodeFunc() const {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64

inline CR_DecompInfo64::CR_DecompInfo64() { }

inline CR_DecompInfo64::CR_DecompInfo64(const CR_DecompInfo64& info) :
    m_mAddrToOpCode(info.m_mAddrToOpCode),
    m_sEntrances(info.m_sEntrances),
    m_mAddrToCodeFunc(info.m_mAddrToCodeFunc)
{
}

inline CR_DecompInfo64& CR_DecompInfo64::operator=(const CR_DecompInfo64& info) {
    MapAddrToOpCode() = info.MapAddrToOpCode();
    Entrances() = info.Entrances();
    MapAddrToCodeFunc() = info.MapAddrToCodeFunc();
    return *this;
}

inline /*virtual*/ CR_DecompInfo64::~CR_DecompInfo64() { }

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64 accessors

inline std::map<CR_Addr64, CR_ShdOpCode64>&
CR_DecompInfo64::MapAddrToOpCode() {
    return m_mAddrToOpCode;
}

inline CR_Addr64Set& CR_DecompInfo64::Entrances() {
    return m_sEntrances;
}

inline std::map<CR_Addr64, CR_ShdCodeFunc64>&
CR_DecompInfo64::MapAddrToCodeFunc() {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64 const accessors

inline const std::map<CR_Addr64, CR_ShdOpCode64>&
CR_DecompInfo64::MapAddrToOpCode() const {
    return m_mAddrToOpCode;
}

inline const CR_Addr64Set& CR_DecompInfo64::Entrances() const {
    return m_sEntrances;
}

inline const std::map<CR_Addr64, CR_ShdCodeFunc64>&
CR_DecompInfo64::MapAddrToCodeFunc() const {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32

inline CR_CodeFunc32 *CR_DecompInfo32::CodeFuncFromAddr(CR_Addr32 addr) {
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return it->second.get();
    else
        return NULL;
}

inline const CR_CodeFunc32 *
CR_DecompInfo32::CodeFuncFromAddr(CR_Addr32 addr) const {
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return it->second.get();
    else
        return NULL;
}

inline CR_OpCode32 *CR_DecompInfo32::OpCodeFromAddr(CR_Addr32 addr) {
    auto it = MapAddrToOpCode().find(addr);
    if (it != MapAddrToOpCode().end())
        return it->second.get();
    else
        return NULL;
}

inline const CR_OpCode32 *
CR_DecompInfo32::OpCodeFromAddr(CR_Addr32 addr) const {
    auto it = MapAddrToOpCode().find(addr);
    if (it != MapAddrToOpCode().end())
        return it->second.get();
    else
        return NULL;
}

inline void CR_DecompInfo32::clear() {
    MapAddrToOpCode().clear();
    Entrances().clear();
    MapAddrToCodeFunc().clear();
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64

inline CR_CodeFunc64 *CR_DecompInfo64::CodeFuncFromAddr(CR_Addr64 addr) {
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return it->second.get();
    else
        return NULL;
}

inline const CR_CodeFunc64 *
CR_DecompInfo64::CodeFuncFromAddr(CR_Addr64 addr) const {
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return it->second.get();
    else
        return NULL;
}

inline CR_OpCode64 *CR_DecompInfo64::OpCodeFromAddr(CR_Addr64 addr) {
    auto it = MapAddrToOpCode().find(addr);
    if (it != MapAddrToOpCode().end())
        return it->second.get();
    else
        return NULL;
}

inline const CR_OpCode64 *
CR_DecompInfo64::OpCodeFromAddr(CR_Addr64 addr) const {
    auto it = MapAddrToOpCode().find(addr);
    if (it != MapAddrToOpCode().end())
        return it->second.get();
    else
        return NULL;
}

inline void CR_DecompInfo64::clear() {
    MapAddrToOpCode().clear();
    Entrances().clear();
    MapAddrToCodeFunc().clear();
}

////////////////////////////////////////////////////////////////////////////
// CR_ModuleEx

inline CR_ModuleEx::CR_ModuleEx() {
}

inline /*virtual*/ CR_ModuleEx::~CR_ModuleEx() {
}

inline void CR_ModuleEx::_CreateInfo32() {
    if (!Info32()) {
        Info32() = make_shared<CR_DecompInfo32>();
    }
}

inline void CR_ModuleEx::_CreateInfo64() {
    if (!Info64()) {
        Info64() = make_shared<CR_DecompInfo64>();
    }
}

inline shared_ptr<CR_DecompInfo32>& CR_ModuleEx::Info32() {
    return m_pinfo32;
}

inline shared_ptr<CR_DecompInfo64>& CR_ModuleEx::Info64() {
    return m_pinfo64;
}

inline const shared_ptr<CR_DecompInfo32>& CR_ModuleEx::Info32() const {
    return m_pinfo32;
}

inline const shared_ptr<CR_DecompInfo64>& CR_ModuleEx::Info64() const {
    return m_pinfo64;
}

////////////////////////////////////////////////////////////////////////////
