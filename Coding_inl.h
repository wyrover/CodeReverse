////////////////////////////////////////////////////////////////////////////
// Coding_inl.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// CR_Operand

inline CR_Operand::CR_Operand() {
    clear();
}

inline CR_Operand::CR_Operand(const CR_Operand& opr) {
    Copy(opr);
}

inline /*virtual*/ CR_Operand::~CR_Operand() { }

inline CR_Operand& CR_Operand::operator=(const CR_Operand& opr) {
    Copy(opr);
    return *this;
}

inline CR_OperandFlags CR_Operand::GetOperandType() const {
    return OperandFlags() & cr_OF_TYPEMASK;
}

inline void CR_Operand::SetOperandType(CR_OperandFlags flags) {
    OperandFlags() &= ~cr_OF_TYPEMASK;
    OperandFlags() |= flags;
}

inline void CR_Operand::SetFuncName(const char *name) {
    Text() = name;
    OperandFlags() |= cr_OF_FUNCNAME;
}

inline void CR_Operand::SetMemImm(CR_Addr64 addr) {
    Value64() = addr;
    SetOperandType(cr_OF_MEMIMM);
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand accessors

inline std::string& CR_Operand::Text() {
    return m_text;
}

inline std::string& CR_Operand::BaseReg() {
    return m_basereg;
}

inline std::string& CR_Operand::IndexReg() {
    return m_indexreg;
}

inline std::string& CR_Operand::Seg() {
    return m_seg;
}

inline CR_OperandFlags& CR_Operand::OperandFlags() {
    return m_flags;
}

inline DWORD& CR_Operand::Size() {
    return m_size;
}

inline CR_Addr32& CR_Operand::Value32() {
    return m_value32;
}

inline CR_Addr64& CR_Operand::Value64() {
    return m_value64;
}

inline CR_TriBool& CR_Operand::IsInteger() {
    return m_is_integer;
}

inline CR_TriBool& CR_Operand::IsPointer() {
    return m_is_pointer;
}

inline CR_TriBool& CR_Operand::IsFunction() {
    return m_is_function;
}

inline CR_Addr32& CR_Operand::Disp() {
    return m_disp;
}

inline char& CR_Operand::Scale() {
    return m_scale;
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand const accessors

inline const std::string& CR_Operand::Text() const {
    return m_text;
}

inline const std::string& CR_Operand::BaseReg() const {
    return m_basereg;
}

inline const std::string& CR_Operand::IndexReg() const {
    return m_indexreg;
}

inline const std::string& CR_Operand::Seg() const {
    return m_seg;
}

inline const CR_OperandFlags& CR_Operand::OperandFlags() const {
    return m_flags;
}

inline const DWORD& CR_Operand::Size() const {
    return m_size;
}

inline const CR_Addr32& CR_Operand::Value32() const {
    return m_value32;
}

inline const CR_Addr64& CR_Operand::Value64() const {
    return m_value64;
}

inline const CR_TriBool& CR_Operand::IsInteger() const {
    return m_is_integer;
}

inline const CR_TriBool& CR_Operand::IsPointer() const {
    return m_is_pointer;
}

inline const CR_TriBool& CR_Operand::IsFunction() const {
    return m_is_function;
}

inline const CR_Addr32& CR_Operand::Disp() const {
    return m_disp;
}

inline const char& CR_Operand::Scale() const {
    return m_scale;
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32

inline CR_OpCode32::CR_OpCode32() {
    clear();
}

inline CR_OpCode32::CR_OpCode32(const CR_OpCode32& oc) {
    Copy(oc);
}

inline /*virtual*/ CR_OpCode32::~CR_OpCode32() { }

inline CR_OpCode32& CR_OpCode32::operator=(const CR_OpCode32& oc) {
    Copy(oc);
    return *this;
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32 accessors

inline CR_Addr32Set& CR_OpCode32::FuncAddrs() {
    return m_funcaddrs;
}

inline CR_Addr32& CR_OpCode32::Addr() {
    return m_addr;
}

inline std::string& CR_OpCode32::Name() {
    return m_name;
}

inline CR_Operands& CR_OpCode32::Operands() {
    return m_operands;
}

inline CR_Operand* CR_OpCode32::Operand(std::size_t index) {
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline CR_DataBytes& CR_OpCode32::Codes() {
    return m_codes;
}

inline CR_OpCodeType& CR_OpCode32::OpCodeType() {
    return m_oct;
}

inline CR_CondCode& CR_OpCode32::CondCode() {
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32 const accessors

inline const CR_Addr32Set& CR_OpCode32::FuncAddrs() const {
    return m_funcaddrs;
}

inline const CR_Addr32& CR_OpCode32::Addr() const {
    return m_addr;
}

inline const std::string& CR_OpCode32::Name() const {
    return m_name;
}

inline const CR_Operands& CR_OpCode32::Operands() const {
    return m_operands;
}

inline const CR_Operand* CR_OpCode32::Operand(std::size_t index) const {
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const CR_DataBytes& CR_OpCode32::Codes() const {
    return m_codes;
}

inline const CR_OpCodeType& CR_OpCode32::OpCodeType() const {
    return m_oct;
}

inline const CR_CondCode& CR_OpCode32::CondCode() const {
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64

inline CR_OpCode64::CR_OpCode64() {
    clear();
}

inline CR_OpCode64::CR_OpCode64(const CR_OpCode64& oc) {
    Copy(oc);
}

inline /*virtual*/ CR_OpCode64::~CR_OpCode64() { }

inline CR_OpCode64& CR_OpCode64::operator=(const CR_OpCode64& oc) {
    Copy(oc);
    return *this;
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64 accessors

inline CR_Addr64Set& CR_OpCode64::FuncAddrs() {
    return m_funcaddrs;
}

inline CR_Addr64& CR_OpCode64::Addr() {
    return m_addr;
}

inline std::string& CR_OpCode64::Name() {
    return m_name;
}

inline CR_Operands& CR_OpCode64::Operands() {
    return m_operands;
}

inline CR_Operand* CR_OpCode64::Operand(std::size_t index) {
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline CR_DataBytes& CR_OpCode64::Codes() {
    return m_codes;
}

inline CR_OpCodeType& CR_OpCode64::OpCodeType() {
    return m_oct;
}

inline CR_CondCode& CR_OpCode64::CondCode() {
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64 const accessors

inline const CR_Addr64Set& CR_OpCode64::FuncAddrs() const {
    return m_funcaddrs;
}

inline const CR_Addr64& CR_OpCode64::Addr() const {
    return m_addr;
}

inline const std::string& CR_OpCode64::Name() const {
    return m_name;
}

inline const CR_Operands& CR_OpCode64::Operands() const {
    return m_operands;
}

inline const CR_Operand* CR_OpCode64::Operand(std::size_t index) const {
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const CR_DataBytes& CR_OpCode64::Codes() const {
    return m_codes;
}

inline const CR_OpCodeType& CR_OpCode64::OpCodeType() const {
    return m_oct;
}

inline const CR_CondCode& CR_OpCode64::CondCode() const {
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 accessors

inline CR_Addr32& CR_CodeFunc32::Addr() {
    return m_addr;
}

inline std::string& CR_CodeFunc32::Name() {
    return m_name;
}

inline CR_FuncFlags& CR_CodeFunc32::FuncFlags() {
    return m_dwFuncFlags;
}

inline CR_Range& CR_CodeFunc32::ArgSizeRange() {
    return m_ArgSizeRange;
}

inline CR_Addr32Set& CR_CodeFunc32::Jumpees() {
    return m_jumpees;
}

inline CR_Addr32Set& CR_CodeFunc32::Jumpers() {
    return m_jumpers;
}

inline CR_Addr32Set& CR_CodeFunc32::Callees() {
    return m_callees;
}

inline CR_Addr32Set& CR_CodeFunc32::Callers() {
    return m_callees;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 const accessors

inline const CR_Addr32& CR_CodeFunc32::Addr() const {
    return m_addr;
}

inline const std::string& CR_CodeFunc32::Name() const {
    return m_name;
}

inline const CR_FuncFlags& CR_CodeFunc32::FuncFlags() const {
    return m_dwFuncFlags;
}

inline const CR_Range& CR_CodeFunc32::ArgSizeRange() const {
    return m_ArgSizeRange;
}

inline const CR_Addr32Set& CR_CodeFunc32::Jumpees() const {
    return m_jumpees;
}

inline const CR_Addr32Set& CR_CodeFunc32::Jumpers() const {
    return m_jumpers;
}

inline const CR_Addr32Set& CR_CodeFunc32::Callees() const {
    return m_callees;
}

inline const CR_Addr32Set& CR_CodeFunc32::Callers() const {
    return m_callees;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 accessors

inline CR_Addr64& CR_CodeFunc64::Addr() {
    return m_addr;
}

inline std::string& CR_CodeFunc64::Name() {
    return m_name;
}

inline CR_FuncFlags& CR_CodeFunc64::FuncFlags() {
    return m_dwFuncFlags;
}

inline CR_Range& CR_CodeFunc64::ArgSizeRange() {
    return m_ArgSizeRange;
}

inline CR_Addr64Set& CR_CodeFunc64::Jumpees() {
    return m_jumpees;
}

inline CR_Addr64Set& CR_CodeFunc64::Jumpers() {
    return m_jumpers;
}

inline CR_Addr64Set& CR_CodeFunc64::Callees() {
    return m_callees;
}

inline CR_Addr64Set& CR_CodeFunc64::Callers() {
    return m_callees;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 const accessors

inline const CR_Addr64& CR_CodeFunc64::Addr() const {
    return m_addr;
}

inline const std::string& CR_CodeFunc64::Name() const {
    return m_name;
}

inline const CR_FuncFlags& CR_CodeFunc64::FuncFlags() const {
    return m_dwFuncFlags;
}

inline const CR_Range& CR_CodeFunc64::ArgSizeRange() const {
    return m_ArgSizeRange;
}

inline const CR_Addr64Set& CR_CodeFunc64::Jumpees() const {
    return m_jumpees;
}

inline const CR_Addr64Set& CR_CodeFunc64::Jumpers() const {
    return m_jumpers;
}

inline const CR_Addr64Set& CR_CodeFunc64::Callees() const {
    return m_callees;
}

inline const CR_Addr64Set& CR_CodeFunc64::Callers() const {
    return m_callees;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32

inline CR_CodeFunc32::CR_CodeFunc32() {
    clear();
}

inline CR_CodeFunc32::CR_CodeFunc32(const CR_CodeFunc32& cf) {
    Copy(cf);
}

inline CR_CodeFunc32& CR_CodeFunc32::operator=(const CR_CodeFunc32& cf) {
    Copy(cf);
    return *this;
}

inline /*virtual*/ CR_CodeFunc32::~CR_CodeFunc32() { }

inline void CR_CodeFunc32::Copy(const CR_CodeFunc32& cf) {
    Addr() = cf.Addr();
    Name() = cf.Name();
    FuncFlags() = cf.FuncFlags();
    ArgSizeRange() = cf.ArgSizeRange();
}

inline void CR_CodeFunc32::clear() {
    Addr() = 0;
    Name().clear();
    FuncFlags() = 0;
    ArgSizeRange().clear();
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64

inline CR_CodeFunc64::CR_CodeFunc64() {
    clear();
}

inline CR_CodeFunc64::CR_CodeFunc64(const CR_CodeFunc64& cf) {
    Copy(cf);
}

inline CR_CodeFunc64& CR_CodeFunc64::operator=(const CR_CodeFunc64& cf) {
    Copy(cf);
    return *this;
}

inline /*virtual*/ CR_CodeFunc64::~CR_CodeFunc64() { }

inline void CR_CodeFunc64::Copy(const CR_CodeFunc64& cf) {
    Addr() = cf.Addr();
    Name() = cf.Name();
    FuncFlags() = cf.FuncFlags();
    ArgSizeRange() = cf.ArgSizeRange();
}

inline void CR_CodeFunc64::clear() {
    Addr() = 0;
    Name().clear();
    FuncFlags() = cr_FF_64BITFUNC;
    ArgSizeRange().clear();
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32

inline CR_DecompInfo32::CR_DecompInfo32() :
    m_error_info(make_shared<CR_ErrorInfo>()),
    m_namescope(m_error_info, false) { }

inline CR_DecompInfo32::CR_DecompInfo32(const CR_DecompInfo32& info) :
    m_mAddrToOpCode(info.m_mAddrToOpCode),
    m_sEntrances(info.m_sEntrances),
    m_mAddrToCodeFunc(info.m_mAddrToCodeFunc),
    m_error_info(info.m_namescope.ErrorInfo()),
    m_namescope(info.m_namescope)
{
}

inline CR_DecompInfo32& CR_DecompInfo32::operator=(const CR_DecompInfo32& info) {
    MapAddrToOpCode() = info.MapAddrToOpCode();
    Entrances() = info.Entrances();
    MapAddrToCodeFunc() = info.MapAddrToCodeFunc();
    ErrorInfo() = info.ErrorInfo();
    NameScope() = info.NameScope();
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

inline CR_NameScope& CR_DecompInfo32::NameScope() {
    return m_namescope;
}

inline shared_ptr<CR_ErrorInfo>& CR_DecompInfo32::ErrorInfo() {
    return m_error_info;
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

inline const CR_NameScope& CR_DecompInfo32::NameScope() const {
    return m_namescope;
}

inline const shared_ptr<CR_ErrorInfo>& CR_DecompInfo32::ErrorInfo() const {
    return m_error_info;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64

inline CR_DecompInfo64::CR_DecompInfo64() :
    m_error_info(make_shared<CR_ErrorInfo>()),
    m_namescope(m_error_info, true) { }

inline CR_DecompInfo64::CR_DecompInfo64(const CR_DecompInfo64& info) :
    m_mAddrToOpCode(info.m_mAddrToOpCode),
    m_sEntrances(info.m_sEntrances),
    m_mAddrToCodeFunc(info.m_mAddrToCodeFunc),
    m_error_info(info.m_namescope.ErrorInfo()),
    m_namescope(info.m_namescope)
{
}

inline CR_DecompInfo64& CR_DecompInfo64::operator=(const CR_DecompInfo64& info) {
    MapAddrToOpCode() = info.MapAddrToOpCode();
    Entrances() = info.Entrances();
    MapAddrToCodeFunc() = info.MapAddrToCodeFunc();
    ErrorInfo() = info.ErrorInfo();
    NameScope() = info.NameScope();
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

inline CR_NameScope& CR_DecompInfo64::NameScope() {
    return m_namescope;
}

inline shared_ptr<CR_ErrorInfo>& CR_DecompInfo64::ErrorInfo() {
    return m_error_info;
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

inline const CR_NameScope& CR_DecompInfo64::NameScope() const {
    return m_namescope;
}

inline const shared_ptr<CR_ErrorInfo>& CR_DecompInfo64::ErrorInfo() const {
    return m_error_info;
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
    NameScope().clear();
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
    NameScope().clear();
}

////////////////////////////////////////////////////////////////////////////
