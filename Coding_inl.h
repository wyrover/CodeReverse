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

inline void CR_Operand::operator=(const CR_Operand& opr) {
    Copy(opr);
}

inline void CR_Operand::SetReg(const char *name) {
    Text() = name;
    OperandType() = OT_REG;
    Size() = CrRegGetSize(name, 64);
}

inline void CR_Operand::SetFuncName(const char *name) {
    Text() = name;
    OperandType() = OT_FUNCNAME;
}

inline void CR_Operand::SetLabel(const char *label) {
    Text() = label;
    OperandType() = OT_IMM;
}

inline void CR_Operand::SetMemImm(CR_Addr64 addr) {
    OperandType() = OT_MEMIMM;
    Value64() = addr;
}

inline void CR_Operand::SetMemExpr(const char *exp) {
    OperandType() = OT_MEMEXPR;
    MemExpr() = exp;
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand accessors

inline CR_String& CR_Operand::Text() {
    return m_text;
}

inline CR_OperandType& CR_Operand::OperandType() {
    return m_ot;
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

inline CR_String& CR_Operand::MemExpr() {
    return m_memexpr;
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

////////////////////////////////////////////////////////////////////////////
// CR_Operand const accessors

inline const CR_String& CR_Operand::Text() const {
    return m_text;
}

inline const CR_OperandType& CR_Operand::OperandType() const {
    return m_ot;
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

inline const CR_String& CR_Operand::MemExpr() const {
    return m_memexpr;
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

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32

inline CR_OpCode32::CR_OpCode32() {
    clear();
}

inline CR_OpCode32::CR_OpCode32(const CR_OpCode32& oc) {
    Copy(oc);
}

inline /*virtual*/ CR_OpCode32::~CR_OpCode32() { }

inline void CR_OpCode32::operator=(const CR_OpCode32& oc) {
    Copy(oc);
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32 accessors

inline CR_Addr32Set& CR_OpCode32::FuncAddrs() {
    return m_funcaddrs;
}

inline CR_Addr32& CR_OpCode32::Addr() {
    return m_addr;
}

inline CR_String& CR_OpCode32::Name() {
    return m_name;
}

inline CR_OperandSet& CR_OpCode32::Operands() {
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

inline const CR_String& CR_OpCode32::Name() const {
    return m_name;
}

inline const CR_OperandSet& CR_OpCode32::Operands() const {
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

inline void CR_OpCode64::operator=(const CR_OpCode64& oc) {
    Copy(oc);
}

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64 accessors

inline CR_Addr64Set& CR_OpCode64::FuncAddrs() {
    return m_funcaddrs;
}

inline CR_Addr64& CR_OpCode64::Addr() {
    return m_addr;
}

inline CR_String& CR_OpCode64::Name() {
    return m_name;
}

inline CR_OperandSet& CR_OpCode64::Operands() {
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

inline const CR_String& CR_OpCode64::Name() const {
    return m_name;
}

inline const CR_OperandSet& CR_OpCode64::Operands() const {
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

inline CR_String& CR_CodeFunc32::Name() {
    return m_name;
}

inline CR_FuncType& CR_CodeFunc32::FuncType() {
    return m_ft;
}

inline int& CR_CodeFunc32::SizeOfStackArgs() {
    return m_SizeOfStackArgs;
}

inline DWORD& CR_CodeFunc32::Flags() {
    return m_flags;
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

inline const CR_String& CR_CodeFunc32::Name() const {
    return m_name;
}

inline const CR_FuncType& CR_CodeFunc32::FuncType() const {
    return m_ft;
}

inline const int& CR_CodeFunc32::SizeOfStackArgs() const {
    return m_SizeOfStackArgs;
}

inline const DWORD& CR_CodeFunc32::Flags() const {
    return m_flags;
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

inline CR_String& CR_CodeFunc64::Name() {
    return m_name;
}

inline CR_FuncType& CR_CodeFunc64::FuncType() {
    return m_ft;
}

inline int& CR_CodeFunc64::SizeOfStackArgs() {
    return m_SizeOfStackArgs;
}

inline DWORD& CR_CodeFunc64::Flags() {
    return m_flags;
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

inline const CR_String& CR_CodeFunc64::Name() const {
    return m_name;
}

inline const CR_FuncType& CR_CodeFunc64::FuncType() const {
    return m_ft;
}

inline const int& CR_CodeFunc64::SizeOfStackArgs() const {
    return m_SizeOfStackArgs;
}

inline const DWORD& CR_CodeFunc64::Flags() const {
    return m_flags;
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

inline void CR_CodeFunc32::operator=(const CR_CodeFunc32& cf) {
    Copy(cf);
}

inline /*virtual*/ CR_CodeFunc32::~CR_CodeFunc32() { }

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64

inline CR_CodeFunc64::CR_CodeFunc64()
{
    clear();
}

inline CR_CodeFunc64::CR_CodeFunc64(const CR_CodeFunc64& cf)
{
    Copy(cf);
}

inline void CR_CodeFunc64::operator=(const CR_CodeFunc64& cf)
{
    Copy(cf);
}

inline /*virtual*/ CR_CodeFunc64::~CR_CodeFunc64()
{
}

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo32

inline CR_DisAsmInfo32::CR_DisAsmInfo32() { }

inline CR_DisAsmInfo32::CR_DisAsmInfo32(const CR_DisAsmInfo32& info) {
    Copy(info);
}

inline void CR_DisAsmInfo32::operator=(const CR_DisAsmInfo32& info) {
    Copy(info);
}

inline /*virtual*/ CR_DisAsmInfo32::~CR_DisAsmInfo32() { }

inline void CR_DisAsmInfo32::MapAddrToOpCode(CR_Addr32 addr, CR_OpCode32 *oc) {
    MapAddrToOpCode()[addr] = CR_SharedOpCode32(oc);
}

inline void
CR_DisAsmInfo32::MapAddrToCodeFunc(CR_Addr32 addr, CR_CodeFunc32* cf) {
    MapAddrToCodeFunc()[addr] = CR_SharedCodeFunc32(cf);
}

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo32 accessors

inline std::map<CR_Addr32, CR_SharedOpCode32>&
CR_DisAsmInfo32::MapAddrToOpCode() {
    return m_mAddrToOpCode;
}

inline CR_Addr32Set& CR_DisAsmInfo32::Entrances() {
    return m_sEntrances;
}

inline std::map<CR_Addr32, CR_SharedCodeFunc32>&
CR_DisAsmInfo32::MapAddrToCodeFunc() {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo32 const accessors

inline const std::map<CR_Addr32, CR_SharedOpCode32>&
CR_DisAsmInfo32::MapAddrToOpCode() const
{
    return m_mAddrToOpCode;
}

inline const CR_Addr32Set& CR_DisAsmInfo32::Entrances() const
{
    return m_sEntrances;
}

inline const std::map<CR_Addr32, CR_SharedCodeFunc32>&
CR_DisAsmInfo32::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo64

inline CR_DisAsmInfo64::CR_DisAsmInfo64() { }

inline CR_DisAsmInfo64::CR_DisAsmInfo64(const CR_DisAsmInfo64& info) {
    Copy(info);
}

inline void CR_DisAsmInfo64::operator=(const CR_DisAsmInfo64& info) {
    Copy(info);
}

inline /*virtual*/ CR_DisAsmInfo64::~CR_DisAsmInfo64() { }

inline void
CR_DisAsmInfo64::MapAddrToOpCode(CR_Addr64 addr, CR_OpCode64 *oc) {
    m_mAddrToOpCode[addr] = CR_SharedOpCode64(oc);
}

inline void
CR_DisAsmInfo64::MapAddrToCodeFunc(CR_Addr64 addr, CR_CodeFunc64 *cf) {
    m_mAddrToCodeFunc[addr] = CR_SharedCodeFunc64(cf);
}

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo64 accessors

inline std::map<CR_Addr64, CR_SharedOpCode64>&
CR_DisAsmInfo64::MapAddrToOpCode() {
    return m_mAddrToOpCode;
}

inline CR_Addr64Set& CR_DisAsmInfo64::Entrances() {
    return m_sEntrances;
}

inline std::map<CR_Addr64, CR_SharedCodeFunc64>&
CR_DisAsmInfo64::MapAddrToCodeFunc() {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo64 const accessors

inline const std::map<CR_Addr64, CR_SharedOpCode64>&
CR_DisAsmInfo64::MapAddrToOpCode() const {
    return m_mAddrToOpCode;
}

inline const CR_Addr64Set& CR_DisAsmInfo64::Entrances() const {
    return m_sEntrances;
}

inline const std::map<CR_Addr64, CR_SharedCodeFunc64>&
CR_DisAsmInfo64::MapAddrToCodeFunc() const {
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
