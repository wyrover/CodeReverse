#ifndef CODING_H_
#define CODING_H_

////////////////////////////////////////////////////////////////////////////
// Coding.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

std::string Cr2Hex(unsigned char value);
std::string Cr4Hex(unsigned short value);
std::string Cr8Hex(unsigned long value);
std::string Cr16Hex(unsigned long long value);
std::string CrValue32(unsigned long value, BOOL is_signed);
std::string CrValue64(unsigned long long value, BOOL is_signed);

////////////////////////////////////////////////////////////////////////////
// CR_CondCode - condition code

enum CR_CondCode {
    C_A, C_AE, C_B, C_BE, C_C, C_E, C_G, C_GE, C_L, C_LE, C_NA, C_NAE,
    C_NB, C_NBE, C_NC, C_NE, C_NG, C_NGE, C_NL, C_NLE, C_NO, C_NP,
    C_NS, C_NZ, C_O, C_P, C_PE, C_PO, C_S, C_Z,
    C_NONE = -1
};

////////////////////////////////////////////////////////////////////////////
// CR_FuncFlags - function flags

typedef unsigned long CR_FuncFlags;
static const CR_FuncFlags
    cr_FF_UNKNOWN           = 0,    // unknown
    cr_FF_CDECL             = (1 << 1),   // __cdecl
    cr_FF_STDCALL           = (1 << 2),   // __stdcall
    cr_FF_FASTCALL          = (1 << 3),   // __fastcall
    cr_FF_THISCALL          = (1 << 4),   // thiscall
    cr_FF_64BITFUNC         = (1 << 5),   // 64-bit function
    cr_FF_JUMPERFUNC        = (1 << 6),   // jumper function
    cr_FF_FUNCINFUNC        = (1 << 7),   // function in function
    cr_FF_LEAFFUNC          = (1 << 8),   // leaf function
    cr_FF_RETURNONLY        = (1 << 9),   // return-only function
    cr_FF_NOTSTDCALL        = (1 << 10),  // not __stdcall
    cr_FF_INVALID           = (1 << 11),  // don't decompile but disasm
    cr_FF_IGNORE            = (1 << 12);  // ignore

////////////////////////////////////////////////////////////////////////////
// x86 registers

enum CR_RegType {
    cr_x86_CRREG = 0,
    cr_x86_DRREG,
    cr_x86_FPUREG,
    cr_x86_MMXREG,
    cr_x86_REG8,
    cr_x86_REG8X,
    cr_x86_REG16,
    cr_x86_REG32,
    cr_x86_REG64,
    cr_x86_SEGREG,
    cr_x86_XMMREG,
    cr_x86_YMMREG,
    cr_x86_COMPREG32,      // compound registry
    cr_x86_COMPREG64,      // compound registry
    cr_x86_COMPREG128,     // compound registry
    cr_x86_FLAG,           // flag
    cr_x86_REGNONE = -1
};

CR_RegType  CrRegGetType(const char *name, int bits);
DWORD       CrRegGetSize(const char *name, int bits);
BOOL        CrRegInReg(const char *reg1, const char *reg2);
BOOL        CrRegOverlapsReg(const char *reg1, const char *reg2);

////////////////////////////////////////////////////////////////////////////
// x86 flags

enum CR_FlagType {
    cr_x86_FLAG_NONE = 0,
    cr_x86_FLAG_CF = (1 << 0),     // carry flag
    cr_x86_FLAG_PF = (1 << 2),     // parity flag
    cr_x86_FLAG_AF = (1 << 4),     // auxiliary flag
    cr_x86_FLAG_ZF = (1 << 6),     // zero flag
    cr_x86_FLAG_SF = (1 << 7),     // sign flag
    cr_x86_FLAG_TF = (1 << 8),     // trap flag
    cr_x86_FLAG_IF = (1 << 9),     // interrupt enable flag
    cr_x86_FLAG_DF = (1 << 10),    // direction flag
    cr_x86_FLAG_OF = (1 << 11),    // overflow flag
};

struct CR_X86Flags {
    union {
        WORD flags;
        DWORD eflags;
        ULONGLONG rflags;
        struct {
            DWORD CF        : 1;    // carry flag
            DWORD ignore1   : 1;
            DWORD PF        : 1;    // parity flag
            DWORD ignore2   : 1;
            DWORD AF        : 1;    // auxiliary flag
            DWORD ignore3   : 1;
            DWORD ZF        : 1;    // zero flag
            DWORD SF        : 1;    // sign flag
            DWORD TF        : 1;    // trap flag
            DWORD IF        : 1;    // interrupt flag
            DWORD DF        : 1;    // direction flag
            DWORD OF        : 1;    // overflow flag
            DWORD ignore4   : 4;
            DWORD ignore5   : 16;
        } flag;
    };
};

CR_FlagType CrFlagGetType(const char *name, int bits);
const char * CrFlagGetName(CR_FlagType type, int bits);

////////////////////////////////////////////////////////////////////////////
// CR_OpCodeType - op.code type

enum CR_OpCodeType {
    cr_OCT_MISC,    // misc
    cr_OCT_JMP,     // jump
    cr_OCT_JCC,     // conditional jump
    cr_OCT_CALL,    // call
    cr_OCT_LOOP,    // loop
    cr_OCT_RETURN,  // ret
    cr_OCT_STACKOP, // stack operation
    cr_OCT_UNKNOWN  // unknown
};

////////////////////////////////////////////////////////////////////////////
// CR_OperandFlags - type of operand

typedef unsigned long CR_OperandFlags;
static const CR_OperandFlags
    cr_OF_REG          = (1 << 0),     // registry
    cr_OF_MEMREG       = (1 << 1),     // memory access by register
    cr_OF_MEMIMM       = (1 << 2),     // memory access by immediate
    cr_OF_MEMINDEX     = (1 << 4),     // memory access by index
    cr_OF_IMM          = (1 << 5),     // immediate
    cr_OF_TYPEMASK     = 0x3F,
    cr_OF_FUNCNAME     = (1 << 6);     // function name

////////////////////////////////////////////////////////////////////////////
// CR_Operand - operand

class CR_Operand {
public:
    CR_Operand();
    CR_Operand(const CR_Operand& opr);
    CR_Operand& operator=(const CR_Operand& opr);
    virtual ~CR_Operand();
    void Copy(const CR_Operand& opr);
    void clear();
    bool operator==(const CR_Operand& opr) const;
    bool operator!=(const CR_Operand& opr) const;
    CR_OperandFlags GetOperandType() const;
    void SetOperandType(CR_OperandFlags flags);

public:
    void SetFuncName(const char *name);
    void SetMemImm(CR_Addr64 addr);
    void SetImm32(CR_Addr32 val, BOOL is_signed);
    void SetImm64(CR_Addr64 val, BOOL is_signed);
    void ParseText(int bits);

public:
    // accessors
    std::string&            Text();
    std::string&            BaseReg();
    std::string&            IndexReg();
    std::string&            Seg();
    CR_OperandFlags&        OperandFlags();
    DWORD&                  Size();
    CR_Addr32&              Value32();
    CR_Addr64&              Value64();
    CR_Addr32&              Disp();
    char&                   Scale();
    // const accessors
    const std::string&      Text() const;
    const std::string&      BaseReg() const;
    const std::string&      IndexReg() const;
    const std::string&      Seg() const;
    const CR_OperandFlags&  OperandFlags() const;
    const DWORD&            Size() const;
    const CR_Addr32&        Value32() const;
    const CR_Addr64&        Value64() const;
    const CR_Addr32&        Disp() const;
    const char&             Scale() const;

protected:
    std::string             m_text;
    std::string             m_basereg;
    std::string             m_indexreg;
    std::string             m_seg;
    CR_OperandFlags         m_flags;
    DWORD                   m_size;
    union {
        CR_Addr64           m_value64;
        CR_Addr32           m_value32;
    };
    CR_Addr32               m_disp;
    char                    m_scale;
}; // class CR_Operand

////////////////////////////////////////////////////////////////////////////
// CR_Operands - set of operands

typedef CR_VecSet<CR_Operand> CR_Operands;

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32 - op.code for 32-bit mode

class CR_OpCode32 {
public:
    CR_OpCode32();
    CR_OpCode32(const CR_OpCode32& oc);
    CR_OpCode32& operator=(const CR_OpCode32& oc);
    virtual ~CR_OpCode32();
    void clear();

    void ParseText(const char *text);

public:
    // accessors
    CR_Addr32&                  Addr();         // address of assembly
    std::string&                Name();         // name of instruction
    CR_Operands&                Operands();     // operands
    CR_Operand*                 Operand(std::size_t index);
    CR_DataBytes&               Codes();        // code of instruction
    CR_OpCodeType&              OpCodeType();   // type of instruction
    CR_CondCode&                CondCode();     // condition type
    CR_Addr32Set&               FuncAddrs();

    // const accessors
    const CR_Addr32&            Addr() const;
    const std::string&          Name() const;
    const CR_Operands&          Operands() const;
    const CR_Operand*           Operand(std::size_t index) const;
    const CR_DataBytes&         Codes() const;
    const CR_OpCodeType&        OpCodeType() const;
    const CR_CondCode&          CondCode() const;
    const CR_Addr32Set&         FuncAddrs() const;

protected:
    CR_Addr32                   m_addr;
    std::string                 m_name;
    CR_Operands                 m_operands;
    CR_DataBytes                m_codes;
    CR_OpCodeType               m_oct;
    CR_CondCode                 m_ccode;
    CR_Addr32Set                m_funcaddrs;

    void Copy(const CR_OpCode32& oc);
}; // class CR_OpCode32

typedef shared_ptr<CR_OpCode32> CR_ShdOpCode32;

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64 - op.code for 64-bit mode

class CR_OpCode64 {
public:
    CR_OpCode64();
    CR_OpCode64(const CR_OpCode64& oc);
    CR_OpCode64& operator=(const CR_OpCode64& oc);
    virtual ~CR_OpCode64();
    void clear();

    void ParseText(const char *text);

public:
    // accessors
    CR_Addr64&                  Addr();         // address of assembly
    std::string&                Name();         // name of instruction
    CR_Operands&                Operands();     // operands
    CR_Operand*                 Operand(std::size_t index);
    CR_DataBytes&               Codes();        // code of instruction
    CR_OpCodeType&              OpCodeType();   // type of instruction
    CR_CondCode&                CondCode();     // condition type
    CR_Addr64Set&               FuncAddrs();

    // const accessors
    const CR_Addr64&            Addr() const;
    const std::string&          Name() const;
    const CR_Operands&          Operands() const;
    const CR_Operand*           Operand(std::size_t index) const;
    const CR_DataBytes&         Codes() const;
    const CR_OpCodeType&        OpCodeType() const;
    const CR_CondCode&          CondCode() const;
    const CR_Addr64Set&         FuncAddrs() const;

protected:
    CR_Addr64                   m_addr;
    std::string                 m_name;
    CR_Operands                 m_operands;
    CR_DataBytes                m_codes;
    CR_OpCodeType               m_oct;
    CR_CondCode                 m_ccode;
    CR_Addr64Set                m_funcaddrs;

    void Copy(const CR_OpCode64& oc);
}; // class CR_OpCode64

typedef shared_ptr<CR_OpCode64> CR_ShdOpCode64;

////////////////////////////////////////////////////////////////////////////
// CR_DataMemberEntry, CR_DataMemberEntries

struct CR_DataMemberEntry {
    std::size_t     m_index;
    std::string     m_name;
    CR_TypeID       m_typeid;
    std::size_t     m_size;
};

typedef CR_VecSet<CR_DataMemberEntry> CR_DataMemberEntries;

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 - code function for 32-bit

class CR_CodeFunc32 {
public:
    CR_CodeFunc32();
    CR_CodeFunc32(const CR_CodeFunc32& cf);
    CR_CodeFunc32& operator=(const CR_CodeFunc32& cf);
    virtual ~CR_CodeFunc32();
    void Copy(const CR_CodeFunc32& cf);
    void clear();
public:
    // accessors
    CR_Addr32&                          Addr();
    std::string&                        Name();
    CR_FuncFlags&                       FuncFlags();
    CR_Range&                           ArgSizeRange();
    CR_Addr32Set&                       Jumpees();
    CR_Addr32Set&                       Jumpers();
    CR_Addr32Set&                       Callees();
    CR_Addr32Set&                       Callers();
    // const accessors
    const CR_Addr32&                    Addr() const;
    const std::string&                  Name() const;
    const CR_FuncFlags&                 FuncFlags() const;
    const CR_Range&                     ArgSizeRange() const;
    const CR_Addr32Set&                 Jumpees() const;
    const CR_Addr32Set&                 Jumpers() const;
    const CR_Addr32Set&                 Callees() const;
    const CR_Addr32Set&                 Callers() const;
protected:
    CR_Addr32                           m_addr;
    std::string                         m_name;
    CR_FuncFlags                        m_dwFuncFlags;
    CR_Range                            m_ArgSizeRange;
    CR_Addr32Set                        m_jumpees;
    CR_Addr32Set                        m_jumpers;
    CR_Addr32Set                        m_callees;
    CR_Addr32Set                        m_callers;
}; // class CR_CodeFunc32

typedef shared_ptr<CR_CodeFunc32> CR_ShdCodeFunc32;

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 - code function for 64-bit

class CR_CodeFunc64 {
public:
    CR_CodeFunc64();
    CR_CodeFunc64(const CR_CodeFunc64& cf);
    CR_CodeFunc64& operator=(const CR_CodeFunc64& cf);
    virtual ~CR_CodeFunc64();
    void Copy(const CR_CodeFunc64& cf);
    void clear();
public:
    // accessors
    CR_Addr64&                          Addr();
    std::string&                        Name();
    CR_FuncFlags&                       FuncFlags();
    CR_Range&                           ArgSizeRange();
    CR_Addr64Set&                       Jumpees();
    CR_Addr64Set&                       Jumpers();
    CR_Addr64Set&                       Callees();
    CR_Addr64Set&                       Callers();
    // const accessors
    const CR_Addr64&                    Addr() const;
    const std::string&                  Name() const;
    const CR_FuncFlags&                 FuncFlags() const;
    const CR_Range&                     ArgSizeRange() const;
    const CR_Addr64Set&                 Jumpees() const;
    const CR_Addr64Set&                 Jumpers() const;
    const CR_Addr64Set&                 Callees() const;
    const CR_Addr64Set&                 Callers() const;
protected:
    CR_Addr64                           m_addr;
    std::string                         m_name;
    CR_FuncFlags                        m_dwFuncFlags;
    CR_Range                            m_ArgSizeRange;
    CR_Addr64Set                        m_jumpees;
    CR_Addr64Set                        m_jumpers;
    CR_Addr64Set                        m_callees;
    CR_Addr64Set                        m_callers;
}; // class CR_CodeFunc64

typedef shared_ptr<CR_CodeFunc64> CR_ShdCodeFunc64;

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32 - decompilation information for 32-bit

class CR_DecompInfo32 {
public:
    CR_DecompInfo32();
    CR_DecompInfo32(const CR_DecompInfo32& info);
    CR_DecompInfo32& operator=(const CR_DecompInfo32& info);
    virtual ~CR_DecompInfo32();
    void clear();

public:
    // accessors
    std::map<CR_Addr32, CR_ShdOpCode32>&         MapAddrToOpCode();
    CR_Addr32Set&                                Entrances();
    std::map<CR_Addr32, CR_ShdCodeFunc32>&       MapAddrToCodeFunc();
    CR_OpCode32 *                                OpCodeFromAddr(CR_Addr32 addr);
    CR_CodeFunc32 *                              CodeFuncFromAddr(CR_Addr32 addr);
    shared_ptr<CR_ErrorInfo>&                    ErrorInfo();
    CR_NameScope&                                NameScope();
    // const accessors
    const std::map<CR_Addr32, CR_ShdOpCode32>&   MapAddrToOpCode() const;
    const CR_Addr32Set&                          Entrances() const;
    const std::map<CR_Addr32, CR_ShdCodeFunc32>& MapAddrToCodeFunc() const;
    const CR_OpCode32 *                          OpCodeFromAddr(CR_Addr32 addr) const;
    const CR_CodeFunc32 *                        CodeFuncFromAddr(CR_Addr32 addr) const;
    const shared_ptr<CR_ErrorInfo>&              ErrorInfo() const;
    const CR_NameScope&                          NameScope() const;

protected:
    // map virtual address to asm code
    std::map<CR_Addr32, CR_ShdOpCode32>          m_mAddrToOpCode;
    // entrances
    CR_Addr32Set                                 m_sEntrances;
    // map addr to code function
    std::map<CR_Addr32, CR_ShdCodeFunc32>        m_mAddrToCodeFunc;
    // error info
    shared_ptr<CR_ErrorInfo>                     m_error_info;
    // name scope
    CR_NameScope                                 m_namescope;
};

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64 - decompilation information for 64-bit

class CR_DecompInfo64
{
public:
    CR_DecompInfo64();
    CR_DecompInfo64(const CR_DecompInfo64& info);
    CR_DecompInfo64& operator=(const CR_DecompInfo64& info);
    virtual ~CR_DecompInfo64();
    void clear();

public:
    // accessors
    std::map<CR_Addr64, CR_ShdOpCode64>&         MapAddrToOpCode();
    CR_Addr64Set&                                Entrances();
    std::map<CR_Addr64, CR_ShdCodeFunc64>&       MapAddrToCodeFunc();
    CR_OpCode64 *                                OpCodeFromAddr(CR_Addr64 addr);
    CR_CodeFunc64 *                              CodeFuncFromAddr(CR_Addr64 addr);
    shared_ptr<CR_ErrorInfo>&                    ErrorInfo();
    CR_NameScope&                                NameScope();
    // const accessors
    const std::map<CR_Addr64, CR_ShdOpCode64>&   MapAddrToOpCode() const;
    const CR_Addr64Set&                          Entrances() const;
    const std::map<CR_Addr64, CR_ShdCodeFunc64>& MapAddrToCodeFunc() const;
    const CR_OpCode64 *                          OpCodeFromAddr(CR_Addr64 addr) const;
    const CR_CodeFunc64 *                        CodeFuncFromAddr(CR_Addr64 addr) const;
    const shared_ptr<CR_ErrorInfo>&              ErrorInfo() const;
    const CR_NameScope&                          NameScope() const;

protected:
    // map virtual address to asm code
    std::map<CR_Addr64, CR_ShdOpCode64>          m_mAddrToOpCode;
    // entrances
    CR_Addr64Set                                 m_sEntrances;
    // map addr to code function
    std::map<CR_Addr64, CR_ShdCodeFunc64>        m_mAddrToCodeFunc;
    // error info
    shared_ptr<CR_ErrorInfo>                     m_error_info;
    // name scope
    CR_NameScope                                 m_namescope;
};

////////////////////////////////////////////////////////////////////////////

#include "Coding_inl.h"

#endif  // ndef CODING_H_
