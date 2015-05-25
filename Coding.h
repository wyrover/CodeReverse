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
    cr_OCT_JMP,     // jump
    cr_OCT_JCC,     // conditional jump
    cr_OCT_CALL,    // call
    cr_OCT_LOOP,    // loop
    cr_OCT_RETURN,  // ret
    cr_OCT_STACKOP, // stack op
    cr_OCT_ARITHOP, // arithmetic op
    cr_OCT_SHIFT,   // shift
    cr_OCT_ROTATE,  // rotate
    cr_OCT_STROP,   // string op
    cr_OCT_MISC,    // misc
    cr_OCT_UNKNOWN  // unknown
};

////////////////////////////////////////////////////////////////////////////
// CR_DataFlags - the flags of data

typedef unsigned long CR_DataFlags;
static const CR_DataFlags
    cr_DF_REG           = 0x01,         // registry
    cr_DF_MEMREG        = 0x02,         // memory access by register
    cr_DF_MEMIMM        = 0x03,         // memory access by immediate
    cr_DF_MEMINDEX      = 0x04,         // memory access by index
    cr_DF_IMM           = 0x05,         // immediate
    cr_DF_IEXPR         = 0x06,         // intermediate expression
    cr_DF_CEXPR         = 0x07,         // C expression
    cr_DF_TYPEMASK      = 0x07,         // the mask bits of type
    cr_DF_ISIMMEDIATE   = (1 << 3),     // is an immediate value?
    cr_DF_ISINTEGER     = (1 << 4),     // is an integer?
    cr_DF_ISDATAPOINTER = (1 << 5),     // is a pointer to data?
    cr_DF_ISFUNCPOINTER = (1 << 6),     // is a pointer to a function?
    cr_DF_ISMAGIC       = (1 << 7),     // is a magic pointer?
    cr_DF_ISCONTINUOUS  = (1 << 8),     // is continuous to the next byte?
    cr_DF_ISREADONLY    = (1 << 9),     // is read-only?
    cr_DF_INPUTTED      = (1 << 10),    // is inputted?
    cr_DF_OUTPUTTED     = (1 << 11);    // is outputted?

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

    CR_DataFlags GetOperandType() const;
    void SetOperandType(CR_DataFlags flags);

    void ModifyFlags(CR_DataFlags add, CR_DataFlags remove);

public:
    void ParseText(int bits);
    void SetMemImm(CR_Addr64 addr);
    void SetImm32(CR_Addr32 val, BOOL is_signed);
    void SetImm64(CR_Addr64 val, BOOL is_signed);
    void SetExprAddrOnMemIndex();

public:
    // accessors
    std::string&            Text();
    std::string&            ExprAddr();
    std::string&            BaseReg();
    std::string&            IndexReg();
    std::string&            Seg();
    CR_DataFlags&           DataFlags();
    DWORD&                  Size();
    CR_Addr32&              Value32();
    CR_Addr64&              Value64();
    CR_Addr32&              Disp();
    char&                   Scale();
    CR_TypeID&              TypeID();
    std::string&            ExprValue();
    // const accessors
    const std::string&      Text() const;
    const std::string&      ExprAddr() const;
    const std::string&      BaseReg() const;
    const std::string&      IndexReg() const;
    const std::string&      Seg() const;
    const CR_DataFlags&     DataFlags() const;
    const DWORD&            Size() const;
    const CR_Addr32&        Value32() const;
    const CR_Addr64&        Value64() const;
    const CR_Addr32&        Disp() const;
    const char&             Scale() const;
    const CR_TypeID&        TypeID() const;
    const std::string&      ExprValue() const;

protected:
    std::string             m_text;             // text
    std::string             m_expr_addr;        // expressed address
    std::string             m_basereg;          // base register
    std::string             m_indexreg;         // index register
    std::string             m_seg;              // segment register
    CR_DataFlags            m_flags;            // operand flags
    DWORD                   m_size;             // size
    union {
        CR_Addr64           m_value64;          // 64-bit value
        CR_Addr32           m_value32;          // 32-bit value
    };
    CR_Addr32               m_disp;             // displacement
    char                    m_scale;            // scale
    CR_TypeID               m_type_id;          // type_id
    std::string             m_expr_value;       // expressed value
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
    void DeductOperandSizes();

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
    void DeductOperandSizes();

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
// CR_ICode32, CR_ICode64 --- intermediate codes

enum CR_ICodeType {
    cr_ICT_NONE,    // (none)
    cr_ICT_ASM,     // assembly
    cr_ICT_NEW,     // new ...
    cr_ICT_RENEW,   // renew ... as ...
    cr_ICT_COMMIT,  // commit ...
    cr_ICT_JOIN,    // join ... to ...
    cr_ICT_ACTION,  // (action) (param1),(param2),...
    cr_ICT_CONTROL, // if, else, return, ...
    cr_ICT_ATTR,    // name.attribute = ...
    cr_ICT_ASSERT   // assert(...)
};

struct CR_ICode32 {
    CR_ICode32();
    CR_ICode32(const CR_ICode32& ic);
    CR_ICode32& operator=(const CR_ICode32& ic);
    CR_ICode32(const CR_OpCode32& oc);
    CR_ICode32& operator=(const CR_OpCode32& oc);
    virtual ~CR_ICode32();
    bool is_asm() const;
    void clear();
protected:
    CR_ICodeType            m_ic_type;
    CR_OpCode32             m_oc;
    std::string             m_name;
    std::string             m_attr;
    std::vector<CR_Operand> m_params;
};

struct CR_ICode64 {
    CR_ICode64();
    CR_ICode64(const CR_ICode64& ic);
    CR_ICode64& operator=(const CR_ICode64& ic);
    CR_ICode64(const CR_OpCode64& oc);
    CR_ICode64& operator=(const CR_OpCode64& oc);
    virtual ~CR_ICode64();
    bool is_asm() const;
    void clear();
protected:
    CR_ICodeType            m_ic_type;
    CR_OpCode64             m_oc;
    std::string             m_name;
    std::string             m_attr;
    std::vector<CR_Operand> m_params;
};

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
// basic blocks

struct CR_BasicBlock32 {
    CR_Addr32                           m_addr;
    CR_Addr32                           m_next_addr;
    CR_Addr32                           m_jump_to;
    CR_CondCode                         m_cond_code;
    std::vector<CR_ICode32>             m_icodes;

    CR_BasicBlock32() :
        m_addr(cr_invalid_addr32),
        m_next_addr(cr_invalid_addr32),
        m_jump_to(cr_invalid_addr32),
        m_cond_code(C_NONE) { }
};

struct CR_BasicBlock64 {
    CR_Addr64                           m_addr;
    CR_Addr64                           m_next_addr;
    CR_Addr64                           m_jump_to;
    CR_CondCode                         m_cond_code;
    std::vector<CR_ICode64>             m_icodes;

    CR_BasicBlock64() :
        m_addr(cr_invalid_addr64),
        m_next_addr(cr_invalid_addr64),
        m_jump_to(cr_invalid_addr64),
        m_cond_code(C_NONE) { }
};

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
          CR_BasicBlock32 *BasicBlockFromAddr(CR_Addr32 addr);
    const CR_BasicBlock32 *BasicBlockFromAddr(CR_Addr32 addr) const;
public:
    // accessors
    CR_Addr32&                          Addr();
    std::string&                        Name();
    CR_FuncFlags&                       FuncFlags();
    CR_Range&                           StackArgSizeRange();
    CR_Addr32Set&                       Jumpees();
    CR_Addr32Set&                       Jumpers();
    CR_Addr32Set&                       Callees();
    CR_Addr32Set&                       Callers();
    CR_Addr32Set&                       Leaders();
    CR_Addr32Set&                       Exits();
    std::vector<CR_BasicBlock32>&       BasicBlocks();
    // const accessors
    const CR_Addr32&                    Addr() const;
    const std::string&                  Name() const;
    const CR_FuncFlags&                 FuncFlags() const;
    const CR_Range&                     StackArgSizeRange() const;
    const CR_Addr32Set&                 Jumpees() const;
    const CR_Addr32Set&                 Jumpers() const;
    const CR_Addr32Set&                 Callees() const;
    const CR_Addr32Set&                 Callers() const;
    const CR_Addr32Set&                 Leaders() const;
    const CR_Addr32Set&                 Exits() const;
    const std::vector<CR_BasicBlock32>& BasicBlocks() const;
protected:
    CR_Addr32                           m_addr;
    std::string                         m_name;
    CR_FuncFlags                        m_dwFuncFlags;
    CR_Range                            m_StackArgSizeRange;
    CR_Addr32Set                        m_jumpees;
    CR_Addr32Set                        m_jumpers;
    CR_Addr32Set                        m_callees;
    CR_Addr32Set                        m_callers;
    CR_Addr32Set                        m_leaders;
    CR_Addr32Set                        m_exits;
    std::vector<CR_BasicBlock32>        m_basic_blocks;
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
    CR_BasicBlock64 *BasicBlockFromAddr(CR_Addr64 addr);
    const CR_BasicBlock64 *BasicBlockFromAddr(CR_Addr64 addr) const;
public:
    // accessors
    CR_Addr64&                          Addr();
    std::string&                        Name();
    CR_FuncFlags&                       FuncFlags();
    CR_Range&                           StackArgSizeRange();
    CR_Addr64Set&                       Jumpees();
    CR_Addr64Set&                       Jumpers();
    CR_Addr64Set&                       Callees();
    CR_Addr64Set&                       Callers();
    CR_Addr64Set&                       Leaders();
    CR_Addr64Set&                       Exits();
    std::vector<CR_BasicBlock64>&       BasicBlocks();
    // const accessors
    const CR_Addr64&                    Addr() const;
    const std::string&                  Name() const;
    const CR_FuncFlags&                 FuncFlags() const;
    const CR_Range&                     StackArgSizeRange() const;
    const CR_Addr64Set&                 Jumpees() const;
    const CR_Addr64Set&                 Jumpers() const;
    const CR_Addr64Set&                 Callees() const;
    const CR_Addr64Set&                 Callers() const;
    const CR_Addr64Set&                 Leaders() const;
    const CR_Addr64Set&                 Exits() const;
    const std::vector<CR_BasicBlock64>& BasicBlocks() const;
protected:
    CR_Addr64                           m_addr;
    std::string                         m_name;
    CR_FuncFlags                        m_dwFuncFlags;
    CR_Range                            m_StackArgSizeRange;
    CR_Addr64Set                        m_jumpees;
    CR_Addr64Set                        m_jumpers;
    CR_Addr64Set                        m_callees;
    CR_Addr64Set                        m_callers;
    CR_Addr64Set                        m_leaders;
    CR_Addr64Set                        m_exits;
    std::vector<CR_BasicBlock64>        m_basic_blocks;
}; // class CR_CodeFunc64

typedef shared_ptr<CR_CodeFunc64> CR_ShdCodeFunc64;

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo32 - decompilation information for 32-bit

class CR_DecompInfo32 {
public:
    typedef std::map<CR_Addr32, CR_ShdOpCode32>     addr_to_shdopcode;
    typedef std::map<CR_Addr32, CR_ShdCodeFunc32>   addr_to_shdcodefunc;
public:
    CR_DecompInfo32();
    CR_DecompInfo32(const CR_DecompInfo32& info);
    CR_DecompInfo32& operator=(const CR_DecompInfo32& info);
    virtual ~CR_DecompInfo32();
    void clear();
    int GetFuncStage(CR_Addr32 func) const;

public:
    // accessors
    addr_to_shdopcode&              MapAddrToOpCode();
    CR_Addr32Set&                   Entrances();
    addr_to_shdcodefunc&            MapAddrToCodeFunc();
    CR_OpCode32 *                   OpCodeFromAddr(CR_Addr32 addr);
    CR_CodeFunc32 *                 CodeFuncFromAddr(CR_Addr32 addr);
    shared_ptr<CR_ErrorInfo>&       ErrorInfo();
    CR_NameScope&                   NameScope();
    // const accessors
    const addr_to_shdopcode&        MapAddrToOpCode() const;
    const CR_Addr32Set&             Entrances() const;
    const addr_to_shdcodefunc&      MapAddrToCodeFunc() const;
    const CR_OpCode32 *             OpCodeFromAddr(CR_Addr32 addr) const;
    const CR_CodeFunc32 *           CodeFuncFromAddr(CR_Addr32 addr) const;
    const shared_ptr<CR_ErrorInfo>& ErrorInfo() const;
    const CR_NameScope&             NameScope() const;

protected:
    // map virtual address to asm code
    addr_to_shdopcode               m_mAddrToOpCode;
    // entrances
    CR_Addr32Set                    m_sEntrances;
    // map addr to code function
    addr_to_shdcodefunc             m_mAddrToCodeFunc;
    // error info
    shared_ptr<CR_ErrorInfo>        m_error_info;
    // name scope
    CR_NameScope                    m_namescope;
};

////////////////////////////////////////////////////////////////////////////
// CR_DecompInfo64 - decompilation information for 64-bit

class CR_DecompInfo64 {
public:
    typedef std::map<CR_Addr64, CR_ShdOpCode64>     addr_to_shdopcode;
    typedef std::map<CR_Addr64, CR_ShdCodeFunc64>   addr_to_shdcodefunc;
public:
    CR_DecompInfo64();
    CR_DecompInfo64(const CR_DecompInfo64& info);
    CR_DecompInfo64& operator=(const CR_DecompInfo64& info);
    virtual ~CR_DecompInfo64();
    void clear();
    int GetFuncStage(CR_Addr64 func) const;

public:
    // accessors
    addr_to_shdopcode&              MapAddrToOpCode();
    CR_Addr64Set&                   Entrances();
    addr_to_shdcodefunc&            MapAddrToCodeFunc();
    CR_OpCode64 *                   OpCodeFromAddr(CR_Addr64 addr);
    CR_CodeFunc64 *                 CodeFuncFromAddr(CR_Addr64 addr);
    shared_ptr<CR_ErrorInfo>&       ErrorInfo();
    CR_NameScope&                   NameScope();
    // const accessors
    const addr_to_shdopcode&        MapAddrToOpCode() const;
    const CR_Addr64Set&             Entrances() const;
    const addr_to_shdcodefunc&      MapAddrToCodeFunc() const;
    const CR_OpCode64 *             OpCodeFromAddr(CR_Addr64 addr) const;
    const CR_CodeFunc64 *           CodeFuncFromAddr(CR_Addr64 addr) const;
    const shared_ptr<CR_ErrorInfo>& ErrorInfo() const;
    const CR_NameScope&             NameScope() const;

protected:
    // map virtual address to asm code
    addr_to_shdopcode               m_mAddrToOpCode;
    // entrances
    CR_Addr64Set                    m_sEntrances;
    // map addr to code function
    addr_to_shdcodefunc             m_mAddrToCodeFunc;
    // error info
    shared_ptr<CR_ErrorInfo>        m_error_info;
    // name scope
    CR_NameScope                    m_namescope;
};

////////////////////////////////////////////////////////////////////////////
// CR_X86_CPU -- x86 CPU

#ifdef __GNUC__
    #define CR_ANONYMOUS_STRUCT __extension__
#else
    #define CR_ANONYMOUS_STRUCT
#endif

#include <pshpack1.h>
typedef struct CR_X86_CPU {
    union {
        DWORDLONG   edx_eax;
        CR_ANONYMOUS_STRUCT struct {
            union {
                DWORD       eax;
                WORD        ax;
                CR_ANONYMOUS_STRUCT struct {
                    BYTE    al;
                    BYTE    ah;
                };
            };
            union {
                DWORD       edx;
                WORD        dx;
                CR_ANONYMOUS_STRUCT struct {
                    BYTE    dl;
                    BYTE    dh;
                };
            };
        };
    };
    union {
        DWORD       ebx;
        WORD        bx;
        CR_ANONYMOUS_STRUCT struct {
            BYTE    bl;
            BYTE    bh;
        };
    };
    union {
        DWORD       ecx;
        WORD        cx;
        CR_ANONYMOUS_STRUCT struct {
            BYTE    cl;
            BYTE    ch;
        };
    };
    union {
        DWORD       edi;
        WORD        di;
    };
    union {
        DWORD       esi;
        WORD        si;
    };
    union {
        DWORD       ebp;
        WORD        bp;
    };
    union {
        DWORD       esp;
        WORD        sp;
    };
    union {
        DWORD       eip;
        WORD        ip;
    };
    union {
        DWORD       eflags;
        WORD        flags;
    };
    union {
        WORD        segs[6];
        CR_ANONYMOUS_STRUCT struct {
            WORD    cs;
            WORD    ds;
            WORD    ss;
            WORD    es;
            WORD    fs;
            WORD    gs;
        };
    };
} CR_X86_CPU;
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////
// CR_X64_CPU -- x64 CPU

#include <pshpack1.h>
typedef struct CR_X64_CPU {
    union {
        DWORDLONG   rdx_rax;
        CR_ANONYMOUS_STRUCT struct {
            union {
                DWORDLONG   rax;
                DWORD       eax;
                WORD        ax;
                CR_ANONYMOUS_STRUCT struct {
                    BYTE    al;
                    BYTE    ah;
                };
            };
            union {
                DWORDLONG   rdx;
                DWORD       edx;
                WORD        dx;
                CR_ANONYMOUS_STRUCT struct {
                    BYTE    dl;
                    BYTE    dh;
                };
            };
        };
    };
    union {
        DWORDLONG   rbx;
        DWORD       ebx;
        WORD        bx;
        CR_ANONYMOUS_STRUCT struct {
            BYTE    bl;
            BYTE    bh;
        };
    };
    union {
        DWORDLONG   rcx;
        DWORD       ecx;
        WORD        cx;
        CR_ANONYMOUS_STRUCT struct {
            BYTE    cl;
            BYTE    ch;
        };
    };
    union {
        DWORDLONG   rdi;
        DWORD       edi;
        WORD        di;
        BYTE        dil;
    };
    union {
        DWORDLONG   rsi;
        DWORD       esi;
        WORD        si;
        BYTE        sil;
    };
    union {
        DWORDLONG   rbp;
        DWORD       ebp;
        WORD        bp;
        BYTE        bpl;
    };
    union {
        DWORDLONG   rsp;
        DWORD       esp;
        WORD        sp;
        BYTE        spl;
    };
    union {
        DWORDLONG   r8;
        DWORD       r8d;
        WORD        r8w;
        BYTE        r8l;
    };
    union {
        DWORDLONG   r9;
        DWORD       r9d;
        WORD        r9w;
        BYTE        r9l;
    };
    union {
        DWORDLONG   r10;
        DWORD       r10d;
        WORD        r10w;
        BYTE        r10l;
    };
    union {
        DWORDLONG   r11;
        DWORD       r11d;
        WORD        r11w;
        BYTE        r11l;
    };
    union {
        DWORDLONG   r12;
        DWORD       r12d;
        WORD        r12w;
        BYTE        r12l;
    };
    union {
        DWORDLONG   r13;
        DWORD       r13d;
        WORD        r13w;
        BYTE        r13l;
    };
    union {
        DWORDLONG   r14;
        DWORD       r14d;
        WORD        r14w;
        BYTE        r14l;
    };
    union {
        DWORDLONG   r15;
        DWORD       r15d;
        WORD        r15w;
        BYTE        r15l;
    };
    union {
        DWORDLONG   rip;
        DWORD       eip;
        WORD        ip;
    };
    union {
        DWORDLONG   rflags;
        DWORD       eflags;
        WORD        flags;
    };
    union {
        WORD        segs[6];
        CR_ANONYMOUS_STRUCT struct {
            WORD    cs;
            WORD    ds;
            WORD    ss;
            WORD    es;
            WORD    fs;
            WORD    gs;
        };
    };
} CR_X64_CPU;
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////
// CR_FPU_WORD, CR_QWORD, CR_DQWORD

#include <pshpack1.h>

// 80-bit data
typedef union CR_FPU_WORD {
    char        b[10];
    short       w[5];
    double      d;
    float       f;
} CR_FPU_WORD;

// 64-bit data
typedef union CR_QWORD {
    DWORDLONG   qw[1];
    double      d[1];
    DWORD       dw[2];
    float       f[2];
    WORD        w[4];
    BYTE        b[8];
} CR_QWORD;

// 128-bit data
typedef union CR_DQWORD {
    M128A       dqw[1];
    DWORDLONG   qw[2];
    double      d[2];
    DWORD       dw[4];
    float       f[4];
    WORD        w[8];
    BYTE        b[16];
} CR_DQWORD;

#include <poppack.h>

////////////////////////////////////////////////////////////////////////////
// CR_X87_FPU, CR_MMX, CR_XMM, CR_SSE

#include <pshpack1.h>

typedef struct CR_X87_FPU {
    union {
        CR_FPU_WORD     st[8];
        CR_ANONYMOUS_STRUCT struct {
            CR_FPU_WORD     st0;
            CR_FPU_WORD     st1;
            CR_FPU_WORD     st2;
            CR_FPU_WORD     st3;
            CR_FPU_WORD     st4;
            CR_FPU_WORD     st5;
            CR_FPU_WORD     st6;
            CR_FPU_WORD     st7;
        };
    };
    WORD            control;
    WORD            status;
    WORD            tag;
    DWORDLONG       instruction;
    DWORDLONG       operand;
} CR_X87_FPU;

typedef struct CR_MMX {
    CR_QWORD mm[8];
    CR_ANONYMOUS_STRUCT struct {
        CR_QWORD mm0;
        CR_QWORD mm1;
        CR_QWORD mm2;
        CR_QWORD mm3;
        CR_QWORD mm4;
        CR_QWORD mm5;
        CR_QWORD mm6;
        CR_QWORD mm7;
    };
} CR_MMX;

typedef struct CR_XMM {
    CR_DQWORD xmm[8];
    CR_ANONYMOUS_STRUCT struct {
        CR_DQWORD xmm0;
        CR_DQWORD xmm1;
        CR_DQWORD xmm2;
        CR_DQWORD xmm3;
        CR_DQWORD xmm4;
        CR_DQWORD xmm5;
        CR_DQWORD xmm6;
        CR_DQWORD xmm7;
    };
} CR_XMM;

typedef struct CR_SSE {
    CR_MMX      mmx;
    CR_XMM      xmm;
    DWORD       mxcsr;
} CR_SSE;

#include <poppack.h>

////////////////////////////////////////////////////////////////////////////
// CR_X86_CORE, CR_X64_CORE

#include <pshpack1.h>
typedef struct CR_X86_CORE {
    CR_X86_CPU cpu;
    CR_X87_FPU fpu;
    CR_SSE     sse;
} CR_X86_CORE;

typedef struct CR_X64_CORE {
    CR_X64_CPU cpu;
    CR_X87_FPU fpu;
    CR_SSE     sse;
} CR_X64_CORE;
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////

#include "Coding_inl.h"

#endif  // ndef CODING_H_
