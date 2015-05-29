////////////////////////////////////////////////////////////////////////////
// Coding.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

std::string Cr2Hex(unsigned char value) {
    char buf[32];
    sprintf(buf, "%02X", value);
    return buf;
}

std::string Cr4Hex(unsigned short value) {
    char buf[32];
    sprintf(buf, "%04X", value);
    return buf;
}

std::string Cr8Hex(unsigned long value) {
    char buf[32];
    sprintf(buf, "%08lX", value);
    return buf;
}

std::string Cr16Hex(unsigned long long value) {
    char buf[32];
    sprintf(buf, "%08lX%08lX", HILONG(value), LOLONG(value));
    return buf;
}

std::string CrValue32(unsigned long value, BOOL is_signed) {
    CHAR buf[64];

    if (is_signed) {
        sprintf(buf, "%ld", (LONG)value);
    } else {
        if (HIWORD(value) == 0) {
            if (HIBYTE(LOWORD(LOLONG(value))) == 0)
                sprintf(buf, "0x%02X", BYTE(value));
            else
                sprintf(buf, "0x%04X", LOWORD(value));
        } else {
            sprintf(buf, "0x%08lX", value);
        }
    }
    return buf;
} // CrValue32

std::string CrValue64(unsigned long long value, BOOL is_signed) {
    char buf[32];
    if (is_signed) {
        sprintf(buf, "%ld", LONG(LONGLONG(value)));
    } else if (HILONG(value) == 0) {
        if (HIWORD(LOLONG(value)) == 0) {
            if (HIBYTE(LOWORD(LOLONG(value))) == 0) {
                sprintf(buf, "0x%02X", BYTE(value));
            } else {
                sprintf(buf, "0x%04X", LOWORD(LOLONG(value)));
            }
        } else {
            sprintf(buf, "0x%08lX", LOLONG(value));
        }
    } else {
        sprintf(buf, "0x%08lX%08lX", HILONG(value), LOLONG(value));
    }
    return buf;
} // CrValue64

////////////////////////////////////////////////////////////////////////////
// x86 flags

CR_FlagType CrFlagGetType(const char *name, int bits) {
    if (name[0] != '\0' && name[1] == 'F' && name[2] == '\0') {
        switch (name[0]) {
        case 'C': return cr_x86_FLAG_CF;
        case 'P': return cr_x86_FLAG_PF;
        case 'A': return cr_x86_FLAG_AF;
        case 'Z': return cr_x86_FLAG_ZF;
        case 'S': return cr_x86_FLAG_SF;
        case 'T': return cr_x86_FLAG_TF;
        case 'I': return cr_x86_FLAG_IF;
        case 'D': return cr_x86_FLAG_DF;
        case 'O': return cr_x86_FLAG_OF;
        }
    }
    return cr_x86_FLAG_NONE;
}

const char *CrFlagGetName(CR_FlagType type, int bits) {
    switch (type) {
    case cr_x86_FLAG_CF: return "CF";
    case cr_x86_FLAG_PF: return "PF";
    case cr_x86_FLAG_AF: return "AF";
    case cr_x86_FLAG_ZF: return "ZF";
    case cr_x86_FLAG_SF: return "SF";
    case cr_x86_FLAG_TF: return "TF";
    case cr_x86_FLAG_IF: return "IF";
    case cr_x86_FLAG_DF: return "DF";
    case cr_x86_FLAG_OF: return "OF";
    default: break;
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// x86 registers

struct CR_X86RegInfo {
    const char *name;
    CR_RegType  type;
    int         bits;
};

static const CR_X86RegInfo cr_reg_entries[] = {
    {"cr0", cr_x86_CRREG, 0},
    {"cr1", cr_x86_CRREG, 0},
    {"cr2", cr_x86_CRREG, 0},
    {"cr3", cr_x86_CRREG, 0},
    {"cr4", cr_x86_CRREG, 0},
    {"cr8", cr_x86_CRREG, 64},
    {"dr0", cr_x86_DRREG, 0},
    {"dr1", cr_x86_DRREG, 0},
    {"dr2", cr_x86_DRREG, 0},
    {"dr3", cr_x86_DRREG, 0},
    {"dr4", cr_x86_DRREG, 0},
    {"dr5", cr_x86_DRREG, 0},
    {"dr6", cr_x86_DRREG, 0},
    {"dr7", cr_x86_DRREG, 0},
    {"st0", cr_x86_FPUREG, 0},
    {"st1", cr_x86_FPUREG, 0},
    {"st2", cr_x86_FPUREG, 0},
    {"st3", cr_x86_FPUREG, 0},
    {"st4", cr_x86_FPUREG, 0},
    {"st5", cr_x86_FPUREG, 0},
    {"st6", cr_x86_FPUREG, 0},
    {"st7", cr_x86_FPUREG, 0},
    {"mm0", cr_x86_MMXREG, 0},
    {"mm1", cr_x86_MMXREG, 0},
    {"mm2", cr_x86_MMXREG, 0},
    {"mm3", cr_x86_MMXREG, 0},
    {"mm4", cr_x86_MMXREG, 0},
    {"mm5", cr_x86_MMXREG, 0},
    {"mm6", cr_x86_MMXREG, 0},
    {"mm7", cr_x86_MMXREG, 0},
    {"xmm0", cr_x86_XMMREG, 0},
    {"xmm1", cr_x86_XMMREG, 0},
    {"xmm2", cr_x86_XMMREG, 0},
    {"xmm3", cr_x86_XMMREG, 0},
    {"xmm4", cr_x86_XMMREG, 0},
    {"xmm5", cr_x86_XMMREG, 0},
    {"xmm6", cr_x86_XMMREG, 0},
    {"xmm7", cr_x86_XMMREG, 0},
    {"xmm8", cr_x86_XMMREG, 64},
    {"xmm9", cr_x86_XMMREG, 64},
    {"xmm10", cr_x86_XMMREG, 64},
    {"xmm11", cr_x86_XMMREG, 64},
    {"xmm12", cr_x86_XMMREG, 64},
    {"xmm13", cr_x86_XMMREG, 64},
    {"xmm14", cr_x86_XMMREG, 64},
    {"xmm15", cr_x86_XMMREG, 64},
    {"ymm0", cr_x86_YMMREG, 0},
    {"ymm1", cr_x86_YMMREG, 0},
    {"ymm2", cr_x86_YMMREG, 0},
    {"ymm3", cr_x86_YMMREG, 0},
    {"ymm4", cr_x86_YMMREG, 0},
    {"ymm5", cr_x86_YMMREG, 0},
    {"ymm6", cr_x86_YMMREG, 0},
    {"ymm7", cr_x86_YMMREG, 0},
    {"ymm8", cr_x86_YMMREG, 64},
    {"ymm9", cr_x86_YMMREG, 64},
    {"ymm10", cr_x86_YMMREG, 64},
    {"ymm11", cr_x86_YMMREG, 64},
    {"ymm12", cr_x86_YMMREG, 64},
    {"ymm13", cr_x86_YMMREG, 64},
    {"ymm14", cr_x86_YMMREG, 64},
    {"ymm15", cr_x86_YMMREG, 64},
    {"rax", cr_x86_REG64, 64},
    {"rcx", cr_x86_REG64, 64},
    {"rdx", cr_x86_REG64, 64},
    {"rbx", cr_x86_REG64, 64},
    {"rsp", cr_x86_REG64, 64},
    {"rbp", cr_x86_REG64, 64},
    {"rsi", cr_x86_REG64, 64},
    {"rdi", cr_x86_REG64, 64},
    {"r8", cr_x86_REG64, 64},
    {"r9", cr_x86_REG64, 64},
    {"r10", cr_x86_REG64, 64},
    {"r11", cr_x86_REG64, 64},
    {"r12", cr_x86_REG64, 64},
    {"r13", cr_x86_REG64, 64},
    {"r14", cr_x86_REG64, 64},
    {"r15", cr_x86_REG64, 64},
    {"eax", cr_x86_REG32, 32},
    {"ecx", cr_x86_REG32, 32},
    {"edx", cr_x86_REG32, 32},
    {"ebx", cr_x86_REG32, 32},
    {"esp", cr_x86_REG32, 32},
    {"ebp", cr_x86_REG32, 32},
    {"esi", cr_x86_REG32, 32},
    {"edi", cr_x86_REG32, 32},
    {"r8d", cr_x86_REG32, 64},
    {"r9d", cr_x86_REG32, 64},
    {"r10d", cr_x86_REG32, 64},
    {"r11d", cr_x86_REG32, 64},
    {"r12d", cr_x86_REG32, 64},
    {"r13d", cr_x86_REG32, 64},
    {"r14d", cr_x86_REG32, 64},
    {"r15d", cr_x86_REG32, 64},
    {"ax", cr_x86_REG16, 0},
    {"cx", cr_x86_REG16, 0},
    {"dx", cr_x86_REG16, 0},
    {"bx", cr_x86_REG16, 0},
    {"sp", cr_x86_REG16, 0},
    {"bp", cr_x86_REG16, 0},
    {"si", cr_x86_REG16, 0},
    {"di", cr_x86_REG16, 0},
    {"r8w", cr_x86_REG16, 64},
    {"r9w", cr_x86_REG16, 64},
    {"r10w", cr_x86_REG16, 64},
    {"r11w", cr_x86_REG16, 64},
    {"r12w", cr_x86_REG16, 64},
    {"r13w", cr_x86_REG16, 64},
    {"r14w", cr_x86_REG16, 64},
    {"r15w", cr_x86_REG16, 64},
    {"al", cr_x86_REG8, 0},
    {"cl", cr_x86_REG8, 0},
    {"dl", cr_x86_REG8, 0},
    {"bl", cr_x86_REG8, 0},
    {"ah", cr_x86_REG8, 0},
    {"ch", cr_x86_REG8, 0},
    {"dh", cr_x86_REG8, 0},
    {"bh", cr_x86_REG8, 0},
    {"r8b", cr_x86_REG8, 64},
    {"r9b", cr_x86_REG8, 64},
    {"r10b", cr_x86_REG8, 64},
    {"r11b", cr_x86_REG8, 64},
    {"r12b", cr_x86_REG8, 64},
    {"r13b", cr_x86_REG8, 64},
    {"r14b", cr_x86_REG8, 64},
    {"r15b", cr_x86_REG8, 64},
    {"spl", cr_x86_REG8X, 64},
    {"bpl", cr_x86_REG8X, 64},
    {"sil", cr_x86_REG8X, 64},
    {"dil", cr_x86_REG8X, 64},
    {"ip", cr_x86_REG16, 0},
    {"eip", cr_x86_REG32, 32},
    {"rip", cr_x86_REG64, 64},
    {"es", cr_x86_SEGREG, 0},
    {"cs", cr_x86_SEGREG, 0},
    {"ss", cr_x86_SEGREG, 0},
    {"ds", cr_x86_SEGREG, 0},
    {"fs", cr_x86_SEGREG, 32},
    {"gs", cr_x86_SEGREG, 32},
    {"dx:ax", cr_x86_COMPREG32, 0},
    {"edx:eax", cr_x86_COMPREG64, 32},
    {"rdx:rax", cr_x86_COMPREG128, 64},
    {"CF", cr_x86_FLAG, 0},
    {"PF", cr_x86_FLAG, 0},
    {"AF", cr_x86_FLAG, 0},
    {"ZF", cr_x86_FLAG, 0},
    {"SF", cr_x86_FLAG, 0},
    {"TF", cr_x86_FLAG, 0},
    {"IF", cr_x86_FLAG, 0},
    {"DF", cr_x86_FLAG, 0},
    {"OF", cr_x86_FLAG, 0},
    {"SFeqOF", cr_x86_FLAG, 0}  // extension (means SF == OF)
};

CR_RegType CrRegGetType(const char *name, int bits) {
    for (auto& entry : cr_reg_entries) {
        if (bits >= entry.bits && _stricmp(entry.name, name) == 0) {
            return entry.type;
        }
    }
    if (*name == '$') {
        ++name;
        while (isdigit(*name)) {
            ++name;
        }
        if (*name == 0) {
            return cr_x86_PARAM;
        }
        if (name[1] == 0) {
            if (*name == 'N') {
                return cr_x86_PARAMNUM;
            }
            if (*name == 'R') {
                return cr_x86_PARAMREG;
            }
            if (*name == 'M') {
                return cr_x86_PARAMMEM;
            }
        }
    }
    return cr_x86_REGNONE;
}

DWORD CrRegGetSize(CR_RegType type, int bits) {
    switch (type) {
    case cr_x86_CRREG:
        if (bits == 64)
            return 64 / 8;
        else if (bits == 32)
            return 32 / 8;
        break;
    case cr_x86_DRREG:         return 32 / 8;
    case cr_x86_FPUREG:        return 80 / 8;
    case cr_x86_MMXREG:        return 64 / 8;
    case cr_x86_REG8:          return 8 / 8;
    case cr_x86_REG8X:         return 8 / 8;
    case cr_x86_REG16:         return 16 / 8;
    case cr_x86_REG32:         return 32 / 8;
    case cr_x86_REG64:         return 64 / 8;
    case cr_x86_SEGREG:        return 32 / 8;
    case cr_x86_XMMREG:        return 128 / 8;
    case cr_x86_YMMREG:        return 256 / 8;
    case cr_x86_COMPREG32:     return 32 / 8;
    case cr_x86_COMPREG64:     return 64 / 8;
    case cr_x86_COMPREG128:    return 128 / 8;
    default:
        ;
    }
    return 0;
}

DWORD CrRegGetSize(const char *name, int bits) {
    return CrRegGetSize(CrRegGetType(name, bits), bits);
}

BOOL CrRegInReg(const char *reg1, const char *reg2) {
    if (std::strcmp(reg1, reg2) == 0)
        return TRUE;

    static const char *s[][4] = {
        {"al", "ax", "eax", "rax"},
        {"bl", "bx", "ebx", "rbx"},
        {"cl", "cx", "ecx", "rcx"},
        {"dl", "dx", "edx", "rdx"},
        {"ah", "ax", "eax", "rax"},
        {"bh", "bx", "ebx", "rbx"},
        {"ch", "cx", "ecx", "rcx"},
        {"dh", "dx", "edx", "rdx"},
        {"spl", "sp", "esp", "rsp"},
        {"bpl", "bp", "ebp", "rbp"},
        {"sil", "si", "esi", "rsi"},
        {"dil", "di", "edi", "rdi"},
        {"ax", "dx:ax", "edx:eax", "rdx:rax"},
        {"dx", "dx:ax", "edx:eax", "rdx:rax"},
        {"eax", "edx:eax", "rdx:rax", NULL},
        {"edx", "edx:eax", "rdx:rax", NULL},
        {"rax", "rdx:rax", NULL, NULL},
        {"rdx", "rdx:rax", NULL, NULL},
        {"ip", "eip", "rip", NULL},
        {"r8b", "r8w", "r8d", "r8"},
        {"r9b", "r9w", "r9d", "r9"},
        {"r10b", "r10w", "r10d", "r10"},
        {"r11b", "r11w", "r11d", "r11"},
        {"r12b", "r12w", "r12d", "r12"},
        {"r13b", "r13w", "r13d", "r13"},
        {"r14b", "r14w", "r14d", "r14"},
        {"r15b", "r15w", "r15d", "r15"},
    };

    for (auto& entry : s) {
        if (std::strcmp(reg1, entry[0]) == 0) {
            if ((entry[1] && std::strcmp(reg2, entry[1]) == 0) ||
                (entry[2] && std::strcmp(reg2, entry[2]) == 0) ||
                (entry[3] && std::strcmp(reg2, entry[3]) == 0))
            {
                return TRUE;
            }
        }
        if (std::strcmp(reg1, entry[1]) == 0) {
            if ((entry[2] && std::strcmp(reg2, entry[2]) == 0) ||
                (entry[3] && std::strcmp(reg2, entry[3]) == 0))
            {
                return TRUE;
            }
        }
        if (std::strcmp(reg1, entry[2]) == 0) {
            if (entry[3] && std::strcmp(reg2, entry[3]) == 0)
                return TRUE;
        }
    }

    return FALSE;
}

BOOL CrRegOverlapsReg(const char *reg1, const char *reg2) {
    return CrRegInReg(reg1, reg2) || CrRegInReg(reg2, reg1);
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand

void CR_Operand::Copy(const CR_Operand& opr) {
    Text() = opr.Text();
    ExprAddr() = opr.ExprAddr();
    BaseReg() = opr.BaseReg();
    IndexReg() = opr.IndexReg();
    Seg() = opr.Seg();
    DataFlags() = opr.DataFlags();
    Size() = opr.Size();
    Value64() = opr.Value64();
    Disp() = opr.Disp();
    Scale() = opr.Scale();
    TypeID() = opr.TypeID();
    ExprValue() = opr.ExprValue();
}

void CR_Operand::clear() {
    Text().clear();
    ExprAddr().clear();
    BaseReg().clear();
    IndexReg().clear();
    Seg().clear();
    DataFlags() = 0;
    Size() = 0;
    Value64() = 0;
    Disp().clear();
    Scale() = 0;
    TypeID() = cr_invalid_id;
    ExprValue().clear();
}

void CR_Operand::SetImm32(CR_Addr32 val, BOOL is_signed) {
    Text() = CrValue32(val, is_signed);
    ExprAddr().clear();
    SetOperandType(cr_DF_IMM);
    Value64() = val;
}

void CR_Operand::SetImm64(CR_Addr64 val, BOOL is_signed) {
    Text() = CrValue64(val, is_signed);
    ExprAddr().clear();
    SetOperandType(cr_DF_IMM);
    Value64() = val;
}

void CR_Operand::SetExprAddrOnMemIndex() {
    std::string expr;
    if (BaseReg().size() && IndexReg().size()) {
        if (BaseReg() == IndexReg()) {
            BaseReg().clear();
            Scale() += 1;
        }
    }
    if (BaseReg().size()) {
        expr += BaseReg();
    }
    if (IndexReg().size() && Scale() != 0) {
        if (BaseReg().size()) {
            expr += "+";
        }
        expr += IndexReg();
        if (Scale() != 1) {
            expr += "*";
            expr += std::to_string(Scale());
        }
    }
    if (Disp().size() && Disp() != "0") {
        if (Disp()[0] == '-') {
            expr += Disp();
        } else {
            expr += "+";
            expr += Disp();
        }
    }
    ExprAddr() = expr;
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand::ParseText

void CR_Operand::ParseText(const char *text, int bits) {
    clear();
    Text() = text;

    char buf[64];
    strcpy(buf, text);
    char *p = buf;

    // a register or a parameter?
    CR_RegType type = CrRegGetType(p, bits);
    if (type != cr_x86_REGNONE) {
        DWORD size = CrRegGetSize(type, bits);
        if (size != 0) {
            BaseReg() = p;
            ExprAddr().clear();
            SetOperandType(cr_DF_REG);
            Size() = size;
            return;
        }
        switch (type) {
        case cr_x86_PARAM:
            BaseReg() = p;
            SetOperandType(cr_DF_PARAM);
            return;
        case cr_x86_PARAMNUM:
            SetOperandType(cr_DF_PARAMNUM);
            return;
        case cr_x86_PARAMREG:
            BaseReg() = p;
            SetOperandType(cr_DF_PARAMREG);
            return;
        case cr_x86_PARAMMEM:
            SetOperandType(cr_DF_PARAMMEM);
            return;
        default:
            break;
        }
    }

    // size spec
    if (strncmp(p, "byte ", 5) == 0) {
        p += 5;
        Size() = 1;
    } else if (strncmp(p, "word ", 5) == 0) {
        p += 5;
        Size() = 2;
    } else if (strncmp(p, "dword ", 6) == 0) {
        p += 6;
        Size() = 4;
    } else if (strncmp(p, "qword ", 6) == 0) {
        p += 6;
        Size() = 8;
    } else if (strncmp(p, "tword ", 6) == 0) {
        p += 6;
        Size() = 10;
    } else if (strncmp(p, "oword ", 6) == 0) {
        p += 6;
        Size() = 16;
    } else if (strncmp(p, "yword ", 6) == 0) {
        p += 6;
        Size() = 32;
    } else if (strncmp(p, "short ", 6) == 0) {
        p += 6;
        Size() = 1;
    } else if (strncmp(p, "near ", 5) == 0) {
        p += 5;
        Size() = 2;
    }

    // near or far
    if (strncmp(p, "near ", 5) == 0) {
        p += 5;
    } else if (strncmp(p, "far ", 4) == 0) {
        p += 4;
    }

    // an immediate?
    if (p[0] == '+' || p[0] == '-') {
        long long value = std::strtoll(p, NULL, 0);
        SetImm64(value, true);
        return;
    }
    if (isdigit(p[0])) {
        unsigned long long value = std::strtoull(p, NULL, 0);
        SetImm64(value, false);
        return;
    }

    // memory addressing?
    if (p[0] == '[') {
        ++p;
        *strchr(p, ']') = '\0';

        // is there segment register in addressing?
        char *q = strchr(p, ':');
        if (q) {
            *q++ = 0;
            Seg() = p;
            p = q;
        }

        if (strncmp(p, "word ", 5) == 0) {
            p += 5;
        } else if (strncmp(p, "dword ", 6) == 0) {
            p += 6;
        } else if (strncmp(p, "qword ", 6) == 0) {
            p += 6;
        }

        if (strncmp(p, "rel ", 4) == 0) {
            p += 4;
        }

        // a register or a parameter for addressing?
        CR_RegType type = CrRegGetType(p, bits);
        if (type != cr_x86_REGNONE) {
            DWORD size = CrRegGetSize(type, bits);
            if (size) {
                BaseReg() = p;
                SetOperandType(cr_DF_MEMREG);
                ExprAddr() = "&" + BaseReg();
                return;
            }
            switch (type) {
            case cr_x86_PARAM:
                assert(0);
                return;
            case cr_x86_PARAMNUM:
                // [$1N]
                BaseReg().clear();
                SetOperandType(cr_DF_MEMIMMPARAM);
                ExprAddr() = p;
                return;
            case cr_x86_PARAMREG:
                // [$1R]
                BaseReg() = p;
                SetOperandType(cr_DF_MEMREGPARAM);
                ExprAddr() = BaseReg();
                return;
            case cr_x86_PARAMMEM:
                assert(0);
                return;
            default:
                break;
            }
        }

        // find '+' or '-'
        bool minus1 = false;
        q = p + strcspn(p, "+-");
        if (*q == 0) {
            if (isdigit(*p)) {
                // an immediate for addressing
                CR_Addr64 addr = std::strtoull(p, NULL, 0);
                Value64() = addr;
                SetOperandType(cr_DF_MEMIMM);
                ExprAddr() = std::to_string(addr);
            } else {
                #if 0
                    fprintf(stderr, "%s\n", Text().c_str());
                #endif
                assert(0);
            }
            return;
        } else {
            minus1 = (*q == '-');
        }
        *q++ = 0;

        // find '*'
        char *r = strchr(p, '*');
        if (r) {
            *r++ = 0;
            BaseReg().clear();
            IndexReg() = p;
            if (*p == '$') {
                // $1*4+0x402800
                SetOperandType(cr_DF_MEMINDEXPARAM);
            } else {
                // eax*4+0x1e
                // eax*4+0x4
                // ebx*4+0x402800
                Scale() = char(strtol(r, NULL, 0));
                if (minus1) {
                    Disp() = std::to_string(-strtol(q, NULL, 0));
                } else {
                    Disp() = std::to_string(strtol(q, NULL, 0));
                }
                SetOperandType(cr_DF_MEMINDEX);
            }
            SetExprAddrOnMemIndex();
            return;
        }

        // find '+' or '-'
        bool minus2 = false;
        r = q + strcspn(q, "+-");
        if (*r == 0) {
            char *s = strchr(q, '*');
            if (s) {
                // eax+ebx*2
                *s++ = 0;
                BaseReg() = p;
                IndexReg() = q;
                Scale() = char(strtol(s, NULL, 0));
                Disp() = "0";
                if (*p == '$') {
                    // $1+ebx+2
                    SetOperandType(cr_DF_MEMINDEXPARAM);
                    if (BaseReg() == IndexReg()) {
                        // $1+$1*2
                        BaseReg().clear();
                        Scale() += 1;
                    }
                } else {
                    // eax+ebx+2
                    SetOperandType(cr_DF_MEMINDEX);
                    if (BaseReg() == IndexReg()) {
                        // ebx+ebx*2
                        BaseReg().clear();
                        Scale() += 1;
                    }
                }
                SetExprAddrOnMemIndex();
                return;
            } else {
                if (isdigit(*q)) {
                    // esp+0x1f
                    BaseReg() = p;
                    IndexReg().clear();
                    Scale() = 0;
                    if (minus1) {
                        Disp() = std::to_string(-strtol(q, NULL, 0));
                    } else {
                        Disp() = std::to_string(strtol(q, NULL, 0));
                    }
                    SetOperandType(cr_DF_MEMINDEX);
                } else if (*q == '$') {
                    // esp-$1
                    // $1+$2
                    BaseReg() = p;
                    IndexReg().clear();
                    Scale() = 0;
                    if (minus1) {
                        Disp() = "-";
                        Disp() += q;
                    } else {
                        Disp() = q;
                    }
                    SetOperandType(cr_DF_MEMINDEXPARAM);
                } else {
                    // esi+eax
                    BaseReg() = p;
                    IndexReg() = q;
                    Scale() = 1;
                    Disp() = "0";
                    SetOperandType(cr_DF_MEMINDEX);
                    if (BaseReg() == IndexReg()) {
                        BaseReg().clear();
                        Scale() = 2;
                    }
                }
                SetExprAddrOnMemIndex();
                return;
            }
        } else {
            minus2 = (*r == '-');
            *r++ = 0;
            char *s = strchr(q, '*');
            if (s) {
                // rbp+rax*4+0x0
                *s++ = 0;
                BaseReg() = p;
                IndexReg() = q;
                Scale() = char(strtol(s, NULL, 0));
                if (minus2) {
                    Disp() = std::to_string(-strtol(r, NULL, 0));
                } else {
                    Disp() = std::to_string(strtol(r, NULL, 0));
                }
                SetOperandType(cr_DF_MEMINDEX);
                if (BaseReg() == IndexReg()) {
                    BaseReg().clear();
                    Scale() += 1;
                }
            } else {
                // rbp+rax+0x0
                BaseReg() = p;
                IndexReg() = q;
                Scale() = 1;
                if (minus2) {
                    Disp() = std::to_string(-strtol(r, NULL, 0));
                } else {
                    Disp() = std::to_string(strtol(r, NULL, 0));
                }
                SetOperandType(cr_DF_MEMINDEX);
                if (BaseReg() == IndexReg()) {
                    BaseReg().clear();
                    Scale() += 1;
                }
            }
            SetExprAddrOnMemIndex();
            return;
        }
    }
    #ifdef _DEBUG
        fprintf(stderr, "ERROR for Operand %s\n", Text().c_str());
    #endif
    assert(0);
} // CR_Operand::ParseText

////////////////////////////////////////////////////////////////////////////
// cr_rep_insns, cr_ccentries

static const char * const cr_rep_insns[] = {
    "rep insb", "rep insw", "rep insd",
    "rep movsb", "rep movsw", "rep movsd", "rep movsq",
    "rep outsb", "rep outsw", "rep outsd",
    "rep stosb", "rep stosw", "rep stosd", "rep stosq",
    "rep lodsb", "rep lodsw", "rep lodsd", "rep lodsq",
    "repe cmpsb", "repe cmpsw", "repe cmpsd", "repe cmpsq",
    "repe scasb", "repe scasw", "repe scasd", "repe scasq",
    "repne cmpsb", "repne cmpsw", "repne cmpsd", "repne cmpsq",
    "repne scasb", "repne scasw", "repne scasd", "repne scasq",
};

struct CR_CCEntry {
    const char *name;
    CR_CondCode cc;
};

static const CR_CCEntry cr_ccentries[] = {
    { "call", C_NONE },

    { "loop", C_NONE },
    { "loope", C_E },
    { "loopne", C_NE },

    { "jmp", C_NONE },

    { "ja", C_A },
    { "jae", C_AE },
    { "jb", C_B },
    { "jbe", C_BE },
    { "jc", C_C },
    { "je", C_E },
    { "jg", C_G },
    { "jge", C_GE },
    { "jl", C_L },
    { "jle", C_LE },
    { "jna", C_NA },
    { "jnae", C_NAE },
    { "jnb", C_NB },
    { "jnbe", C_NBE },
    { "jnc", C_NC },
    { "jne", C_NE },
    { "jng", C_NG },
    { "jnge", C_NGE },
    { "jnl", C_NL },
    { "jnle", C_NLE },
    { "jno", C_NO },
    { "jnp", C_NP },
    { "jns", C_NS },
    { "jnz", C_NZ },
    { "jo", C_O },
    { "jp", C_P },
    { "jpe", C_PE },
    { "jpo", C_PO },
    { "js", C_S },
    { "jz", C_Z },
}; // const CR_CCEntry cr_ccentries[]

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32

void CR_OpCode32::Copy(const CR_OpCode32& oc) {
    FuncAddrs() = oc.FuncAddrs();
    Addr() = oc.Addr();
    Name() = oc.Name();
    Operands() = oc.Operands();
    Codes() = oc.Codes();
    OpCodeType() = oc.OpCodeType();
    CondCode() = oc.CondCode();
}

void CR_OpCode32::clear() {
    FuncAddrs().clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    OpCodeType() = cr_OCT_MISC;
    CondCode() = C_NONE;
}

void CR_OpCode32::ParseText(const char *text) {
    char buf[128];
    strcpy(buf, text);

    char *q = buf;

    if (strncmp(q, "cs ", 3) == 0 || strncmp(q, "ss ", 3) == 0 ||
        strncmp(q, "ds ", 3) == 0 || strncmp(q, "es ", 3) == 0 ||
        strncmp(q, "fs ", 3) == 0 || strncmp(q, "gs ", 3) == 0)
    {
        q += 3;
    }

    if (strncmp(q, "a16 ", 4) == 0 || strncmp(q, "o16 ", 4) == 0 ||
        strncmp(q, "o32 ", 4) == 0 || strncmp(q, "o64 ", 4) == 0)
    {
        q += 4;
    }

    if (q[0] == 'r' && q[1] == 'e') {
        for (auto& entry : cr_rep_insns) {
            if (_stricmp(q, entry) == 0) {
                Name() = q;
                OpCodeType() = cr_OCT_STROP;

                char *p = q + strlen(q) - 1;

                CR_Operand opr;
                if (*p == 'b')
                    opr.Size() = 1;
                else if (*p == 'w')
                    opr.Size() = 2;
                else if (*p == 'd')
                    opr.Size() = 4;

                if (q[3] == 'e')
                    CondCode() = C_E;
                else if (q[3] == 'n')
                    CondCode() = C_NE;
                else
                    CondCode() = C_NONE;

                Operands().clear();
                Operands().insert(opr);
                return;
            }
        }
    }

    if (strncmp(q, "rep ", 4) == 0)
        q += 4;
    if (strncmp(q, "repne ", 6) == 0)
        q += 6;

    if (strncmp(q, "ret", 3) == 0 || strncmp(q, "iret", 4) == 0) {
        char *p = strchr(q, ' ');
        if (p) {
            *p = '\0';
            CR_Operand opr;
            Operands().clear();
            opr.ParseText(p + 1, 32);
            Operands().insert(opr);
        }
        Name() = q;
        OpCodeType() = cr_OCT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j') {
        for (auto& entry : cr_ccentries) {
            if (strncmp(q, entry.name, strlen(entry.name)) == 0) {
                char *p = strchr(q, ' ');
                *p = '\0';
                Name() = entry.name;
                CondCode() = entry.cc;

                if (strncmp(entry.name, "loop", 4) == 0) {
                    OpCodeType() = cr_OCT_LOOP;
                } else if (CondCode() == C_NONE) {
                    if (_stricmp(entry.name, "call") == 0)
                        OpCodeType() = cr_OCT_CALL;
                    else
                        OpCodeType() = cr_OCT_JMP;
                } else {
                    OpCodeType() = cr_OCT_JCC;
                }

                p++;
                CR_Operand opr;
                opr.ParseText(p, 32);
                Operands().clear();
                Operands().insert(opr);
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL) {
        Name() = q;
        return;
    }

    if (strncmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');
    if (strncmp(q, "wait ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p++ = '\0';
    Name() = q;
    for (;;) {
        static const std::unordered_set<std::string> stackops = {
            "push", "pop", "enter", "leave"
        };
        if (stackops.find(q) != stackops.end()) {
            OpCodeType() = cr_OCT_STACKOP;
            break;
        }
        static const std::unordered_set<std::string> shiftops = {
            "sal", "sar", "shl", "shr", "shld", "shrd"
        };
        if (shiftops.find(q) != shiftops.end()) {
            OpCodeType() = cr_OCT_SHIFT;
            break;
        }
        static const std::unordered_set<std::string> rotateops = {
            "rol", "ror", "rcl", "rcl"
        };
        if (rotateops.find(q) != rotateops.end()) {
            OpCodeType() = cr_OCT_ROTATE;
            break;
        }
        static const std::set<std::string> arithops = {
            "adc", "add", "dec", "div", "idiv", "imul", "inc", "mul",
            "neg", "sbb", "sub", "cmp", "and", "not", "or", "xor",
            "cbw", "cwd", "cdq", "cwde", "aaa", "aad", "aam", "aas",
            "daa", "das"
        };
        if (arithops.find(q) != arithops.end()) {
            OpCodeType() = cr_OCT_ARITHOP;
            break;
        }
        break;
    }

    Operands().clear();
    CR_Operand opr;

    p = strtok(p, ",");
    if (p) {
        opr.ParseText(p, 32);
        Operands().insert(opr);
        p = strtok(NULL, ",");
        if (p) {
            opr.ParseText(p, 32);
            Operands().insert(opr);
            p = strtok(NULL, ",");
            if (p) {
                opr.ParseText(p, 32);
                Operands().insert(opr);
            }
        }
    }

    if (_stricmp(q, "mov") == 0 && Operands().size()) {
        if (Operand(0)->Text() == "esp" || Operand(0)->Text() == "ebp") {
            OpCodeType() = cr_OCT_STACKOP;
        }
    }
} // CR_OpCode32::ParseText

void CR_OpCode32::DeductOperandSizes() {
    if (Name() == "push") {
        Operand(0)->Size() = 4;
    } else if (
        Name() == "mov" || Name() == "cmp" ||
        Name() == "test" || Name() == "and" ||
        Name() == "or" || Name() == "xor" || 
        Name() == "add" || Name() == "adc" || 
        Name() == "sub" || Name() == "sbb" ||
        Name() == "xadd" || Name() == "xchg" ||
        Name() == "cmpxchg" ||
        Name() == "lock mov" || Name() == "lock cmp" ||
        Name() == "lock test" || Name() == "lock and" ||
        Name() == "lock or" || Name() == "lock xor" || 
        Name() == "lock add" || Name() == "lock adc" || 
        Name() == "lock sub" || Name() == "lock sbb" ||
        Name() == "lock xadd" || Name() == "lock xchg" ||
        Name() == "lock cmpxchg" ||
        Name() == "movnti" || Name().find("cmov") == 0)
    {
        assert(Operands().size() >= 2);
        if (Operand(0)->Size() == 0)
            Operand(0)->Size() = Operand(1)->Size();
        else if (Operand(1)->Size() == 0) {
            Operand(1)->Size() = Operand(0)->Size();
        }
    } else if (Name() == "imul") {
        if (Operands().size() >= 2 &&
            (Operand(1)->GetOperandType() == cr_DF_MEMREG ||
             Operand(1)->GetOperandType() == cr_DF_MEMIMM ||
             Operand(1)->GetOperandType() == cr_DF_MEMINDEX))
        {
            if (Operand(1)->Size() == 0) {
                Operand(1)->Size() = Operand(0)->Size();
            }
        }
    } else if (OpCodeType() == cr_OCT_JMP || OpCodeType() == cr_OCT_JCC ||
               OpCodeType() == cr_OCT_CALL)
    {
        Operand(0)->Size() = 4;
    } else if (Name() == "ret" && Operands().size() == 1) {
        Operand(0)->Size() = 4;
    } else if (Name() == "lea") {
        Operand(1)->Size() = 4;
    } else if (Name() == "sal" || Name() == "sar" ||
               Name() == "shl" || Name() == "shr" ||
               Name() == "rol" || Name() == "ror" ||
               Name() == "rcl" || Name() == "rcr")
    {
        Operand(1)->Size() = 1;
    } else if (Name() == "bt" ||
               Name() == "btc" ||
               Name() == "btr" ||
               Name() == "bts" ||
               Name() == "lock bt" ||
               Name() == "lock btc" ||
               Name() == "lock btr" ||
               Name() == "lock bts")
    {
        if (Operand(1)->GetOperandType() == cr_DF_IMM) {
            Operand(1)->Size() = 1;
        }
    } else if (Name() == "int" || Name() == "prefetchnta") {
        Operand(0)->Size() = 1;
    } else if (Operands().size() >= 2) {
        if (Operand(0)->Text().find("xmm") == 0) {
            if (Operand(1)->Size() == 0) {
                Operand(1)->Size() = Operand(0)->Size();
            }
            if (Operands().size() == 3 && Operand(2)->Size() == 0) {
                Operand(2)->Size() = 1;
            }
        } else if (Operand(1)->Text().find("xmm") == 0) {
            if (Operand(0)->Size() == 0) {
                Operand(0)->Size() = Operand(1)->Size();
            }
            if (Operands().size() == 3 && Operand(2)->Size() == 0) {
                Operand(2)->Size() = 1;
            }
        }
    }
} // CR_OpCode32::DeductOperandSizes

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64

void CR_OpCode64::Copy(const CR_OpCode64& oc) {
    FuncAddrs() = oc.FuncAddrs();
    Addr() = oc.Addr();
    Name() = oc.Name();
    Operands() = oc.Operands();
    Codes() = oc.Codes();
    OpCodeType() = oc.OpCodeType();
    CondCode() = oc.CondCode();
}

void CR_OpCode64::clear() {
    FuncAddrs().clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    OpCodeType() = cr_OCT_MISC;
    CondCode() = C_NONE;
}

void CR_OpCode64::ParseText(const char *text) {
    char buf[128];
    strcpy(buf, text);

    char *q = buf;
    if (strncmp(q, "a16 ", 4) == 0 || strncmp(q, "o16 ", 4) == 0 ||
        strncmp(q, "o32 ", 4) == 0 || strncmp(q, "o64 ", 4) == 0)
    {
        q += 4;
    }

    if (q[0] == 'r' && q[1] == 'e') {
        for (auto& entry : cr_rep_insns) {
            if (_stricmp(q, entry) == 0) {
                Name() = q;
                OpCodeType() = cr_OCT_STROP;
                char *p = q + strlen(q) - 1;

                CR_Operand opr;
                if (*p == 'b')
                    opr.Size() = 1;
                else if (*p == 'w')
                    opr.Size() = 2;
                else if (*p == 'd')
                    opr.Size() = 4;
                else if (*p == 'q')
                    opr.Size() = 8;

                if (q[3] == 'e')
                    CondCode() = C_E;
                else if (q[3] == 'n')
                    CondCode() = C_NE;
                else
                    CondCode() = C_NONE;

                Operands().clear();
                Operands().insert(opr);
                return;
            }
        }
    }

    if (strncmp(q, "rep ", 4) == 0)
        q += 4;
    if (strncmp(q, "repne ", 6) == 0)
        q += 6;

    if (strncmp(q, "ret", 3) == 0 || strncmp(q, "iret", 4) == 0) {
        char *p = strchr(q, ' ');
        if (p) {
            *p = '\0';
            CR_Operand opr;
            Operands().clear();
            opr.ParseText(p + 1, 64);
            Operands().insert(opr);
        }
        Name() = q;
        OpCodeType() = cr_OCT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j') {
        for (auto& entry : cr_ccentries) {
            if (strncmp(q, entry.name, strlen(entry.name)) == 0) {
                char *p = strchr(q, ' ');
                *p = '\0';
                Name() = entry.name;
                CondCode() = entry.cc;

                if (strncmp(entry.name, "loop", 4) == 0) {
                    OpCodeType() = cr_OCT_LOOP;
                } else if (CondCode() == C_NONE) {
                    if (_stricmp(entry.name, "call") == 0)
                        OpCodeType() = cr_OCT_CALL;
                    else
                        OpCodeType() = cr_OCT_JMP;
                } else {
                    OpCodeType() = cr_OCT_JCC;
                }

                p++;
                CR_Operand opr;
                opr.ParseText(p, 64);
                Operands().clear();
                Operands().insert(opr);
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL) {
        Name() = q;
        return;
    }

    if (strncmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');
    if (strncmp(q, "wait ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p++ = '\0';
    Name() = q;
    for (;;) {
        static const std::unordered_set<std::string> stackops = {
            "push", "pop", "enter", "leave"
        };
        if (stackops.find(q) != stackops.end()) {
            OpCodeType() = cr_OCT_STACKOP;
            break;
        }
        static const std::unordered_set<std::string> shiftops = {
            "sal", "sar", "shl", "shr", "shld", "shrd"
        };
        if (shiftops.find(q) != shiftops.end()) {
            OpCodeType() = cr_OCT_SHIFT;
            break;
        }
        static const std::unordered_set<std::string> rotateops = {
            "rol", "ror", "rcl", "rcl"
        };
        if (rotateops.find(q) != rotateops.end()) {
            OpCodeType() = cr_OCT_ROTATE;
            break;
        }
        static const std::set<std::string> arithops = {
            "adc", "add", "dec", "div", "idiv", "imul", "inc", "mul",
            "neg", "sbb", "sub", "cmp", "and", "not", "or", "xor",
            "cbw", "cwd", "cdq", "cwde", "aaa", "aad", "aam", "aas",
            "daa", "das"
        };
        if (arithops.find(q) != arithops.end()) {
            OpCodeType() = cr_OCT_ARITHOP;
            break;
        }
        break;
    }

    Operands().clear();
    CR_Operand opr;

    p = strtok(p, ",");
    if (p) {
        opr.ParseText(p, 32);
        Operands().insert(opr);
        p = strtok(NULL, ",");
        if (p) {
            opr.ParseText(p, 32);
            Operands().insert(opr);
            p = strtok(NULL, ",");
            if (p) {
                opr.ParseText(p, 32);
                Operands().insert(opr);
            }
        }
    }

    if (_stricmp(q, "mov") == 0 && Operands().size()) {
        if (Operand(0)->Text() == "rsp" || Operand(0)->Text() == "rbp") {
            OpCodeType() = cr_OCT_STACKOP;
        }
    }
} // CR_OpCode64::ParseText

void CR_OpCode64::DeductOperandSizes() {
    if (Name() == "push") {
        Operand(0)->Size() = 8;
    } else if (
        Name() == "mov" || Name() == "cmp" ||
        Name() == "test" || Name() == "and" ||
        Name() == "or" || Name() == "xor" || 
        Name() == "add" || Name() == "adc" || 
        Name() == "sub" || Name() == "sbb" ||
        Name() == "xadd" || Name() == "xchg" ||
        Name() == "cmpxchg" ||
        Name() == "lock mov" || Name() == "lock cmp" ||
        Name() == "lock test" || Name() == "lock and" ||
        Name() == "lock or" || Name() == "lock xor" || 
        Name() == "lock add" || Name() == "lock adc" || 
        Name() == "lock sub" || Name() == "lock sbb" ||
        Name() == "lock xadd" || Name() == "lock xchg" ||
        Name() == "lock cmpxchg" ||
        Name() == "movnti" || Name().find("cmov") == 0)
    {
        assert(Operands().size() >= 2);
        if (Operand(0)->Size() == 0)
            Operand(0)->Size() = Operand(1)->Size();
        else if (Operand(1)->Size() == 0) {
            Operand(1)->Size() = Operand(0)->Size();
        }
    } else if (Name() == "imul") {
        if (Operands().size() >= 2 &&
            (Operand(1)->GetOperandType() == cr_DF_MEMREG ||
             Operand(1)->GetOperandType() == cr_DF_MEMIMM ||
             Operand(1)->GetOperandType() == cr_DF_MEMINDEX))
        {
            if (Operand(1)->Size() == 0) {
                Operand(1)->Size() = Operand(0)->Size();
            }
        }
    } else if (OpCodeType() == cr_OCT_JMP ||
               OpCodeType() == cr_OCT_JCC ||
               OpCodeType() == cr_OCT_CALL)
    {
        Operand(0)->Size() = 8;
    } else if (Name() == "ret" && Operands().size() == 1) {
        Operand(0)->Size() = 8;
    } else if (Name() == "lea") {
        Operand(1)->Size() = 8;
    } else if (Name() == "sal" || Name() == "sar" ||
               Name() == "shl" || Name() == "shr" ||
               Name() == "rol" || Name() == "ror" ||
               Name() == "rcl" || Name() == "rcr")
    {
        Operand(1)->Size() = 1;
    } else if (Name() == "bt" ||
               Name() == "btc" ||
               Name() == "btr" ||
               Name() == "bts" ||
               Name() == "lock bt" ||
               Name() == "lock btc" ||
               Name() == "lock btr" ||
               Name() == "lock bts")
    {
        if (Operand(1)->GetOperandType() == cr_DF_IMM) {
            Operand(1)->Size() = 1;
        }
    } else if (Name() == "int" || Name() == "prefetchnta") {
        Operand(0)->Size() = 1;
    } else if (Operands().size() >= 2) {
        if (Operand(0)->Text().find("xmm") == 0) {
            if (Operand(1)->Size() == 0) {
                Operand(1)->Size() = Operand(0)->Size();
            }
            if (Operands().size() == 3 && Operand(2)->Size() == 0) {
                Operand(2)->Size() = 1;
            }
        } else if (Operand(1)->Text().find("xmm") == 0) {
            if (Operand(0)->Size() == 0) {
                Operand(0)->Size() = Operand(1)->Size();
            }
            if (Operands().size() == 3 && Operand(2)->Size() == 0) {
                Operand(2)->Size() = 1;
            }
        }
    }
} // CR_OpCode64::DeductOperandSizes

////////////////////////////////////////////////////////////////////////////

CR_BasicBlock32 *CR_CodeFunc32::BasicBlockFromAddr(CR_Addr32 addr) {
    for (auto& block : BasicBlocks()) {
        if (block.m_addr == addr) {
            return &block;
        }
    }
    return NULL;
}

const CR_BasicBlock32 *
CR_CodeFunc32::BasicBlockFromAddr(CR_Addr32 addr) const {
    for (const auto& block : BasicBlocks()) {
        if (block.m_addr == addr) {
            return &block;
        }
    }
    return NULL;
}

CR_BasicBlock64 *CR_CodeFunc64::BasicBlockFromAddr(CR_Addr64 addr) {
    for (auto& block : BasicBlocks()) {
        if (block.m_addr == addr) {
            return &block;
        }
    }
    return NULL;
}

const CR_BasicBlock64 *
CR_CodeFunc64::BasicBlockFromAddr(CR_Addr64 addr) const {
    for (const auto& block : BasicBlocks()) {
        if (block.m_addr == addr) {
            return &block;
        }
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////

int CR_DecompInfo32::GetFuncStage(CR_Addr32 func) const {
    auto it = MapAddrToCodeFunc().find(func);
    if (it == MapAddrToCodeFunc().end()) {
        return 0;
    }
    if (OpCodeFromAddr(func) == NULL) {
        return 0;
    }
    auto cf = it->second;
    assert(cf);
    auto block = cf->BasicBlockFromAddr(func);
    if (block == NULL) {
        return 1;
    }
    return 2;
}

int CR_DecompInfo64::GetFuncStage(CR_Addr64 func) const {
    auto it = MapAddrToCodeFunc().find(func);
    if (it == MapAddrToCodeFunc().end()) {
        return 0;
    }
    if (OpCodeFromAddr(func) == NULL) {
        return 0;
    }
    auto cf = it->second;
    assert(cf);
    auto block = cf->BasicBlockFromAddr(func);
    if (block == NULL) {
        return 1;
    }
    return 2;
}

////////////////////////////////////////////////////////////////////////////
