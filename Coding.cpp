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
    {"es", cr_x86_SEGREG, 64},
    {"cs", cr_x86_SEGREG, 0},
    {"ss", cr_x86_SEGREG, 64},
    {"ds", cr_x86_SEGREG, 64},
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
        if (bits >= entry.bits &&
            _stricmp(entry.name, name) == 0)
        {
            return entry.type;
        }
    }
    return cr_x86_REGNONE;
}

DWORD CrRegGetSize(const char *name, int bits) {
    switch (CrRegGetType(name, bits)) {
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
    Disp() = 0;
    Scale() = 0;
    TypeID() = cr_invalid_id;
}

void CR_Operand::SetImm32(CR_Addr32 val, BOOL is_signed) {
    Text() = CrValue32(val, is_signed);
    ExprAddr().clear();
    SetOperandType(cr_OF_IMM);
    Value64() = val;
}

void CR_Operand::SetImm64(CR_Addr64 val, BOOL is_signed) {
    Text() = CrValue64(val, is_signed);
    ExprAddr().clear();
    SetOperandType(cr_OF_IMM);
    Value64() = val;
}

void CR_Operand::SetExprAddrOnMemIndex() {
    std::string expr;
    if (BaseReg().size()) {
        expr += BaseReg();
    }
    if (IndexReg().size() && Scale() != 0) {
        if (BaseReg().size()) {
            expr += "+";
        }
        expr += IndexReg();
        expr += std::to_string(Scale());
    }
    if (Disp() > 0) {
        expr += "+";
        expr += std::to_string(Disp());
    } else if (Disp() < 0) {
        expr += "-";
        expr += std::to_string(Disp());
    }
    ExprAddr() = expr;
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand::ParseText

void CR_Operand::ParseText(int bits) {
    char buf[64];
    strcpy(buf, Text().c_str());
    char *p = buf;

    DWORD size = CrRegGetSize(p, bits);
    if (size != 0) {
        BaseReg() = p;
        ExprAddr().clear();
        SetOperandType(cr_OF_REG);
        Size() = size;
        return;
    }

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
    if (p[0] == '[') {
        ++p;
        *strchr(p, ']') = '\0';

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

        // is there segment register?
        char *q = strchr(p, ':');
        if (q) {
            *q++ = 0;
            Seg() = p;
            p = q;
        }

        DWORD size;
        if ((size = CrRegGetSize(p, bits)) != 0) {
            BaseReg() = p;
            SetOperandType(cr_OF_MEMREG);
            ExprAddr() = BaseReg();
            return;
        }

        // find '+' or '-'
        bool minus1 = false;
        q = p + strcspn(p, "+-");
        if (*q == 0) {
            if (isdigit(*p)) {
                CR_Addr64 addr = std::strtoull(p, NULL, 0);
                Value64() = addr;
                SetOperandType(cr_OF_MEMIMM);
                ExprAddr() = std::to_string(addr);
            } else {
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
            // eax*4+0x1e
            // eax*4+0x4
            // ebx*4+0x402800
            // edi*4+0x0
            *r++ = 0;
            BaseReg().clear();
            IndexReg() = p;
            Scale() = char(strtol(r, NULL, 0));
            if (minus1) {
                Disp() = -strtol(q, NULL, 0);
            } else {
                Disp() = strtol(q, NULL, 0);
            }
            SetOperandType(cr_OF_MEMINDEX);
            SetExprAddrOnMemIndex();
            return;
        }

        // find '+' or '-'
        bool minus2 = false;
        r = q + strcspn(q, "+-");
        if (*r == 0) {
            char *s = strchr(q, '*');
            if (s) {
                // ebx+ebx*2
                *s++ = 0;
                BaseReg() = p;
                IndexReg() = q;
                Scale() = char(strtol(s, NULL, 0));
                Disp() = 0;
                SetOperandType(cr_OF_MEMINDEX);
                if (BaseReg() == IndexReg()) {
                    BaseReg().clear();
                    Scale() += 1;
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
                        Disp() = -strtol(q, NULL, 0);
                    } else {
                        Disp() = strtol(q, NULL, 0);
                    }
                    SetOperandType(cr_OF_MEMINDEX);
                    SetExprAddrOnMemIndex();
                    return;
                } else {
                    // esi+eax
                    BaseReg() = p;
                    IndexReg() = q;
                    Scale() = 1;
                    Disp() = 0;
                    SetOperandType(cr_OF_MEMINDEX);
                    if (BaseReg() == IndexReg()) {
                        BaseReg().clear();
                        Scale() = 2;
                    }
                    SetExprAddrOnMemIndex();
                    return;
                }
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
                    Disp() = -strtol(r, NULL, 0);
                } else {
                    Disp() = strtol(r, NULL, 0);
                }
                SetOperandType(cr_OF_MEMINDEX);
                if (BaseReg() == IndexReg()) {
                    BaseReg().clear();
                    Scale() += 1;
                }
                SetExprAddrOnMemIndex();
                return;
            } else {
                // rbp+rax+0x0
                BaseReg() = p;
                IndexReg() = q;
                Scale() = 1;
                if (minus2) {
                    Disp() = -strtol(r, NULL, 0);
                } else {
                    Disp() = strtol(r, NULL, 0);
                }
                SetOperandType(cr_OF_MEMINDEX);
                if (BaseReg() == IndexReg()) {
                    BaseReg().clear();
                    Scale() += 1;
                }
                SetExprAddrOnMemIndex();
                return;
            }
        }
    }
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
        const std::size_t size =
            sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (std::size_t i = 0; i < size; ++i) {
            if (_stricmp(q, cr_rep_insns[i]) == 0) {
                Name() = q;
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
            opr.Text() = p + 1;
            Operands().clear();
            opr.ParseText(32);
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
                opr.Text() = p;
                opr.ParseText(32);
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

    *p = '\0';
    Name() = q;
    if (_stricmp(q, "push") == 0 || _stricmp(q, "pop") == 0 ||
        _stricmp(q, "enter") == 0 || _stricmp(q, "leave") == 0)
    {
        OpCodeType() = cr_OCT_STACKOP;
    }

    Operands().clear();
    p = strtok(p + 1, ",");
    if (p) {
        CR_Operand opr;
        opr.Text() = p;
        Operands().insert(opr);
        p = strtok(NULL, ",");
        if (p) {
            opr.Text() = p;
            Operands().insert(opr);
            p = strtok(NULL, ",");
            if (p) {
                opr.Text() = p;
                Operands().insert(opr);
                Operand(2)->ParseText(32);
            }
            Operand(1)->ParseText(32);
        }
        Operand(0)->ParseText(32);
    }
}

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
        const std::size_t size =
            sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (std::size_t i = 0; i < size; ++i) {
            if (_stricmp(q, cr_rep_insns[i]) == 0) {
                Name() = q;
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

    if (strncmp(q, "ret", 3) == 0 || strncmp(q, "iret", 4) == 0) {
        char *p = strchr(q, ' ');
        if (p) {
            *p = '\0';
            CR_Operand opr;
            opr.Text() = p + 1;
            Operands().clear();
            opr.ParseText(64);
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
                opr.Text() = p;
                opr.ParseText(64);
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

    *p = '\0';
    Name() = q;
    if (_stricmp(q, "push") == 0 || _stricmp(q, "pop") == 0 ||
        _stricmp(q, "enter") == 0 || _stricmp(q, "leave") == 0)
    {
        OpCodeType() = cr_OCT_STACKOP;
    }

    Operands().clear();
    p = strtok(p + 1, ",");
    if (p) {
        CR_Operand opr;
        opr.Text() = p;
        Operands().insert(opr);
        p = strtok(NULL, ",");
        if (p) {
            opr.Text() = p;
            Operands().insert(opr);
            p = strtok(NULL, ",");
            if (p) {
                opr.Text() = p;
                Operands().insert(opr);
                Operand(2)->ParseText(64);
            }
            Operand(1)->ParseText(64);
        }
        Operand(0)->ParseText(64);
    }
}

////////////////////////////////////////////////////////////////////////////
// CrGetAsmIO16, CrGetAsmIO32, CrGetAsmIO64

void CrStrSplitToSet(
    std::set<std::string>& s, const char *psz, const char *seps)
{
    s.clear();
    char *str = _strdup(psz);
    char *p = strtok(str, seps);
    while (p != NULL) {
        s.insert(p);
        p = strtok(NULL, seps);
    }
    free(str);
}

// assembly instruction input/output information
struct X86ASMIO {
    const char *name;
    int num_args;
    const char *in;
    const char *out;
    int osize;
};

static int CrCompareAsmIO(const void *a, const void *b) {
    const X86ASMIO *x = (const X86ASMIO *)a;
    const X86ASMIO *y = (const X86ASMIO *)b;
    int cmp = strcmp(x->name, y->name);
    if (cmp != 0)
        return cmp;

    cmp = x->num_args - y->num_args;
    if (cmp != 0)
        return cmp;
    
    cmp = x->osize - y->osize;
    if (cmp != 0)
        return cmp;

    return 0;
}

BOOL CrGetAsmIO16(
    X86ASMIO *key, std::set<std::string>& in, 
    std::set<std::string>& out, int osize)
{
    static const X86ASMIO s_table[] = {
        {"aaa", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"aad", 0, "al,ah", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 0, "al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 1, "$0,al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aas", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"adc", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"add", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"and", 2, "$0,$1", "$0,ZF,SF,CF,OF,AF,PF,SFeqOF", 0},
        {"cbw", 0, "al", "ax", 0},
        {"clc", 0, "", "CF", 0},
        {"cld", 0, "", "DF", 0},
        {"cli", 0, "", "IF", 0},
        {"cmc", 0, "CF", "CF", 0},
        {"cmp", 2, "$0,$1", "OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsb", 0, "si,di,DF,m8(si),m8(di)", "OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "si,di,DF,m16(si),m16(di)", "OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cwd", 0, "ax", "dx", 0},
        {"daa", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"das", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"dec", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"div", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"div", 1, "$0,dx:ax", "ax,dx,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"idiv", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"idiv", 1, "$0,dx:ax", "dx,ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 1, "al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 1, "ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"inc", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"ja", 1, "$0", "", 0},
        {"jae", 1, "$0", "", 0},
        {"jb", 1, "$0", "", 0},
        {"jbe", 1, "$0", "", 0},
        {"jc", 1, "$0", "", 0},
        {"jcxz", 1, "$0,cx", "", 0},
        {"je", 1, "$0", "", 0},
        {"jg", 1, "$0", "", 0},
        {"jge", 1, "$0", "", 0},
        {"jl", 1, "$0", "", 0},
        {"jle", 1, "$0", "", 0},
        {"jmp", 1, "$0", "", 0},
        {"jna", 1, "$0", "", 0},
        {"jnae", 1, "$0", "", 0},
        {"jnb", 1, "$0", "", 0},
        {"jnbe", 1, "$0", "", 0},
        {"jnc", 1, "$0", "", 0},
        {"jne", 1, "$0", "", 0},
        {"jng", 1, "$0", "", 0},
        {"jnge", 1, "$0", "", 0},
        {"jnl", 1, "$0", "", 0},
        {"jnle", 1, "$0", "", 0},
        {"jno", 1, "$0", "", 0},
        {"jnp", 1, "$0", "", 0},
        {"jns", 1, "$0", "", 0},
        {"jnz", 1, "$0", "", 0},
        {"jo", 1, "$0", "", 0},
        {"jp", 1, "$0", "", 0},
        {"jpe", 1, "$0", "", 0},
        {"jpo", 1, "$0", "", 0},
        {"js", 1, "$0", "", 0},
        {"jz", 1, "$0", "", 0},
        {"lea", 2, "$0,$1", "$0", 0},
        {"lodsb", 0, "si,DF,m8(si)", "al,si", 0},
        {"lodsw", 0, "si,DF,m16(si)", "ax,si", 0},
        {"loop", 1, "$0,cx", "cx", 0},
        {"loope", 1, "$0,cx,ZF", "cx", 0},
        {"loopne", 1, "$0,cx,ZF", "cx", 0},
        {"loopz", 1, "$0,cx,ZF", "cx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "di,si,DF,m8(si)", "di,si,m8(di)", 0},
        {"movsw", 0, "di,si,DF,m16(si)", "di,si,m16(di)", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"rep lodsb", 0, "si,DF,cx,m8(si)", "cx,al,si", 0},
        {"rep lodsw", 0, "si,DF,cx,m16(si)", "cx,ax,si", 0},
        {"rep stosb", 0, "di,al,cx,DF", "di,cx,m8(di)", 0},
        {"rep stosw", 0, "di,ax,cx,DF", "di,cx,m16(di)", 0},
        {"repe cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "di,al,DF,m8(di)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "di,ax,DF,m16(di)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "di,al,DF", "di,m8(di)", 0},
        {"stosw", 0, "di,ax,DF", "di,m16(di)", 0},
        {"sub", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"test", 2, "$0,$1", "ZF,SF,PF,CF,OF,SFeqOF", 0},
        {"xchg", 2, "$0,$1", "$0,$1", 0},
        {"xlat", 1, "al,$0,mem", "al", 0},
        {"xlatb", 1, "al,$0,mem", "al", 0},
        {"xor", 2, "$0,$1", "$0,ZF,SF,OF,CF,PF,AF,SFeqOF", 0},
    };

    const std::size_t size = sizeof(s_table) / sizeof(s_table[0]);
    const X86ASMIO *p = 
        reinterpret_cast<const X86ASMIO *>(
            bsearch(key, s_table, size, sizeof(X86ASMIO), CrCompareAsmIO));
    if (p == NULL)
        return FALSE;

    if (p->osize != 0 && p->osize != osize)
        p++;

    if (strcmp(key->name, p->name) != 0)
        return FALSE;

    CrStrSplitToSet(in, p->in, ",");
    CrStrSplitToSet(out, p->out, ",");
    return TRUE;
}

BOOL CrGetAsmIO32(X86ASMIO *key, std::set<std::string>& in, 
    std::set<std::string>& out, int osize)
{
    static const X86ASMIO s_table[] = {
        {"aaa", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"aad", 0, "al,ah", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 0, "al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 1, "$0,al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aas", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"adc", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"add", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"and", 2, "$0,$1", "$0,ZF,SF,CF,OF,AF,PF,SFeqOF", 0},
        {"bsf", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bsr", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bswap", 1, "$0", "$0", 0},
        {"bt", 2, "$1,$2", "CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btc", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btr", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bts", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"cbw", 0, "al", "ax", 0},
        {"cdq", 0, "eax", "edx", 0},
        {"clc", 0, "", "CF", 0},
        {"cld", 0, "", "DF", 0},
        {"cli", 0, "", "IF", 0},
        {"cmc", 0, "CF", "CF", 0},
        {"cmova", 2, "$1,CF,ZF", "$0", 0},
        {"cmovae", 2, "$1,CF", "$0", 0},
        {"cmovb", 2, "$1,CF", "$0", 0},
        {"cmovbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovc", 2, "$1,CF", "$0", 0},
        {"cmove", 2, "$1,ZF", "$0", 0},
        {"cmovg", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovna", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnae", 2, "$1,CF", "$0", 0},
        {"cmovnb", 2, "$1,CF", "$0", 0},
        {"cmovnbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnc", 2, "$1,CF", "$0", 0},
        {"cmovne", 2, "$1,ZF", "$0", 0},
        {"cmovng", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovnge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovno", 2, "$1,OF", "$0", 0},
        {"cmovnp", 2, "$1,PF", "$0", 0},
        {"cmovns", 2, "$1,SF", "$0", 0},
        {"cmovnz", 2, "$1,ZF", "$0", 0},
        {"cmovo", 2, "$1,OF", "$0", 0},
        {"cmovp", 2, "$1,PF", "$0", 0},
        {"cmovpe", 2, "$1,PF", "$0", 0},
        {"cmovpo", 2, "$1,PF", "$0", 0},
        {"cmovs", 2, "$1,SF", "$0", 0},
        {"cmovz", 2, "$1,ZF", "$0", 0},
        {"cmp", 2, "$0,$1", "OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsb", 0, "esi,edi,DF,m8(esi),m8(edi)", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsd", 0, "esi,edi,DF,m32(esi),m32(edi)", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "esi,edi,DF,m16(esi),m16(edi)", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpxchg", 2, "$0,$1", "$0,$1,ZF,SF,CF,PF,AF,SFeqOF", 0},
        {"cwd", 0, "ax", "dx", 0},
        {"cwde", 0, "ax", "eax", 0},
        {"daa", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"das", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"dec", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"div", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"div", 1, "$0,dx:ax", "ax,dx,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"div", 1, "$0,edx:eax", "eax,edx,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"idiv", 1, "$0,al", "al:ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"idiv", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"idiv", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 1, "al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 1, "ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 1, "eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"inc", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"ja", 1, "$0", "", 0},
        {"jae", 1, "$0", "", 0},
        {"jb", 1, "$0", "", 0},
        {"jbe", 1, "$0", "", 0},
        {"jc", 1, "$0", "", 0},
        {"jcxz", 1, "$0,cx", "", 0},
        {"je", 1, "$0", "", 0},
        {"jg", 1, "$0", "", 0},
        {"jge", 1, "$0", "", 0},
        {"jl", 1, "$0", "", 0},
        {"jle", 1, "$0", "", 0},
        {"jmp", 1, "$0", "", 0},
        {"jna", 1, "$0", "", 0},
        {"jnae", 1, "$0", "", 0},
        {"jnb", 1, "$0", "", 0},
        {"jnbe", 1, "$0", "", 0},
        {"jnc", 1, "$0", "", 0},
        {"jne", 1, "$0", "", 0},
        {"jng", 1, "$0", "", 0},
        {"jnge", 1, "$0", "", 0},
        {"jnl", 1, "$0", "", 0},
        {"jnle", 1, "$0", "", 0},
        {"jno", 1, "$0", "", 0},
        {"jnp", 1, "$0", "", 0},
        {"jns", 1, "$0", "", 0},
        {"jnz", 1, "$0", "", 0},
        {"jo", 1, "$0", "", 0},
        {"jp", 1, "$0", "", 0},
        {"jpe", 1, "$0", "", 0},
        {"jpo", 1, "$0", "", 0},
        {"js", 1, "$0", "", 0},
        {"jz", 1, "$0", "", 0},
        {"lea", 2, "$0,$1", "$0", 0},
        {"lodsb", 0, "esi,DF,m8(esi)", "al,esi", 0},
        {"lodsd", 0, "esi,DF,m32(esi)", "eax,esi", 0},
        {"lodsw", 0, "esi,DF,m16(esi)", "ax,esi", 0},
        {"loop", 1, "$0,ecx", "ecx", 0},
        {"loope", 1, "$0,ecx,ZF", "ecx", 0},
        {"loopne", 1, "$0,ecx,ZF", "ecx", 0},
        {"loopz", 1, "$0,ecx,ZF", "ecx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "edi,esi,DF,m8(esi)", "edi,esi,m8(edi)", 0},
        {"movsd", 0, "edi,esi,DF,m32(esi)", "edi,esi,m32(edi)", 0},
        {"movsw", 0, "edi,esi,DF,m16(esi)", "edi,esi,m16(edi)", 0},
        {"movsx", 2, "$1", "$0", 0},
        {"movzx", 2, "$1", "$0", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"mul", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"nop", 1, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"popcnt", 2, "$1", "$0", 0},
        {"rep lodsb", 0, "esi,DF,ecx,m8(esi)", "ecx,al,esi", 0},
        {"rep lodsd", 0, "esi,DF,ecx,m32(esi)", "ecx,eax,esi", 0},
        {"rep lodsw", 0, "esi,DF,ecx,m16(esi)", "ecx,ax,esi", 0},
        {"rep stosb", 0, "ddi,al,ecx,DF", "edi,ecx,m8(edi)", 0},
        {"rep stosd", 0, "ddi,eax,ecx,DF", "edi,ecx,m32(edi)", 0},
        {"rep stosw", 0, "ddi,ax,ecx,DF", "edi,ecx,m16(edi)", 0},
        {"repe cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "edi,al,DF,m8(edi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasd", 0, "edi,eax,DF,m32(edi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "edi,ax,DF,m16(edi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"seta", 1, "ZF,CF", "$0", 0},
        {"setae", 1, "CF", "$0", 0},
        {"setb", 1, "CF", "$0", 0},
        {"setc", 1, "CF", "$0", 0},
        {"sete", 1, "ZF", "$0", 0},
        {"setg", 1, "ZF,SFeqOF", "$0", 0},
        {"setge", 1, "SFeqOF", "$0", 0},
        {"setl", 1, "SFeqOF", "$0", 0},
        {"setle", 1, "ZF,SFeqOF", "$0", 0},
        {"setna", 1, "ZF,CF", "$0", 0},
        {"setnae", 1, "CF", "$0", 0},
        {"setnb", 1, "CF", "$0", 0},
        {"setnbe", 1, "ZF,CF", "$0", 0},
        {"setnc", 1, "CF", "$0", 0},
        {"setne", 1, "ZF", "$0", 0},
        {"setng", 1, "ZF,SFeqOF", "$0", 0},
        {"setnge", 1, "SFeqOF", "$0", 0},
        {"setnl", 1, "SFeqOF", "$0", 0},
        {"setnle", 1, "ZF,SFeqOF", "$0", 0},
        {"setno", 1, "OF", "$0", 0},
        {"setnp", 1, "PF", "$0", 0},
        {"setns", 1, "SF", "$0", 0},
        {"setnz", 1, "ZF", "$0", 0},
        {"seto", 1, "OF", "$0", 0},
        {"setp", 1, "PF", "$0", 0},
        {"setpe", 1, "PF", "$0", 0},
        {"setpo", 1, "PF", "$0", 0},
        {"sets", 1, "SF", "$0", 0},
        {"setz", 1, "ZF", "$0", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "edi,al,DF", "edi,m8(edi)", 0},
        {"stosd", 0, "edi,eax,DF", "edi,m32(edi)", 0},
        {"stosw", 0, "edi,ax,DF", "edi,m16(edi)", 0},
        {"sub", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"test", 2, "$0,$1", "ZF,SF,PF,CF,OF,SFeqOF", 0},
        {"xadd", 2, "$0,$1", "$0,$1,OF,CF,PF,AF,SF,ZF,SFeqOF", 0},
        {"xchg", 2, "$0,$1", "$0,$1", 0},
        {"xlat", 1, "al,$0,mem", "al", 0},
        {"xlatb", 1, "al,$0,mem", "al", 0},
        {"xor", 2, "$0,$1", "$0,ZF,SF,OF,CF,PF,AF,SFeqOF", 0},
    };

    const std::size_t size = sizeof(s_table) / sizeof(s_table[0]);
    const X86ASMIO *p =
        reinterpret_cast<const X86ASMIO *>(
            bsearch(key, s_table, size, sizeof(X86ASMIO), CrCompareAsmIO));
    if (p == NULL)
        return FALSE;

    if (p->osize != 0 && p->osize != osize)
        p++;
    if (p->osize != 0 && p->osize != osize)
        p++;

    if (strcmp(key->name, p->name) != 0)
        return FALSE;

    CrStrSplitToSet(in, p->in, ",");
    CrStrSplitToSet(out, p->out, ",");
    return TRUE;
}

BOOL CrGetAsmIO64(
    X86ASMIO *key, std::set<std::string>& in, 
    std::set<std::string>& out, int osize)
{
    static const X86ASMIO s_table[] = {
        {"adc", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"add", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"and", 2, "$0,$1", "$0,ZF,SF,CF,OF,AF,PF,SFeqOF", 0},
        {"bsf", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bsr", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bswap", 1, "$0", "$0", 0},
        {"bt", 2, "$1,$2", "CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btc", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btr", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bts", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"cbw", 0, "al", "ax", 0},
        {"cdq", 0, "eax", "edx", 0},
        {"cdqe", 0, "rax", "eax", 0},
        {"clc", 0, "", "CF", 0},
        {"cld", 0, "", "DF", 0},
        {"cli", 0, "", "IF", 0},
        {"cmc", 0, "CF", "CF", 0},
        {"cmova", 2, "$1,CF,ZF", "$0", 0},
        {"cmovae", 2, "$1,CF", "$0", 0},
        {"cmovb", 2, "$1,CF", "$0", 0},
        {"cmovbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovc", 2, "$1,CF", "$0", 0},
        {"cmove", 2, "$1,ZF", "$0", 0},
        {"cmovg", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovna", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnae", 2, "$1,CF", "$0", 0},
        {"cmovnb", 2, "$1,CF", "$0", 0},
        {"cmovnbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnc", 2, "$1,CF", "$0", 0},
        {"cmovne", 2, "$1,ZF", "$0", 0},
        {"cmovng", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovnge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovno", 2, "$1,OF", "$0", 0},
        {"cmovnp", 2, "$1,PF", "$0", 0},
        {"cmovns", 2, "$1,SF", "$0", 0},
        {"cmovnz", 2, "$1,ZF", "$0", 0},
        {"cmovo", 2, "$1,OF", "$0", 0},
        {"cmovp", 2, "$1,PF", "$0", 0},
        {"cmovpe", 2, "$1,PF", "$0", 0},
        {"cmovpo", 2, "$1,PF", "$0", 0},
        {"cmovs", 2, "$1,SF", "$0", 0},
        {"cmovz", 2, "$1,ZF", "$0", 0},
        {"cmp", 2, "$0,$1", "OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsb", 0, "rsi,rdi,DF,m8(rsi),m8(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsd", 0, "rsi,rdi,DF,m32(rsi),m32(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsq", 0, "rsi,rdi,DF,m64(rsi),m64(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "rsi,rdi,DF,m16(rsi),m16(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpxchg", 2, "$0,$1", "$0,$1,ZF,SF,CF,PF,AF,SFeqOF", 0},
        {"cwd", 0, "ax", "dx", 0},
        {"cwde", 0, "ax", "eax", 0},
        {"cqo", 0, "rax", "rdx", 0},
        {"dec", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"div", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"div", 1, "$0,dx:ax", "ax,dx,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"div", 1, "$0,edx:eax", "eax,edx,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"div", 1, "$0,rdx:rax", "rax,rdx,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"idiv", 1, "$0,al", "al:ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"idiv", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"idiv", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"idiv", 1, "$0,rax", "rdx:rax,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"imul", 1, "al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 1, "ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 1, "eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 1, "rax", "rdx:rax,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"inc", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"ja", 1, "$0", "", 0},
        {"jae", 1, "$0", "", 0},
        {"jb", 1, "$0", "", 0},
        {"jbe", 1, "$0", "", 0},
        {"jc", 1, "$0", "", 0},
        {"jcxz", 1, "$0,cx", "", 0},
        {"je", 1, "$0", "", 0},
        {"jg", 1, "$0", "", 0},
        {"jge", 1, "$0", "", 0},
        {"jl", 1, "$0", "", 0},
        {"jle", 1, "$0", "", 0},
        {"jmp", 1, "$0", "", 0},
        {"jna", 1, "$0", "", 0},
        {"jnae", 1, "$0", "", 0},
        {"jnb", 1, "$0", "", 0},
        {"jnbe", 1, "$0", "", 0},
        {"jnc", 1, "$0", "", 0},
        {"jne", 1, "$0", "", 0},
        {"jng", 1, "$0", "", 0},
        {"jnge", 1, "$0", "", 0},
        {"jnl", 1, "$0", "", 0},
        {"jnle", 1, "$0", "", 0},
        {"jno", 1, "$0", "", 0},
        {"jnp", 1, "$0", "", 0},
        {"jns", 1, "$0", "", 0},
        {"jnz", 1, "$0", "", 0},
        {"jo", 1, "$0", "", 0},
        {"jp", 1, "$0", "", 0},
        {"jpe", 1, "$0", "", 0},
        {"jpo", 1, "$0", "", 0},
        {"js", 1, "$0", "", 0},
        {"jz", 1, "$0", "", 0},
        {"lea", 2, "$0,$1", "$0", 0},
        {"lodsb", 0, "rsi,DF,m8(rsi)", "al,rsi", 0},
        {"lodsd", 0, "rsi,DF,m32(rsi)", "eax,rsi", 0},
        {"lodsq", 0, "rsi,DF,m64(rsi)", "rax,rsi", 0},
        {"lodsw", 0, "rsi,DF,m16(rsi)", "ax,rsi", 0},
        {"loop", 1, "$0,rcx", "rcx", 0},
        {"loope", 1, "$0,rcx,ZF", "rcx", 0},
        {"loopne", 1, "$0,rcx,ZF", "rcx", 0},
        {"loopz", 1, "$0,rcx,ZF", "rcx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "rdi,rsi,DF,m8(rsi)", "rdi,rsi,m8(rdi)", 0},
        {"movsd", 0, "rdi,rsi,DF,m32(rsi)", "rdi,rsi,m32(rdi)", 0},
        {"movsq", 0, "rdi,rsi,DF,m64(rsi)", "rdi,rsi,m64(rdi)", 0},
        {"movsw", 0, "rdi,rsi,DF,m16(rsi)", "rdi,rsi,m16(rdi)", 0},
        {"movsx", 2, "$1", "$0", 0},
        {"movzx", 2, "$1", "$0", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"mul", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"mul", 1, "$0,rax", "rdx:rax,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"nop", 1, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"popcnt", 2, "$1", "$0", 0},
        {"rep lodsb", 0, "rsi,DF,rcx,m8(rsi)", "rcx,al,rsi", 0},
        {"rep lodsd", 0, "rsi,DF,rcx,m32(rsi)", "rcx,eax,rsi", 0},
        {"rep lodsw", 0, "rsi,DF,rcx,m64(rsi)", "rcx,ax,rsi", 0},
        {"rep lodsq", 0, "rsi,DF,rcx,m16(rsi)", "rcx,rax,rsi", 0},
        {"rep stosb", 0, "ddi,al,rcx,DF", "rdi,rcx,m8(rdi)", 0},
        {"rep stosd", 0, "ddi,eax,rcx,DF", "rdi,rcx,m32(rdi)", 0},
        {"rep stosq", 0, "ddi,rax,rcx,DF", "rdi,rcx,m64(rdi)", 0},
        {"rep stosw", 0, "ddi,ax,rcx,DF", "rdi,rcx,m16(rdi)", 0},
        {"repe cmpsb", 0, "rcx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsd", 0, "rcx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsq", 0, "rcx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "rcx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "ecx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsd", 0, "ecx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsq", 0, "ecx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "ecx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "rcx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsd", 0, "rcx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsq", 0, "rcx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "rcx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "rcx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsd", 0, "rcx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsq", 0, "rcx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "rcx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "rdi,al,DF,m8(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasd", 0, "rdi,eax,DF,m32(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasq", 0, "rdi,eax,DF,m64(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "rdi,ax,DF,m16(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"seta", 1, "ZF,CF", "$0", 0},
        {"setae", 1, "CF", "$0", 0},
        {"setb", 1, "CF", "$0", 0},
        {"setc", 1, "CF", "$0", 0},
        {"sete", 1, "ZF", "$0", 0},
        {"setg", 1, "ZF,SFeqOF", "$0", 0},
        {"setge", 1, "SFeqOF", "$0", 0},
        {"setl", 1, "SFeqOF", "$0", 0},
        {"setle", 1, "ZF,SFeqOF", "$0", 0},
        {"setna", 1, "ZF,CF", "$0", 0},
        {"setnae", 1, "CF", "$0", 0},
        {"setnb", 1, "CF", "$0", 0},
        {"setnbe", 1, "ZF,CF", "$0", 0},
        {"setnc", 1, "CF", "$0", 0},
        {"setne", 1, "ZF", "$0", 0},
        {"setng", 1, "ZF,SFeqOF", "$0", 0},
        {"setnge", 1, "SFeqOF", "$0", 0},
        {"setnl", 1, "SFeqOF", "$0", 0},
        {"setnle", 1, "ZF,SFeqOF", "$0", 0},
        {"setno", 1, "OF", "$0", 0},
        {"setnp", 1, "PF", "$0", 0},
        {"setns", 1, "SF", "$0", 0},
        {"setnz", 1, "ZF", "$0", 0},
        {"seto", 1, "OF", "$0", 0},
        {"setp", 1, "PF", "$0", 0},
        {"setpe", 1, "PF", "$0", 0},
        {"setpo", 1, "PF", "$0", 0},
        {"sets", 1, "SF", "$0", 0},
        {"setz", 1, "ZF", "$0", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "rdi,al,DF", "rdi,m8(rdi)", 0},
        {"stosd", 0, "rdi,eax,DF", "rdi,m32(rdi)", 0},
        {"stosq", 0, "rdi,rax,DF", "rdi,m64(rdi)", 0},
        {"stosw", 0, "rdi,ax,DF", "rdi,m16(rdi)", 0},
        {"sub", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"test", 2, "$0,$1", "ZF,SF,PF,CF,OF,SFeqOF", 0},
        {"xadd", 2, "$0,$1", "$0,$1,OF,CF,PF,AF,SF,ZF,SFeqOF", 0},
        {"xchg", 2, "$0,$1", "$0,$1", 0},
        {"xlat", 1, "al,$0,mem", "al", 0},
        {"xlatb", 1, "al,$0,mem", "al", 0},
        {"xor", 2, "$0,$1", "$0,ZF,SF,OF,CF,PF,AF,SFeqOF", 0},
    };

    const std::size_t size = sizeof(s_table) / sizeof(s_table[0]);
    const X86ASMIO *p =
        reinterpret_cast<const X86ASMIO *>(
            bsearch(key, s_table, size, sizeof(X86ASMIO), CrCompareAsmIO));
    if (p == NULL)
        return FALSE;

    if (p->osize != 0 && p->osize != osize)
        p++;
    if (p->osize != 0 && p->osize != osize)
        p++;

    if (strcmp(key->name, p->name) != 0)
        return FALSE;

    CrStrSplitToSet(in, p->in, ",");
    CrStrSplitToSet(out, p->out, ",");
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
