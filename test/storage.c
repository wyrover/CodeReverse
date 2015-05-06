#include <windows.h>
#include <stdio.h>

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

typedef union CR_MMX {
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

typedef union CR_XMM {
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
    CR_XMM      xmm;
    CR_MMX      mmx;
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

#define do_it(type,var,field) \
    printf(#var ", \"" #field "\", %d, %d\n", \
        (int)(FIELD_OFFSET(type, field) * 8), \
        (int)(sizeof(var.field) * 8))

int main(void) {
    CR_X86_CPU x86_cpu;
    CR_X64_CPU x64_cpu;
    CR_X87_FPU x87_fpu;
    CR_MMX mmx;
    CR_XMM xmm;

    do_it(CR_X86_CPU, x86_cpu, edx_eax);
    do_it(CR_X86_CPU, x86_cpu, eax);
    do_it(CR_X86_CPU, x86_cpu, ax);
    do_it(CR_X86_CPU, x86_cpu, al);
    do_it(CR_X86_CPU, x86_cpu, ah);
    do_it(CR_X86_CPU, x86_cpu, edx);
    do_it(CR_X86_CPU, x86_cpu, dx);
    do_it(CR_X86_CPU, x86_cpu, dl);
    do_it(CR_X86_CPU, x86_cpu, dh);
    do_it(CR_X86_CPU, x86_cpu, ebx);
    do_it(CR_X86_CPU, x86_cpu, bx);
    do_it(CR_X86_CPU, x86_cpu, bl);
    do_it(CR_X86_CPU, x86_cpu, bh);
    do_it(CR_X86_CPU, x86_cpu, ecx);
    do_it(CR_X86_CPU, x86_cpu, cx);
    do_it(CR_X86_CPU, x86_cpu, cl);
    do_it(CR_X86_CPU, x86_cpu, ch);
    do_it(CR_X86_CPU, x86_cpu, edi);
    do_it(CR_X86_CPU, x86_cpu, di);
    do_it(CR_X86_CPU, x86_cpu, esi);
    do_it(CR_X86_CPU, x86_cpu, si);
    do_it(CR_X86_CPU, x86_cpu, ebp);
    do_it(CR_X86_CPU, x86_cpu, bp);
    do_it(CR_X86_CPU, x86_cpu, esp);
    do_it(CR_X86_CPU, x86_cpu, sp);
    do_it(CR_X86_CPU, x86_cpu, eip);
    do_it(CR_X86_CPU, x86_cpu, ip);
    do_it(CR_X86_CPU, x86_cpu, eflags);
    do_it(CR_X86_CPU, x86_cpu, flags);
    do_it(CR_X86_CPU, x86_cpu, cs);
    do_it(CR_X86_CPU, x86_cpu, ds);
    do_it(CR_X86_CPU, x86_cpu, ss);
    do_it(CR_X86_CPU, x86_cpu, es);
    do_it(CR_X86_CPU, x86_cpu, fs);
    do_it(CR_X86_CPU, x86_cpu, gs);

    do_it(CR_X64_CPU, x64_cpu, rdx_rax);
    do_it(CR_X64_CPU, x64_cpu, rax);
    do_it(CR_X64_CPU, x64_cpu, eax);
    do_it(CR_X64_CPU, x64_cpu, ax);
    do_it(CR_X64_CPU, x64_cpu, al);
    do_it(CR_X64_CPU, x64_cpu, ah);
    do_it(CR_X64_CPU, x64_cpu, rdx);
    do_it(CR_X64_CPU, x64_cpu, edx);
    do_it(CR_X64_CPU, x64_cpu, dx);
    do_it(CR_X64_CPU, x64_cpu, dl);
    do_it(CR_X64_CPU, x64_cpu, dh);
    do_it(CR_X64_CPU, x64_cpu, rbx);
    do_it(CR_X64_CPU, x64_cpu, ebx);
    do_it(CR_X64_CPU, x64_cpu, bx);
    do_it(CR_X64_CPU, x64_cpu, bl);
    do_it(CR_X64_CPU, x64_cpu, bh);
    do_it(CR_X64_CPU, x64_cpu, rcx);
    do_it(CR_X64_CPU, x64_cpu, ecx);
    do_it(CR_X64_CPU, x64_cpu, cx);
    do_it(CR_X64_CPU, x64_cpu, cl);
    do_it(CR_X64_CPU, x64_cpu, ch);
    do_it(CR_X64_CPU, x64_cpu, rdi);
    do_it(CR_X64_CPU, x64_cpu, edi);
    do_it(CR_X64_CPU, x64_cpu, di);
    do_it(CR_X64_CPU, x64_cpu, dil);
    do_it(CR_X64_CPU, x64_cpu, rsi);
    do_it(CR_X64_CPU, x64_cpu, esi);
    do_it(CR_X64_CPU, x64_cpu, si);
    do_it(CR_X64_CPU, x64_cpu, sil);
    do_it(CR_X64_CPU, x64_cpu, rbp);
    do_it(CR_X64_CPU, x64_cpu, ebp);
    do_it(CR_X64_CPU, x64_cpu, bp);
    do_it(CR_X64_CPU, x64_cpu, bpl);
    do_it(CR_X64_CPU, x64_cpu, rsp);
    do_it(CR_X64_CPU, x64_cpu, esp);
    do_it(CR_X64_CPU, x64_cpu, sp);
    do_it(CR_X64_CPU, x64_cpu, spl);
    do_it(CR_X64_CPU, x64_cpu, r8);
    do_it(CR_X64_CPU, x64_cpu, r8d);
    do_it(CR_X64_CPU, x64_cpu, r8w);
    do_it(CR_X64_CPU, x64_cpu, r8l);
    do_it(CR_X64_CPU, x64_cpu, r9);
    do_it(CR_X64_CPU, x64_cpu, r9d);
    do_it(CR_X64_CPU, x64_cpu, r9w);
    do_it(CR_X64_CPU, x64_cpu, r9l);
    do_it(CR_X64_CPU, x64_cpu, r10);
    do_it(CR_X64_CPU, x64_cpu, r10d);
    do_it(CR_X64_CPU, x64_cpu, r10w);
    do_it(CR_X64_CPU, x64_cpu, r10l);
    do_it(CR_X64_CPU, x64_cpu, r11);
    do_it(CR_X64_CPU, x64_cpu, r11d);
    do_it(CR_X64_CPU, x64_cpu, r11w);
    do_it(CR_X64_CPU, x64_cpu, r11l);
    do_it(CR_X64_CPU, x64_cpu, r12);
    do_it(CR_X64_CPU, x64_cpu, r12d);
    do_it(CR_X64_CPU, x64_cpu, r12w);
    do_it(CR_X64_CPU, x64_cpu, r12l);
    do_it(CR_X64_CPU, x64_cpu, r13);
    do_it(CR_X64_CPU, x64_cpu, r13d);
    do_it(CR_X64_CPU, x64_cpu, r13w);
    do_it(CR_X64_CPU, x64_cpu, r13l);
    do_it(CR_X64_CPU, x64_cpu, r14);
    do_it(CR_X64_CPU, x64_cpu, r14d);
    do_it(CR_X64_CPU, x64_cpu, r14w);
    do_it(CR_X64_CPU, x64_cpu, r14l);
    do_it(CR_X64_CPU, x64_cpu, r15);
    do_it(CR_X64_CPU, x64_cpu, r15d);
    do_it(CR_X64_CPU, x64_cpu, r15w);
    do_it(CR_X64_CPU, x64_cpu, r15l);
    do_it(CR_X64_CPU, x64_cpu, rip);
    do_it(CR_X64_CPU, x64_cpu, eip);
    do_it(CR_X64_CPU, x64_cpu, ip);
    do_it(CR_X64_CPU, x64_cpu, rflags);
    do_it(CR_X64_CPU, x64_cpu, eflags);
    do_it(CR_X64_CPU, x64_cpu, flags);
    do_it(CR_X64_CPU, x64_cpu, cs);
    do_it(CR_X64_CPU, x64_cpu, ds);
    do_it(CR_X64_CPU, x64_cpu, ss);
    do_it(CR_X64_CPU, x64_cpu, es);
    do_it(CR_X64_CPU, x64_cpu, fs);
    do_it(CR_X64_CPU, x64_cpu, gs);

    do_it(CR_X87_FPU, x87_fpu, st0);
    do_it(CR_X87_FPU, x87_fpu, st1);
    do_it(CR_X87_FPU, x87_fpu, st2);
    do_it(CR_X87_FPU, x87_fpu, st3);
    do_it(CR_X87_FPU, x87_fpu, st4);
    do_it(CR_X87_FPU, x87_fpu, st5);
    do_it(CR_X87_FPU, x87_fpu, st6);
    do_it(CR_X87_FPU, x87_fpu, st7);
    do_it(CR_X87_FPU, x87_fpu, control);
    do_it(CR_X87_FPU, x87_fpu, status);
    do_it(CR_X87_FPU, x87_fpu, tag);
    do_it(CR_X87_FPU, x87_fpu, instruction);
    do_it(CR_X87_FPU, x87_fpu, operand);

    do_it(CR_MMX, mmx, mm0);
    do_it(CR_MMX, mmx, mm1);
    do_it(CR_MMX, mmx, mm2);
    do_it(CR_MMX, mmx, mm3);
    do_it(CR_MMX, mmx, mm4);
    do_it(CR_MMX, mmx, mm5);
    do_it(CR_MMX, mmx, mm6);
    do_it(CR_MMX, mmx, mm7);

    do_it(CR_XMM, xmm, xmm0);
    do_it(CR_XMM, xmm, xmm1);
    do_it(CR_XMM, xmm, xmm2);
    do_it(CR_XMM, xmm, xmm3);
    do_it(CR_XMM, xmm, xmm4);
    do_it(CR_XMM, xmm, xmm5);
    do_it(CR_XMM, xmm, xmm6);
    do_it(CR_XMM, xmm, xmm7);
}
