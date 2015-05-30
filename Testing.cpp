////////////////////////////////////////////////////////////////////////////
// Dumping.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

// TODO: add test code more
#ifdef _DEBUG
    void CrDoTest32(CR_ModuleEx& module) {
        fprintf(stderr, "Testing...\n");
        bool flag;
        CR_OpCode32 oc1, oc2;
        CR_ParamMatch matches;
        #if 1
            matches.clear();
            oc1.Parse("sub eax, ebx");
            oc2.Parse("sub eax, ebx");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches.empty());

            matches.clear();
            oc1.Parse("mov eax, ebx");
            oc2.Parse("mov eax, ecx");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(!flag);

            matches.clear();
            oc1.Parse("add ebx, eax");
            oc2.Parse("add ecx, eax");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(!flag);

            matches.clear();
            oc1.Parse("sub eax, eax");
            oc2.Parse("sub $1, eax");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(matches.size() == 1);
            assert(flag);
            assert(matches["$1"].Text() == "eax");

            matches.clear();
            oc1.Parse("lea eax, [eax]");
            oc2.Parse("lea $0R, [$0R]");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(matches.size() == 1);
            assert(flag);
            assert(matches["$0R"].Text() == "eax");

            matches.clear();
            oc1.Parse("lea edx, [edx+3]");
            oc2.Parse("lea $0R, [$0R+$1N]");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches.size() == 2);
            assert(matches["$0R"].Text() == "edx");
            assert(matches["$1N"].Text() == "0x03");

            matches.clear();
            oc1.Parse("lea edx, [edx+3]");
            oc2.Parse("lea eax, [$0R+$1N]");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(!flag);
        #endif
        fprintf(stderr, "Tested.\n");
    }

    void CrDoTest64(CR_ModuleEx& module) {
        fprintf(stderr, "Testing...\n");
        bool flag;
        CR_OpCode64 oc1, oc2;
        CR_ParamMatch matches;
        #if 1
            matches.clear();
            oc1.Parse("sub rax, rbx");
            oc2.Parse("sub rax, rbx");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches.empty());

            matches.clear();
            oc1.Parse("mov rax, rbx");
            oc2.Parse("mov rax, rcx");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(!flag);

            matches.clear();
            oc1.Parse("add rbx, rax");
            oc2.Parse("add rcx, rax");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(!flag);

            matches.clear();
            oc1.Parse("sub rax, rax");
            oc2.Parse("sub $1, rax");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches.size() == 1);
            assert(matches["$1"].Text() == "rax");

            matches.clear();
            oc1.Parse("lea rax, [rax]");
            oc2.Parse("lea $0R, [$0R]");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches.size() == 1);
            assert(matches["$0R"].Text() == "rax");

            matches.clear();
            oc1.Parse("lea rdx, [rdx+3]");
            oc2.Parse("lea $0R, [$0R+$1N]");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches.size() == 2);
            assert(matches["$0R"].Text() == "rdx");
            assert(matches["$1N"].Text() == "0x03");

            matches.clear();
            oc1.Parse("lea rdx, [rdx+3]");
            oc2.Parse("lea rax, [$0R+$1N]");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(!flag);
        #endif
        fprintf(stderr, "Tested.\n");
    }
#endif  // def _DEBUG

////////////////////////////////////////////////////////////////////////////
