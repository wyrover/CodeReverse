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
            oc1.Parse("sub eax, eax");
            oc2.Parse("sub $1, eax");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches["$1"].Text() == "eax");
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
            oc1.Parse("sub rax, rax");
            oc2.Parse("sub $1, rax");
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches["$1"].Text() == "rax");
        #endif
        fprintf(stderr, "Tested.\n");
    }
#endif  // def _DEBUG

////////////////////////////////////////////////////////////////////////////
