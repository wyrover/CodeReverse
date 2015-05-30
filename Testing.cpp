////////////////////////////////////////////////////////////////////////////
// Dumping.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
    void CrDoTest32(CR_ModuleEx& module) {
        bool flag;
        CR_OpCode32 oc1, oc2;
        #if 1
            oc1.Parse("sub eax, eax");
            oc2.Parse("sub $1, eax");
            CR_ParamMatch matches;
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches["$1"].Text() == "eax");
        #endif
    }

    void CrDoTest64(CR_ModuleEx& module) {
        bool flag;
        CR_OpCode64 oc1, oc2;
        #if 1
            oc1.Parse("sub rax, rax");
            oc2.Parse("sub $1, rax");
            CR_ParamMatch matches;
            flag = CrParamPatternMatch(oc1, oc2, matches);
            assert(flag);
            assert(matches["$1"].Text() == "rax");
        #endif
    }
#endif  // def _DEBUG

////////////////////////////////////////////////////////////////////////////
