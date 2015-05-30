////////////////////////////////////////////////////////////////////////////
// ModuleEx.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

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
// disasm

BOOL CR_ModuleEx::_PrepareForDisAsm32() {
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

	CreateInfo32();

    if (Info32()->Entrances().size()) {
        return TRUE;
    }

    // register entrances
    auto RVA = RVAOfEntryPoint();
    CR_Addr32 va = VA32FromRVA(RVA);
    Info32()->Entrances().emplace(va);
    {
        auto codefunc = make_shared<CR_CodeFunc32>();
        codefunc->Addr() = va;
        codefunc->Name() = "EntryPoint";
        codefunc->StackArgSizeRange().Set(0);
        codefunc->FuncFlags() |= cr_FF_CDECL;
        Info32()->MapAddrToCodeFunc().emplace(va, codefunc);
        MapRVAToFuncName().emplace(RVA, codefunc->Name());
        MapFuncNameToRVA().emplace(codefunc->Name(), RVA);
    }

    // exporting functions are entrances
    for (auto& e_symbol : ExportSymbols()) {
        va = VA32FromRVA(e_symbol.dwRVA);
        if (!AddressInCode32(va)) {
            continue;
        }

        Info32()->Entrances().emplace(va);
        MapRVAToFuncName().emplace(e_symbol.dwRVA, e_symbol.pszName);
        MapFuncNameToRVA().emplace(e_symbol.pszName, e_symbol.dwRVA);
    }
    return TRUE;
} // CR_ModuleEx::_PrepareForDisAsm32

BOOL CR_ModuleEx::_PrepareForDisAsm64() {
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

	CreateInfo64();

    if (Info64()->Entrances().size()) {
        return TRUE;
    }

    CreateInfo64();

    // register entrances
    auto RVA = RVAOfEntryPoint();
    CR_Addr64 va = VA64FromRVA(RVA);
    Info64()->Entrances().emplace(va);
    {
        auto codefunc = make_shared<CR_CodeFunc64>();
        codefunc->Addr() = va;
        codefunc->Name() = "EntryPoint";
        codefunc->StackArgSizeRange().Set(0);
        Info64()->MapAddrToCodeFunc().emplace(va, codefunc);
        MapRVAToFuncName().emplace(RVA, codefunc->Name());
        MapFuncNameToRVA().emplace(codefunc->Name(), RVA);
    }

    // exporting functions are entrances
    for (auto& e_symbol : ExportSymbols()) {
        va = VA64FromRVA(e_symbol.dwRVA);
        if (!AddressInCode64(va)) {
            continue;
        }

        Info64()->Entrances().emplace(va);
        MapRVAToFuncName().emplace(e_symbol.dwRVA, e_symbol.pszName);
        MapFuncNameToRVA().emplace(e_symbol.pszName, e_symbol.dwRVA);
    }
    return TRUE;
} // CR_ModuleEx::_PrepareForDisAsm64

extern "C"
int32_t disasm(uint8_t *data, char *output, int outbufsize, int segsize,
               int64_t offset, int autosync, uint32_t prefer);

BOOL CR_ModuleEx::_DisAsmAddr32(CR_Addr32 func, CR_Addr32 va) {
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    int len;
    char outbuf[256];
    CR_Addr32 addr;

    // add or retrieve the code function
    auto cf = Info32()->CodeFuncFromAddr(func);
    if (cf == NULL) {
        Info32()->MapAddrToCodeFunc().emplace(func, make_shared<CR_CodeFunc32>());
        cf = Info32()->CodeFuncFromAddr(func);
    }
    assert(cf);
    if (func == va) {
        cf->Addr() = func;
    }

    const REAL_IMAGE_SECTION_HEADER *pCode = CodeSectionHeader();
    assert(pCode);

    DWORD rva = RVAFromVA32(va);
    LPBYTE input = m_pLoadedImage + rva;
    LPBYTE iend = m_pLoadedImage + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend) {
        // add or retrieve op.code
        auto oc = Info32()->OpCodeFromAddr(va);
        if (oc == NULL) {
            Info32()->MapAddrToOpCode().emplace(va, make_shared<CR_OpCode32>());
            oc = Info32()->OpCodeFromAddr(va);
        }
        assert(oc);
        if (oc->FuncAddrs().count(func) > 0)
            break;

        // set op.code address
        oc->Addr() = va;

        // add function address for this op.code
        oc->FuncAddrs().emplace(func);
        if (oc->FuncAddrs().size() > 1) {
            cf->FuncFlags() |= cr_FF_FUNCINFUNC;   // function in function
        }

        // disassemble
        len = disasm(input, outbuf, sizeof(outbuf), 32, va, false, 0);

        // parse insn
        if (!len || input + len > iend) {
            len = 1;
            oc->Name() = "???";
            oc->OpCodeType() = cr_OCT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf->FuncFlags() |= cr_FF_INVALID;
        } else {
            oc->Parse(outbuf);
            #if 0
                auto& opers = oc->Operands();
                for (auto& oper : opers) {
                    if (oper.GetOperandType() == cr_DF_MEMINDEX) {
                        fprintf(stdout,
                            "!!!%s: %s\n",
                            oper.Text().c_str(),
                            oper.ExprAddr().c_str());
                    }
                }
            #endif
        }

        // complement operand size
        oc->DeductOperandSizes();

        // add asm codes to op.code
        if (oc->Codes().empty()) {
            for (int i = 0; i < len; ++i)
                oc->Codes().emplace_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (oc->OpCodeType()) {
        case cr_OCT_JCC:    // conditional jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_DF_IMM:
                addr = oc->Operand(0)->Value32();
                cf->Jumpers().emplace(va);
                cf->Jumpees().emplace(addr);
                break;

            default: break;
            }
            break;

        case cr_OCT_JMP:    // jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_DF_IMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    addr = oc->Operand(0)->Value32();
                    Info32()->Entrances().emplace(addr);
                    cf->Callers().emplace(addr);

                    auto newcf = Info32()->CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        Info32()->MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc32>());
                        newcf = Info32()->CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().emplace(func);
                } else {
                    addr = oc->Operand(0)->Value32();
                    cf->Jumpers().emplace(va);
                    cf->Jumpees().emplace(addr);
                }
                break;

            case cr_DF_MEMIMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case cr_OCT_CALL:   // call
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_DF_IMM:
                // function call
                addr = oc->Operand(0)->Value32();
                Info32()->Entrances().emplace(addr);
                cf->Callees().emplace(addr);
                {
                    auto newcf = Info32()->CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        Info32()->MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc32>());
                        newcf = Info32()->CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callers().emplace(func);
                }
                break;

            default:
                break;
            }
            break;

        case cr_OCT_RETURN: // return
            if (oc->Operands().size() && oc->Operand(0)->GetOperandType() == cr_DF_IMM) {
                // func is __stdcall
                cf->FuncFlags() |= cr_FF_STDCALL;
                cf->StackArgSizeRange().Set(oc->Operand(0)->Value32());
            } else {
                // func is not __stdcall
                cf->FuncFlags() |= cr_FF_NOTSTDCALL;
                if (func == va) {
                    cf->FuncFlags() |= cr_FF_RETURNONLY | cr_FF_CDECL;
                }
            }
            cf->Exits().insert(va);
            bBreak = TRUE;
            break;

        default:
            break;
        }

        if (bBreak)
            break;

        // move to next position
        input += len;
        va += len;
    }

    return TRUE;
} // CR_ModuleEx::_DisAsmAddr32

BOOL CR_ModuleEx::_DisAsmAddr64(CR_Addr64 func, CR_Addr64 va) {
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // calculate
    int len;
    char outbuf[256];
    CR_Addr64 addr;

    // add or retrieve the code function
    auto cf = Info64()->CodeFuncFromAddr(func);
    if (cf == NULL) {
        Info64()->MapAddrToCodeFunc().emplace(func, make_shared<CR_CodeFunc64>());
        cf = Info64()->CodeFuncFromAddr(func);
    }
    assert(cf);
    if (func == va) {
        cf->Addr() = func;
    }

    auto pCode = CodeSectionHeader();
    assert(pCode);

    DWORD rva = RVAFromVA64(va);
    LPBYTE input = m_pLoadedImage + rva;
    LPBYTE iend = m_pLoadedImage + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend) {
        // add or retrieve op.code
        auto oc = Info64()->OpCodeFromAddr(va);
        if (oc == NULL) {
            Info64()->MapAddrToOpCode().emplace(va, make_shared<CR_OpCode64>());
            oc = Info64()->OpCodeFromAddr(va);
        }
        assert(oc);
        if (oc->FuncAddrs().count(func) > 0)
            break;

        // set op.code address
        oc->Addr() = va;

        // add function address for this op.code
        oc->FuncAddrs().emplace(func);
        if (oc->FuncAddrs().size() > 1) {
            cf->FuncFlags() |= cr_FF_FUNCINFUNC;   // function in function
        }

        // disassemble
        len = disasm(input, outbuf, sizeof(outbuf), 64, va, false, 0);

        // parse insn
        if (!len || input + len > iend) {
            len = 1;
            oc->Name() = "???";
            oc->OpCodeType() = cr_OCT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf->FuncFlags() |= cr_FF_INVALID;
        } else {
            oc->Parse(outbuf);
            #if 0
                auto& opers = oc->Operands();
                for (auto& oper : opers) {
                    if (oper.GetOperandType() == cr_DF_MEMINDEX) {
                        fprintf(stdout,
                            "!!!%s: %s\n",
                            oper.Text().c_str(),
                            oper.ExprAddr().c_str());
                    }
                }
            #endif
        }

        // complement operand size
        oc->DeductOperandSizes();

        // add asm codes to op.code
        if (oc->Codes().empty()) {
            for (int i = 0; i < len; ++i)
                oc->Codes().emplace_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (oc->OpCodeType()) {
        case cr_OCT_JCC:    // conditional jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_DF_IMM:
                addr = oc->Operand(0)->Value64();
                cf->Jumpers().emplace(va);
                cf->Jumpees().emplace(addr);
                break;

            default:
                break;
            }
            break;

        case cr_OCT_JMP:    // jump
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_DF_IMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    addr = oc->Operand(0)->Value64();
                    Info64()->Entrances().emplace(addr);
                    cf->Callers().emplace(addr);

                    auto newcf = Info64()->CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        Info64()->MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc64>());
                        newcf = Info64()->CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().emplace(func);
                } else {
                    addr = oc->Operand(0)->Value64();
                    cf->Jumpers().emplace(va);
                    cf->Jumpees().emplace(addr);
                }
                break;

            case cr_DF_MEMIMM:
                if (func == va) {
                    // func is jumper
                    cf->FuncFlags() |= cr_FF_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case cr_OCT_CALL:   // call
            switch (oc->Operand(0)->GetOperandType()) {
            case cr_DF_IMM:
                // function call
                addr = oc->Operand(0)->Value64();
                Info64()->Entrances().emplace(addr);
                cf->Callees().emplace(addr);
                {
                    auto newcf = Info64()->CodeFuncFromAddr(addr);
                    if (newcf == NULL) {
                        Info64()->MapAddrToCodeFunc().emplace(
                            addr, make_shared<CR_CodeFunc64>());
                        newcf = Info64()->CodeFuncFromAddr(addr);
                    }
                    newcf->Addr() = addr;
                    newcf->Callers().emplace(func);
                }
                break;

            default:
                break;
            }
            break;

        case cr_OCT_RETURN: // return
            if (oc->Operands().size() && oc->Operand(0)->GetOperandType() == cr_DF_IMM) {
                cf->StackArgSizeRange().Set(oc->Operand(0)->Value64());
            } else {
                if (func == va) {
                    cf->FuncFlags() |= cr_FF_RETURNONLY;
                }
            }
            cf->Exits().insert(va);
            bBreak = TRUE;
            break;

        default:
            break;
        }

        if (bBreak)
            break;

        // move to next position
        input += len;
        va += len;
    }

    return TRUE;
} // CR_ModuleEx::_DisAsmAddr64

BOOL CR_ModuleEx::DisAsm32() {
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

	CreateInfo32();

    if (Info32()->Entrances().empty()) {
        _PrepareForDisAsm32();
    }

    // disasm entrances
    bool needs_retry;
    do {
        // NOTE: Info32()->Entrances() may grow in _DisAsmAddr32
        needs_retry = false;
        CR_Addr32Set addrs = Info32()->Entrances();
        for (auto addr : addrs) {
            // check func stage
            auto stage = Info32()->GetFuncStage(addr);
            if (stage > 0) {
                continue;
            }

            needs_retry = true;
            _DisAsmAddr32(addr, addr);

            // get code func
            auto cf = Info32()->CodeFuncFromAddr(addr);
            assert(cf);

            // recurse all jumpees
            // NOTE: cf->Jumpees() may grow in _DisAsmAddr32
            CR_Addr32Set jumpees;
            do {
                jumpees = cf->Jumpees();
                for (auto jumpee : jumpees) {
                    _DisAsmAddr32(addr, jumpee);
                }
            } while (jumpees.size() < cf->Jumpees().size());
        }
    } while (needs_retry);

    return TRUE;
} // CR_ModuleEx::DisAsm32

BOOL CR_ModuleEx::DisAsm64() {
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

	CreateInfo64();

    if (Info64()->Entrances().empty()) {
        _PrepareForDisAsm64();
    }

    // disasm entrances
    bool needs_retry;
    do {
        // NOTE: Info64()->Entrances() may grow in _DisAsmAddr64
        needs_retry = false;
        CR_Addr64Set addrs = Info64()->Entrances();
        for (auto addr : addrs) {
            // check func stage
            auto stage = Info64()->GetFuncStage(addr);
            if (stage > 0) {
                continue;
            }

            needs_retry = true;
            _DisAsmAddr64(addr, addr);

            // get code func
            auto cf = Info64()->CodeFuncFromAddr(addr);
            assert(cf);

            // recurse all jumpees
            // NOTE: cf->Jumpees() may grow in _DisAsmAddr64
            CR_Addr64Set jumpees;
            do {
                jumpees = cf->Jumpees();
                for (auto jumpee : jumpees) {
                    _DisAsmAddr64(addr, jumpee);
                }
            } while (jumpees.size() < cf->Jumpees().size());
        }
    } while (needs_retry);

    return TRUE;
} // CR_ModuleEx::DisAsm64

////////////////////////////////////////////////////////////////////////////
// create flow graph

void CR_ModuleEx::CreateFlowGraph32(CR_Addr32 entrance) {
    auto cf = Info32()->CodeFuncFromAddr(entrance);
    assert(cf);

    CR_Addr32Set leaders;
    leaders.insert(entrance);

    // insert jumpees
    auto& jumpees = cf->Jumpees();
    leaders.insert(jumpees.begin(), jumpees.end());

    // insert exits' next
    auto& exits = cf->Exits();
    for (auto addr : exits) {
        auto op_code = Info32()->OpCodeFromAddr(addr);
        auto size = op_code->Codes().size();
        auto next_addr = static_cast<CR_Addr32>(addr + size);
        leaders.insert(next_addr);
    }

    // insert jumpers next
    auto& jumpers = cf->Jumpers();
    for (auto addr : jumpers) {
        auto op_code = Info32()->OpCodeFromAddr(addr);
        auto size = op_code->Codes().size();
        auto next_addr = static_cast<CR_Addr32>(addr + size);
        leaders.insert(next_addr);
    }

    // sort
    std::vector<CR_Addr32> vecLeaders(leaders.begin(), leaders.end());
    std::sort(vecLeaders.begin(), vecLeaders.end());

    // store leaders
    cf->Leaders() = std::move(leaders);

    const size_t size = vecLeaders.size() - 1;
    for (size_t i = 0; i < size; ++i) {
        // for every pair of two adjacent leaders
        auto addr1 = vecLeaders[i], addr2 = vecLeaders[i + 1];
        // prepare a basic block
        CR_BasicBlock32 block;
        block.m_addr = addr1;
        CR_Addr32 next_addr = cr_invalid_addr32;
        for (auto addr = addr1; addr < addr2; ) {
            if (cf->Leaders().count(addr)) {
                // set label at each leader
                block.AddLeaderLabel(addr);
            }
            // op.code from addr
            auto op_code = Info32()->OpCodeFromAddr(addr);
            if (op_code == NULL) {
                break;
            }
            auto type = op_code->OpCodeType();
            if (type == cr_OCT_JMP) {
                // jump
                auto oper = op_code->Operand(0);
                if (oper->GetOperandType() == cr_DF_IMM) {
                    block.m_jump_to = oper->Value32();  // jump to
                }
                next_addr = cr_invalid_addr32;
            } else if (type == cr_OCT_RETURN) {
                next_addr = cr_invalid_addr32;
            } else if (type == cr_OCT_JCC || type == cr_OCT_LOOP) {
                // conditional jump or loop
                auto oper = op_code->Operand(0);
                if (oper->GetOperandType() == cr_DF_IMM) {
                    block.m_jump_to = oper->Value32();  // jump to
                }
                block.m_cond_code = op_code->CondCode();
                next_addr =
                    static_cast<CR_Addr32>(addr + op_code->Codes().size());
            } else {
                next_addr =
                    static_cast<CR_Addr32>(addr + op_code->Codes().size());
            }
            // add op.code
            block.m_icodes.emplace_back(*op_code);
            // go to next addr
            addr += static_cast<CR_Addr32>(op_code->Codes().size());
        }
        // add label at last
        block.AddLeaderLabel(addr2);
        // set next addr
        block.m_next_addr = next_addr;
        // add block
        cf->BasicBlocks().emplace_back(block);
    }
}

void CR_ModuleEx::CreateFlowGraph64(CR_Addr64 entrance) {
    auto cf = Info64()->CodeFuncFromAddr(entrance);
    assert(cf);

    CR_Addr64Set leaders;
    leaders.insert(entrance);

    // insert jumpees
    auto& jumpees = cf->Jumpees();
    leaders.insert(jumpees.begin(), jumpees.end());

    // insert exits' next
    auto& exits = cf->Exits();
    for (auto addr : exits) {
        auto op_code = Info64()->OpCodeFromAddr(addr);
        auto size = op_code->Codes().size();
        auto next_addr = static_cast<CR_Addr64>(addr + size);
        leaders.insert(next_addr);
    }

    // insert jumpers' next
    auto& jumpers = cf->Jumpers();
    for (auto addr : jumpers) {
        auto op_code = Info64()->OpCodeFromAddr(addr);
        auto size = op_code->Codes().size();
        auto next_addr = static_cast<CR_Addr64>(addr + size);
        leaders.insert(next_addr);
    }

    // sort
    std::vector<CR_Addr64> vecLeaders(leaders.begin(), leaders.end());
    std::sort(vecLeaders.begin(), vecLeaders.end());

    // store leaders
    cf->Leaders() = std::move(leaders);

    const size_t size = vecLeaders.size() - 1;
    for (size_t i = 0; i < size; ++i) {
        // for every pair of two adjacent leaders
        auto addr1 = vecLeaders[i], addr2 = vecLeaders[i + 1];
        // prepare a basic block
        CR_BasicBlock64 block;
        block.m_addr = addr1;
        CR_Addr64 next_addr = cr_invalid_addr64;
        for (auto addr = addr1; addr < addr2; ) {
            if (cf->Leaders().count(addr)) {
                // set label at each leader
                block.AddLeaderLabel(addr);
            }
            // op.code from addr
            auto op_code = Info64()->OpCodeFromAddr(addr);
            if (op_code == NULL) {
                break;
            }
            auto type = op_code->OpCodeType();
            if (type == cr_OCT_JMP) {
                // jump
                auto oper = op_code->Operand(0);
                if (oper->GetOperandType() == cr_DF_IMM) {
                    block.m_jump_to = oper->Value64();  // jump to
                }
                next_addr = cr_invalid_addr64;
            } else if (type == cr_OCT_RETURN) {
                next_addr = cr_invalid_addr64;
            } else if (type == cr_OCT_JCC || type == cr_OCT_LOOP) {
                // conditional jump or loop
                auto oper = op_code->Operand(0);
                if (oper->GetOperandType() == cr_DF_IMM) {
                    block.m_jump_to = oper->Value64();  // jump to
                }
                block.m_cond_code = op_code->CondCode();
                next_addr =
                    static_cast<CR_Addr64>(addr + op_code->Codes().size());
            } else {
                next_addr =
                    static_cast<CR_Addr64>(addr + op_code->Codes().size());
            }
            // add op.code
            block.m_icodes.emplace_back(*op_code);
            // go to next addr
            addr += static_cast<CR_Addr64>(op_code->Codes().size());
        }
        // add label at last
        block.AddLeaderLabel(addr2);
        // set next addr
        block.m_next_addr = next_addr;
        // add block
        cf->BasicBlocks().emplace_back(block);
    }
}

////////////////////////////////////////////////////////////////////////////
// decompiling

BOOL CR_ModuleEx::Decompile32() {
    CR_Addr32Set entrances = Info32()->Entrances();
    for (auto entrance : entrances) {
        CreateFlowGraph32(entrance);
    }
    return FALSE;
}

BOOL CR_ModuleEx::Decompile64() {
    CR_Addr64Set entrances = Info64()->Entrances();
    for (auto entrance : entrances) {
        CreateFlowGraph64(entrance);
    }
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
