#ifndef CR_MODULEEX_H_
#define CR_MODULEEX_H_

////////////////////////////////////////////////////////////////////////////
// ModuleEx.h
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

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

class CR_ModuleEx : public CR_Module {
public:
    CR_ModuleEx();
    virtual ~CR_ModuleEx();

public:
    BOOL DisAsm32();
    BOOL DisAsm64();

    BOOL Decompile32();
    BOOL Decompile64();

    BOOL DumpDisAsm32(std::FILE *fp);
    BOOL DumpDisAsm64(std::FILE *fp);

    BOOL DumpDecompile32(std::FILE *fp);
    BOOL DumpDecompile64(std::FILE *fp);

    void CreateFlowGraph32(CR_Addr32 entrance);
    void CreateFlowGraph64(CR_Addr64 entrance);

public:
    shared_ptr<CR_DecompInfo32>&        Info32();
    shared_ptr<CR_DecompInfo64>&        Info64();
    const shared_ptr<CR_DecompInfo32>&  Info32() const;
    const shared_ptr<CR_DecompInfo64>&  Info64() const;

protected:
    shared_ptr<CR_DecompInfo32>     m_pinfo32;
    shared_ptr<CR_DecompInfo64>     m_pinfo64;

    BOOL _PrepareForDisAsm32();
    BOOL _PrepareForDisAsm64();
    BOOL _DisAsmAddr32(CR_Addr32 func, CR_Addr32 va);
    BOOL _DisAsmAddr64(CR_Addr64 func, CR_Addr64 va);
    BOOL _DumpDisAsmFunc32(std::FILE *fp, CR_Addr32 func);
    BOOL _DumpDisAsmFunc64(std::FILE *fp, CR_Addr64 func);
    bool _CreateInfo32();
    bool _CreateInfo64();
}; // class CR_ModuleEx

////////////////////////////////////////////////////////////////////////////

#ifdef _DEBUG
    void CrDoTest32(CR_ModuleEx& module);
    void CrDoTest64(CR_ModuleEx& module);
#endif  // def _DEBUG

// inline functions
#include "ModuleEx_inl.h"

#endif  // ndef CR_MODULEEX_H_
