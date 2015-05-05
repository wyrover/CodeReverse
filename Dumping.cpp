////////////////////////////////////////////////////////////////////////////
// Dumping.cpp
// Copyright (C) 2013-2015 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

const char *CrGetTimeStampString(DWORD TimeStamp) {
    std::time_t t;
    char *p;
    std::size_t len;
    if (TimeStamp == 0)
        return "NULL";

    t = static_cast<time_t>(TimeStamp);
    p = std::asctime(std::gmtime(&t));
    len = std::strlen(p);
    if (len > 0 && p[len - 1] == '\n')
        p[len - 1] = '\0';
    return p;
} // CrGetTimeStampString

const char *CrGetMachineString(WORD Machine) {
#ifndef IMAGE_FILE_MACHINE_SH3DSP
    #define IMAGE_FILE_MACHINE_SH3DSP 0x01A3
#endif
#ifndef IMAGE_FILE_MACHINE_SH5
    #define IMAGE_FILE_MACHINE_SH5 0x01A8
#endif
#ifndef IMAGE_FILE_MACHINE_ARMV7
    #define IMAGE_FILE_MACHINE_ARMV7 0x01C4
#endif
#ifndef IMAGE_FILE_MACHINE_AM33
    #define IMAGE_FILE_MACHINE_AM33 0x01D3
#endif
#ifndef IMAGE_FILE_MACHINE_POWERPCFP
    #define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#endif
#ifndef IMAGE_FILE_MACHINE_TRICORE
    #define IMAGE_FILE_MACHINE_TRICORE 0x0520
#endif
#ifndef IMAGE_FILE_MACHINE_CEF
    #define IMAGE_FILE_MACHINE_CEF 0x0CEF
#endif
#ifndef IMAGE_FILE_MACHINE_EBC
    #define IMAGE_FILE_MACHINE_EBC 0x0EBC
#endif
#ifndef IMAGE_FILE_MACHINE_AMD64
    #define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_M32R
    #define IMAGE_FILE_MACHINE_M32R 0x9041
#endif
#ifndef IMAGE_FILE_MACHINE_CEE
    #define IMAGE_FILE_MACHINE_CEE 0xC0EE
#endif
    switch(Machine) {
    case IMAGE_FILE_MACHINE_UNKNOWN: return "IMAGE_FILE_MACHINE_UNKNOWN";
    case IMAGE_FILE_MACHINE_I386: return "IMAGE_FILE_MACHINE_I386";
    case IMAGE_FILE_MACHINE_R3000: return "IMAGE_FILE_MACHINE_R3000";
    case IMAGE_FILE_MACHINE_R4000: return "IMAGE_FILE_MACHINE_R4000";
    case IMAGE_FILE_MACHINE_R10000: return "IMAGE_FILE_MACHINE_R10000";
    case IMAGE_FILE_MACHINE_WCEMIPSV2: return "IMAGE_FILE_MACHINE_WCEMIPSV2";
    case IMAGE_FILE_MACHINE_ALPHA: return "IMAGE_FILE_MACHINE_ALPHA";
    case IMAGE_FILE_MACHINE_SH3: return "IMAGE_FILE_MACHINE_SH3";
    case IMAGE_FILE_MACHINE_SH3DSP: return "IMAGE_FILE_MACHINE_SH3DSP";
    case IMAGE_FILE_MACHINE_SH3E: return "IMAGE_FILE_MACHINE_SH3E";
    case IMAGE_FILE_MACHINE_SH4: return "IMAGE_FILE_MACHINE_SH4";
    case IMAGE_FILE_MACHINE_SH5: return "IMAGE_FILE_MACHINE_SH5";
    case IMAGE_FILE_MACHINE_ARM: return "IMAGE_FILE_MACHINE_ARM";
    case IMAGE_FILE_MACHINE_ARMV7: return "IMAGE_FILE_MACHINE_ARMV7";
    case IMAGE_FILE_MACHINE_THUMB: return "IMAGE_FILE_MACHINE_THUMB";
    case IMAGE_FILE_MACHINE_AM33: return "IMAGE_FILE_MACHINE_AM33";
    case IMAGE_FILE_MACHINE_POWERPC: return "IMAGE_FILE_MACHINE_POWERPC";
    case IMAGE_FILE_MACHINE_POWERPCFP: return "IMAGE_FILE_MACHINE_POWERPCFP";
    case IMAGE_FILE_MACHINE_IA64: return "IMAGE_FILE_MACHINE_IA64";
    case IMAGE_FILE_MACHINE_MIPS16: return "IMAGE_FILE_MACHINE_MIPS16";
    case IMAGE_FILE_MACHINE_ALPHA64: return "IMAGE_FILE_MACHINE_ALPHA64";
    case IMAGE_FILE_MACHINE_MIPSFPU: return "IMAGE_FILE_MACHINE_MIPSFPU";
    case IMAGE_FILE_MACHINE_MIPSFPU16: return "IMAGE_FILE_MACHINE_MIPSFPU16";
    case IMAGE_FILE_MACHINE_TRICORE: return "IMAGE_FILE_MACHINE_TRICORE";
    case IMAGE_FILE_MACHINE_CEF: return "IMAGE_FILE_MACHINE_CEF";
    case IMAGE_FILE_MACHINE_EBC: return "IMAGE_FILE_MACHINE_EBC";
    case IMAGE_FILE_MACHINE_AMD64: return "IMAGE_FILE_MACHINE_AMD64";
    case IMAGE_FILE_MACHINE_M32R: return "IMAGE_FILE_MACHINE_M32R";
    case IMAGE_FILE_MACHINE_CEE: return "IMAGE_FILE_MACHINE_CEE";
    default: return "Unknown Machine";
    }
} // CrGetMachineString

const char *CrGetFileCharacteristicsString(WORD w) {
    static char buf[512];
    buf[0] = 0;
    if (IMAGE_FILE_RELOCS_STRIPPED & w) strcat(buf, "IMAGE_FILE_RELOCS_STRIPPED ");
    if (IMAGE_FILE_EXECUTABLE_IMAGE & w) strcat(buf, "IMAGE_FILE_EXECUTABLE_IMAGE ");
    if (IMAGE_FILE_LINE_NUMS_STRIPPED & w) strcat(buf, "IMAGE_FILE_LINE_NUMS_STRIPPED ");
    if (IMAGE_FILE_LOCAL_SYMS_STRIPPED & w) strcat(buf, "IMAGE_FILE_LOCAL_SYMS_STRIPPED ");
    if (IMAGE_FILE_AGGRESIVE_WS_TRIM & w) strcat(buf, "IMAGE_FILE_AGGRESIVE_WS_TRIM ");
    if (IMAGE_FILE_LARGE_ADDRESS_AWARE & w) strcat(buf, "IMAGE_FILE_LARGE_ADDRESS_AWARE ");
    if (IMAGE_FILE_BYTES_REVERSED_LO & w) strcat(buf, "IMAGE_FILE_BYTES_REVERSED_LO ");
    if (IMAGE_FILE_32BIT_MACHINE & w) strcat(buf, "IMAGE_FILE_32BIT_MACHINE ");
    if (IMAGE_FILE_DEBUG_STRIPPED & w) strcat(buf, "IMAGE_FILE_DEBUG_STRIPPED ");
    if (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP & w) strcat(buf, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ");
    if (IMAGE_FILE_NET_RUN_FROM_SWAP & w) strcat(buf, "IMAGE_FILE_NET_RUN_FROM_SWAP ");
    if (IMAGE_FILE_SYSTEM & w) strcat(buf, "IMAGE_FILE_SYSTEM ");
    if (IMAGE_FILE_DLL & w) strcat(buf, "IMAGE_FILE_DLL ");
    if (IMAGE_FILE_UP_SYSTEM_ONLY & w) strcat(buf, "IMAGE_FILE_UP_SYSTEM_ONLY ");
    if (IMAGE_FILE_BYTES_REVERSED_HI & w) strcat(buf, "IMAGE_FILE_BYTES_REVERSED_HI ");
    if (buf[0])
        buf[strlen(buf) - 1] = 0;
    return buf;
} // CrGetFileCharacteristicsString

const char *CrGetSectionFlagsString(DWORD dw) {
#ifndef IMAGE_SCN_TYPE_DSECT
    #define IMAGE_SCN_TYPE_DSECT 0x00000001
#endif
#ifndef IMAGE_SCN_TYPE_NOLOAD
    #define IMAGE_SCN_TYPE_NOLOAD 0x00000002
#endif
#ifndef IMAGE_SCN_TYPE_GROUP
    #define IMAGE_SCN_TYPE_GROUP 0x00000004
#endif
#ifndef IMAGE_SCN_TYPE_NO_PAD
    #define IMAGE_SCN_TYPE_NO_PAD 0x00000008
#endif
#ifndef IMAGE_SCN_TYPE_COPY
    #define IMAGE_SCN_TYPE_COPY 0x00000010
#endif
#ifndef IMAGE_SCN_CNT_CODE
    #define IMAGE_SCN_CNT_CODE 0x00000020
#endif
#ifndef IMAGE_SCN_CNT_INITIALIZED_DATA
    #define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#endif
#ifndef IMAGE_SCN_CNT_UNINITIALIZED_DATA
    #define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#endif
#ifndef IMAGE_SCN_LNK_OTHER
    #define IMAGE_SCN_LNK_OTHER 0x00000100
#endif
#ifndef IMAGE_SCN_LNK_INFO
    #define IMAGE_SCN_LNK_INFO 0x00000200
#endif
#ifndef IMAGE_SCN_TYPE_OVER
    #define IMAGE_SCN_TYPE_OVER 0x00000400
#endif
#ifndef IMAGE_SCN_LNK_REMOVE
    #define IMAGE_SCN_LNK_REMOVE 0x00000800
#endif
#ifndef IMAGE_SCN_LNK_COMDAT
    #define IMAGE_SCN_LNK_COMDAT 0x00001000
#endif
#ifndef IMAGE_SCN_MEM_PROTECTED
    #define IMAGE_SCN_MEM_PROTECTED 0x00004000
#endif
#ifndef IMAGE_SCN_NO_DEFER_SPEC_EXC
    #define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
#endif
#ifndef IMAGE_SCN_GPREL
    #define IMAGE_SCN_GPREL 0x00008000
#endif
#ifndef IMAGE_SCN_MEM_FARDATA
    #define IMAGE_SCN_MEM_FARDATA 0x00008000
#endif
#ifndef IMAGE_SCN_MEM_SYSHEAP
    #define IMAGE_SCN_MEM_SYSHEAP 0x00010000
#endif
#ifndef IMAGE_SCN_MEM_PURGEABLE
    #define IMAGE_SCN_MEM_PURGEABLE 0x00020000
#endif
#ifndef IMAGE_SCN_MEM_16BIT
    #define IMAGE_SCN_MEM_16BIT 0x00020000
#endif
#ifndef IMAGE_SCN_MEM_LOCKED
    #define IMAGE_SCN_MEM_LOCKED 0x00040000
#endif
#ifndef IMAGE_SCN_MEM_PRELOAD
    #define IMAGE_SCN_MEM_PRELOAD 0x00080000
#endif
#ifndef IMAGE_SCN_ALIGN_1BYTES
    #define IMAGE_SCN_ALIGN_1BYTES 0x00100000
#endif
#ifndef IMAGE_SCN_ALIGN_2BYTES
    #define IMAGE_SCN_ALIGN_2BYTES 0x00200000
#endif
#ifndef IMAGE_SCN_ALIGN_4BYTES
    #define IMAGE_SCN_ALIGN_4BYTES 0x00300000
#endif
#ifndef IMAGE_SCN_ALIGN_8BYTES
    #define IMAGE_SCN_ALIGN_8BYTES 0x00400000
#endif
#ifndef IMAGE_SCN_ALIGN_16BYTES
    #define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#endif
#ifndef IMAGE_SCN_ALIGN_32BYTES
    #define IMAGE_SCN_ALIGN_32BYTES 0x00600000
#endif
#ifndef IMAGE_SCN_ALIGN_64BYTES
    #define IMAGE_SCN_ALIGN_64BYTES 0x00700000
#endif
#ifndef IMAGE_SCN_ALIGN_128BYTES
    #define IMAGE_SCN_ALIGN_128BYTES 0x00800000
#endif
#ifndef IMAGE_SCN_ALIGN_256BYTES
    #define IMAGE_SCN_ALIGN_256BYTES 0x00900000
#endif
#ifndef IMAGE_SCN_ALIGN_512BYTES
    #define IMAGE_SCN_ALIGN_512BYTES 0x00A00000
#endif
#ifndef IMAGE_SCN_ALIGN_1024BYTES
    #define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000
#endif
#ifndef IMAGE_SCN_ALIGN_2048BYTES
    #define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000
#endif
#ifndef IMAGE_SCN_ALIGN_4096BYTES
    #define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
#endif
#ifndef IMAGE_SCN_ALIGN_8192BYTES
    #define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000
#endif
#ifndef IMAGE_SCN_LNK_NRELOC_OVFL
    #define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
#endif
#ifndef IMAGE_SCN_MEM_DISCARDABLE
    #define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#endif
#ifndef IMAGE_SCN_MEM_NOT_CACHED
    #define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#endif
#ifndef IMAGE_SCN_MEM_NOT_PAGED
    #define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#endif
#ifndef IMAGE_SCN_MEM_SHARED
    #define IMAGE_SCN_MEM_SHARED 0x10000000
#endif
#ifndef IMAGE_SCN_MEM_EXECUTE
    #define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif
#ifndef IMAGE_SCN_MEM_READ
    #define IMAGE_SCN_MEM_READ 0x40000000
#endif
#ifndef IMAGE_SCN_MEM_WRITE
    #define IMAGE_SCN_MEM_WRITE 0x80000000
#endif

    static char buf[512];
    buf[0] = 0;

    if (IMAGE_SCN_TYPE_DSECT & dw) strcat(buf, "IMAGE_SCN_TYPE_DSECT ");
    if (IMAGE_SCN_TYPE_NOLOAD & dw) strcat(buf, "IMAGE_SCN_TYPE_NOLOAD ");
    if (IMAGE_SCN_TYPE_GROUP & dw) strcat(buf, "IMAGE_SCN_TYPE_GROUP ");
    if (IMAGE_SCN_TYPE_NO_PAD & dw) strcat(buf, "IMAGE_SCN_TYPE_NO_PAD ");
    if (IMAGE_SCN_TYPE_COPY & dw) strcat(buf, "IMAGE_SCN_TYPE_COPY ");
    if (IMAGE_SCN_CNT_CODE & dw) strcat(buf, "IMAGE_SCN_CNT_CODE ");
    if (IMAGE_SCN_CNT_INITIALIZED_DATA & dw) strcat(buf, "IMAGE_SCN_CNT_INITIALIZED_DATA ");
    if (IMAGE_SCN_CNT_UNINITIALIZED_DATA & dw) strcat(buf, "IMAGE_SCN_CNT_UNINITIALIZED_DATA ");
    if (IMAGE_SCN_LNK_OTHER & dw) strcat(buf, "IMAGE_SCN_LNK_OTHER ");
    if (IMAGE_SCN_LNK_INFO & dw) strcat(buf, "IMAGE_SCN_LNK_INFO ");
    if (IMAGE_SCN_TYPE_OVER & dw) strcat(buf, "IMAGE_SCN_TYPE_OVER ");
    if (IMAGE_SCN_LNK_REMOVE & dw) strcat(buf, "IMAGE_SCN_LNK_REMOVE ");
    if (IMAGE_SCN_LNK_COMDAT & dw) strcat(buf, "IMAGE_SCN_LNK_COMDAT ");
    if (IMAGE_SCN_MEM_PROTECTED & dw) strcat(buf, "IMAGE_SCN_MEM_PROTECTED ");
    if (IMAGE_SCN_NO_DEFER_SPEC_EXC & dw) strcat(buf, "IMAGE_SCN_NO_DEFER_SPEC_EXC ");
    if (IMAGE_SCN_GPREL & dw) strcat(buf, "IMAGE_SCN_GPREL ");
    if (IMAGE_SCN_MEM_FARDATA & dw) strcat(buf, "IMAGE_SCN_MEM_FARDATA ");
    if (IMAGE_SCN_MEM_SYSHEAP & dw) strcat(buf, "IMAGE_SCN_MEM_SYSHEAP ");
    if (IMAGE_SCN_MEM_PURGEABLE & dw) strcat(buf, "IMAGE_SCN_MEM_PURGEABLE ");
    if (IMAGE_SCN_MEM_16BIT & dw) strcat(buf, "IMAGE_SCN_MEM_16BIT ");
    if (IMAGE_SCN_MEM_LOCKED & dw) strcat(buf, "IMAGE_SCN_MEM_LOCKED ");
    if (IMAGE_SCN_MEM_PRELOAD & dw) strcat(buf, "IMAGE_SCN_MEM_PRELOAD ");
    if (IMAGE_SCN_ALIGN_1BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_1BYTES ");
    if (IMAGE_SCN_ALIGN_2BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_2BYTES ");
    if (IMAGE_SCN_ALIGN_4BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_4BYTES ");
    if (IMAGE_SCN_ALIGN_8BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_8BYTES ");
    if (IMAGE_SCN_ALIGN_16BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_16BYTES ");
    if (IMAGE_SCN_ALIGN_32BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_32BYTES ");
    if (IMAGE_SCN_ALIGN_64BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_64BYTES ");
    if (IMAGE_SCN_ALIGN_128BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_128BYTES ");
    if (IMAGE_SCN_ALIGN_256BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_256BYTES ");
    if (IMAGE_SCN_ALIGN_512BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_512BYTES ");
    if (IMAGE_SCN_ALIGN_1024BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_1024BYTES ");
    if (IMAGE_SCN_ALIGN_2048BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_2048BYTES ");
    if (IMAGE_SCN_ALIGN_4096BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_4096BYTES ");
    if (IMAGE_SCN_ALIGN_8192BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_8192BYTES ");
    if (IMAGE_SCN_LNK_NRELOC_OVFL & dw) strcat(buf, "IMAGE_SCN_LNK_NRELOC_OVFL ");
    if (IMAGE_SCN_MEM_DISCARDABLE & dw) strcat(buf, "IMAGE_SCN_MEM_DISCARDABLE ");
    if (IMAGE_SCN_MEM_NOT_CACHED & dw) strcat(buf, "IMAGE_SCN_MEM_NOT_CACHED ");
    if (IMAGE_SCN_MEM_NOT_PAGED & dw) strcat(buf, "IMAGE_SCN_MEM_NOT_PAGED ");
    if (IMAGE_SCN_MEM_SHARED & dw) strcat(buf, "IMAGE_SCN_MEM_SHARED ");
    if (IMAGE_SCN_MEM_EXECUTE & dw) strcat(buf, "IMAGE_SCN_MEM_EXECUTE ");
    if (IMAGE_SCN_MEM_READ & dw) strcat(buf, "IMAGE_SCN_MEM_READ ");
    if (IMAGE_SCN_MEM_WRITE & dw) strcat(buf, "IMAGE_SCN_MEM_WRITE ");
    if (buf[0])
        buf[strlen(buf) - 1] = 0;
    return buf;
} // CrGetSectionFlagsString

const char *CrGetDllCharacteristicsString(WORD w) {
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    #define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
    #define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    #define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
    #define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_SEH
    #define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_BIND
    #define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
    #define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
    #define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000
#endif

    static char buf[512];
    buf[0] = 0;
    if (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ");
    if (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ");
    if (IMAGE_DLLCHARACTERISTICS_NX_COMPAT & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT ");
    if (IMAGE_DLLCHARACTERISTICS_NO_ISOLATION & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ");
    if (IMAGE_DLLCHARACTERISTICS_NO_SEH & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NO_SEH ");
    if (IMAGE_DLLCHARACTERISTICS_NO_BIND & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NO_BIND ");
    if (IMAGE_DLLCHARACTERISTICS_WDM_DRIVER & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ");
    if (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ");
    if (buf[0])
        buf[strlen(buf) - 1] = 0;
    return buf;
} // CrGetDllCharacteristicsString

const char *CrGetSubsystemString(WORD w) {
#ifndef IMAGE_SUBSYSTEM_UNKNOWN
    #define IMAGE_SUBSYSTEM_UNKNOWN 0
#endif
#ifndef IMAGE_SUBSYSTEM_NATIVE
    #define IMAGE_SUBSYSTEM_NATIVE 1
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_GUI
    #define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_CUI
    #define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#endif
#ifndef IMAGE_SUBSYSTEM_OS2_CUI
    #define IMAGE_SUBSYSTEM_OS2_CUI 5
#endif
#ifndef IMAGE_SUBSYSTEM_POSIX_CUI
    #define IMAGE_SUBSYSTEM_POSIX_CUI 7
#endif
#ifndef IMAGE_SUBSYSTEM_NATIVE_WINDOWS
    #define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
    #define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_APPLICATION
    #define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
    #define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
    #define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_ROM
    #define IMAGE_SUBSYSTEM_EFI_ROM 13
#endif
#ifndef IMAGE_SUBSYSTEM_XBOX
    #define IMAGE_SUBSYSTEM_XBOX 14
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
    #define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#endif

    switch(w) {
    case IMAGE_SUBSYSTEM_UNKNOWN: return "IMAGE_SUBSYSTEM_UNKNOWN";
    case IMAGE_SUBSYSTEM_NATIVE: return "IMAGE_SUBSYSTEM_NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI: return "IMAGE_SUBSYSTEM_OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return "IMAGE_SUBSYSTEM_POSIX_CUI";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS: return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM: return "IMAGE_SUBSYSTEM_EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX: return "IMAGE_SUBSYSTEM_XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
    default: return "(Unknown)";
    }
} // CrGetSubsystemString

void CrDumpDataDirectory(std::FILE *fp, LPVOID Data, DWORD index) {
#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
    #define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_IMPORT
    #define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_RESOURCE
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_EXCEPTION
    #define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_SECURITY
    #define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_BASERELOC
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_DEBUG
    #define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
    #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_GLOBALPTR
    #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_TLS
    #define IMAGE_DIRECTORY_ENTRY_TLS 9
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_IAT
    #define IMAGE_DIRECTORY_ENTRY_IAT 12
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#endif

    auto Directory = reinterpret_cast<IMAGE_DATA_DIRECTORY *>(Data);
    fprintf(fp, "    ");
    switch(index) {
    case IMAGE_DIRECTORY_ENTRY_EXPORT: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_EXPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_IMPORT: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_IMPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_RESOURCE: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_RESOURCE"); break;
    case IMAGE_DIRECTORY_ENTRY_EXCEPTION: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_EXCEPTION"); break;
    case IMAGE_DIRECTORY_ENTRY_SECURITY: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_SECURITY"); break;
    case IMAGE_DIRECTORY_ENTRY_BASERELOC: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_BASERELOC"); break;
    case IMAGE_DIRECTORY_ENTRY_DEBUG: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_DEBUG"); break;
    case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"); break;
    case IMAGE_DIRECTORY_ENTRY_GLOBALPTR: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR"); break;
    case IMAGE_DIRECTORY_ENTRY_TLS: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_TLS"); break;
    case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"); break;
    case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_IAT: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_IAT"); break;
    case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: fprintf(fp, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"); break;
    }
    fprintf(fp,
        " (%lu): V.A.: 0x%08lX, Size: 0x%08lX (%lu)\n", index,
        Directory->VirtualAddress, Directory->Size, Directory->Size);
} // CrDumpDataDirectory

void CrDumpDOSHeader(std::FILE *fp, LPVOID Data) {
    auto DOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(Data);
    fprintf(fp, "\n### DOS Header ###\n");
    fprintf(fp, "  e_magic: 0x%04X\n", DOSHeader->e_magic);
    fprintf(fp, "  e_cblp: 0x%04X\n", DOSHeader->e_cblp);
    fprintf(fp, "  e_cp: 0x%04X\n", DOSHeader->e_cp);
    fprintf(fp, "  e_crlc: 0x%04X\n", DOSHeader->e_crlc);
    fprintf(fp, "  e_cparhdr: 0x%04X\n", DOSHeader->e_cparhdr);
    fprintf(fp, "  e_minalloc: 0x%04X\n", DOSHeader->e_minalloc);
    fprintf(fp, "  e_maxalloc: 0x%04X\n", DOSHeader->e_maxalloc);
    fprintf(fp, "  e_ss: 0x%04X\n", DOSHeader->e_ss);
    fprintf(fp, "  e_sp: 0x%04X\n", DOSHeader->e_sp);
    fprintf(fp, "  e_csum: 0x%04X\n", DOSHeader->e_csum);
    fprintf(fp, "  e_ip: 0x%04X\n", DOSHeader->e_ip);
    fprintf(fp, "  e_cs: 0x%04X\n", DOSHeader->e_cs);
    fprintf(fp, "  e_lfarlc: 0x%04X\n", DOSHeader->e_lfarlc);
    fprintf(fp, "  e_ovno: 0x%04X\n", DOSHeader->e_ovno);
    fprintf(fp, "  e_res[0]: 0x%04X\n", DOSHeader->e_res[0]);
    fprintf(fp, "  e_res[1]: 0x%04X\n", DOSHeader->e_res[1]);
    fprintf(fp, "  e_res[2]: 0x%04X\n", DOSHeader->e_res[2]);
    fprintf(fp, "  e_res[3]: 0x%04X\n", DOSHeader->e_res[3]);
    fprintf(fp, "  e_oemid: 0x%04X\n", DOSHeader->e_oemid);
    fprintf(fp, "  e_oeminfo: 0x%04X\n", DOSHeader->e_oeminfo);
    fprintf(fp, "  e_res2[0]: 0x%04X\n", DOSHeader->e_res2[0]);
    fprintf(fp, "  e_res2[1]: 0x%04X\n", DOSHeader->e_res2[1]);
    fprintf(fp, "  e_res2[2]: 0x%04X\n", DOSHeader->e_res2[2]);
    fprintf(fp, "  e_res2[3]: 0x%04X\n", DOSHeader->e_res2[3]);
    fprintf(fp, "  e_res2[4]: 0x%04X\n", DOSHeader->e_res2[4]);
    fprintf(fp, "  e_res2[5]: 0x%04X\n", DOSHeader->e_res2[5]);
    fprintf(fp, "  e_res2[6]: 0x%04X\n", DOSHeader->e_res2[6]);
    fprintf(fp, "  e_res2[7]: 0x%04X\n", DOSHeader->e_res2[7]);
    fprintf(fp, "  e_res2[8]: 0x%04X\n", DOSHeader->e_res2[8]);
    fprintf(fp, "  e_res2[9]: 0x%04X\n", DOSHeader->e_res2[9]);
    fprintf(fp, "  e_lfanew: 0x%08lX\n", DOSHeader->e_lfanew);
} // CrDumpDOSHeader

void CrDumpFileHeader(std::FILE *fp, LPVOID Data) {
    auto FileHeader = reinterpret_cast<IMAGE_FILE_HEADER *>(Data);
    fprintf(fp, "\n### IMAGE_FILE_HEADER ###\n");
    fprintf(fp, "  Machine: 0x%04X (%s)\n", FileHeader->Machine, CrGetMachineString(FileHeader->Machine));
    fprintf(fp, "  NumberOfSections: 0x%04X (%u)\n", FileHeader->NumberOfSections, FileHeader->NumberOfSections);
    fprintf(fp, "  TimeDateStamp: 0x%08lX (%s)\n", FileHeader->TimeDateStamp, CrGetTimeStampString(FileHeader->TimeDateStamp));
    fprintf(fp, "  PointerToSymbolTable: 0x%08lX\n", FileHeader->PointerToSymbolTable);
    fprintf(fp, "  NumberOfSymbols: 0x%08lX (%lu)\n", FileHeader->NumberOfSymbols, FileHeader->NumberOfSymbols);
    fprintf(fp, "  SizeOfOptionalHeader: 0x%04X (%u)\n", FileHeader->SizeOfOptionalHeader, FileHeader->SizeOfOptionalHeader);
    fprintf(fp, "  Characteristics: 0x%04X (%s)\n", FileHeader->Characteristics, CrGetFileCharacteristicsString(FileHeader->Characteristics));
} // CrDumpFileHeader

void CrDumpOptionalHeader32(std::FILE *fp, LPVOID Data, DWORD CheckSum) {
    DWORD i;
    auto Optional32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32 *>(Data);
    IMAGE_DATA_DIRECTORY *DataDirectories, *DataDirectory;

    fprintf(fp, "\n### IMAGE_OPTIONAL_HEADER32 ###\n");
    fprintf(fp, "  Magic: 0x%04X\n", Optional32->Magic);
    fprintf(fp, "  LinkerVersion: %u.%u\n", Optional32->MajorLinkerVersion, Optional32->MinorLinkerVersion);
    fprintf(fp, "  SizeOfCode: 0x%08lX (%lu)\n", Optional32->SizeOfCode, Optional32->SizeOfCode);
    fprintf(fp, "  SizeOfInitializedData: 0x%08lX (%lu)\n", Optional32->SizeOfInitializedData, Optional32->SizeOfInitializedData);
    fprintf(fp, "  SizeOfUninitializedData: 0x%08lX (%lu)\n", Optional32->SizeOfUninitializedData, Optional32->SizeOfUninitializedData);
    fprintf(fp, "  AddressOfEntryPoint: 0x%08lX\n", Optional32->AddressOfEntryPoint);
    fprintf(fp, "  BaseOfCode: 0x%08lX\n", Optional32->BaseOfCode);
    fprintf(fp, "  BaseOfData: 0x%08lX\n", Optional32->BaseOfData);
    fprintf(fp, "  ImageBase: 0x%08lX\n", Optional32->ImageBase);
    fprintf(fp, "  SectionAlignment: 0x%08lX\n", Optional32->SectionAlignment);
    fprintf(fp, "  FileAlignment: 0x%08lX\n", Optional32->FileAlignment);
    fprintf(fp, "  OperatingSystemVersion: %u.%u\n", Optional32->MajorOperatingSystemVersion, Optional32->MinorOperatingSystemVersion);
    fprintf(fp, "  ImageVersion: %u.%u\n", Optional32->MajorImageVersion, Optional32->MinorImageVersion);
    fprintf(fp, "  SubsystemVersion: %u.%u\n", Optional32->MajorSubsystemVersion, Optional32->MinorSubsystemVersion);
    fprintf(fp, "  Win32VersionValue: 0x%08lX\n", Optional32->Win32VersionValue);
    fprintf(fp, "  SizeOfImage: 0x%08lX (%lu)\n", Optional32->SizeOfImage, Optional32->SizeOfImage);
    fprintf(fp, "  SizeOfHeaders: 0x%08lX (%lu)\n", Optional32->SizeOfHeaders, Optional32->SizeOfHeaders);
#ifndef NO_CHECKSUM
    fprintf(fp, "  CheckSum: 0x%08lX (%s)\n", Optional32->CheckSum, (Optional32->CheckSum == 0 || Optional32->CheckSum == CheckSum ? "valid" : "invalid"));
#else
    fprintf(fp, "  CheckSum: 0x%08lX\n", Optional32->CheckSum);
#endif
    fprintf(fp, "  Subsystem: 0x%04X (%s)\n", Optional32->Subsystem, CrGetSubsystemString(Optional32->Subsystem));
    fprintf(fp, "  DllCharacteristics: 0x%04X (%s)\n", Optional32->DllCharacteristics, CrGetDllCharacteristicsString(Optional32->DllCharacteristics));
    fprintf(fp, "  SizeOfStackReserve: 0x%08lX (%lu)\n", Optional32->SizeOfStackReserve, Optional32->SizeOfStackReserve);
    fprintf(fp, "  SizeOfStackCommit: 0x%08lX (%lu)\n", Optional32->SizeOfStackCommit, Optional32->SizeOfStackCommit);
    fprintf(fp, "  SizeOfHeapReserve: 0x%08lX (%lu)\n", Optional32->SizeOfHeapReserve, Optional32->SizeOfHeapReserve);
    fprintf(fp, "  SizeOfHeapCommit: 0x%08lX (%lu)\n", Optional32->SizeOfHeapCommit, Optional32->SizeOfHeapCommit);
    fprintf(fp, "  LoaderFlags: 0x%08lX\n", Optional32->LoaderFlags);
    fprintf(fp, "  NumberOfRvaAndSizes: 0x%08lX (%lu)\n", Optional32->NumberOfRvaAndSizes, Optional32->NumberOfRvaAndSizes);

    fprintf(fp, "\n  ### Directory Entries ###\n");
    DataDirectories = Optional32->DataDirectory;
    for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        DataDirectory = &DataDirectories[i];
        if (DataDirectory->VirtualAddress != 0 || DataDirectory->Size != 0) {
            CrDumpDataDirectory(fp, DataDirectory, i);
        }
    }
} // CrDumpOptionalHeader32

void CrDumpOptionalHeader64(std::FILE *fp, LPVOID Data, DWORD CheckSum) {
    DWORD i;
    auto Optional64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 *>(Data);
    IMAGE_DATA_DIRECTORY *DataDirectories, *DataDirectory;

    fprintf(fp, "\n### IMAGE_OPTIONAL_HEADER64 ###\n");
    fprintf(fp, "  Magic: 0x%04X\n", Optional64->Magic);
    fprintf(fp, "  LinkerVersion: %u.%u\n", Optional64->MajorLinkerVersion, Optional64->MinorLinkerVersion);
    fprintf(fp, "  SizeOfCode: 0x%08lX (%lu)\n", Optional64->SizeOfCode, Optional64->SizeOfCode);
    fprintf(fp, "  SizeOfInitializedData: 0x%08lX (%lu)\n", Optional64->SizeOfInitializedData, Optional64->SizeOfInitializedData);
    fprintf(fp, "  SizeOfUninitializedData: 0x%08lX (%lu)\n", Optional64->SizeOfUninitializedData, Optional64->SizeOfUninitializedData);
    fprintf(fp, "  AddressOfEntryPoint: 0x%08lX\n", Optional64->AddressOfEntryPoint);
    fprintf(fp, "  BaseOfCode: 0x%08lX\n", Optional64->BaseOfCode);
    fprintf(fp, "  ImageBase: 0x%08lX%08lX\n", HILONG(Optional64->ImageBase), LOLONG(Optional64->ImageBase));
    fprintf(fp, "  SectionAlignment: 0x%08lX\n", Optional64->SectionAlignment);
    fprintf(fp, "  FileAlignment: 0x%08lX\n", Optional64->FileAlignment);
    fprintf(fp, "  OperatingSystemVersion: %u.%u\n", Optional64->MajorOperatingSystemVersion, Optional64->MinorOperatingSystemVersion);
    fprintf(fp, "  ImageVersion: %u.%u\n", Optional64->MajorImageVersion, Optional64->MinorImageVersion);
    fprintf(fp, "  SubsystemVersion: %u.%u\n", Optional64->MajorSubsystemVersion, Optional64->MinorSubsystemVersion);
    fprintf(fp, "  Win32VersionValue: 0x%08lX\n", Optional64->Win32VersionValue);
    fprintf(fp, "  SizeOfImage: 0x%08lX (%lu)\n", Optional64->SizeOfImage, Optional64->SizeOfImage);
    fprintf(fp, "  SizeOfHeaders: 0x%08lX (%lu)\n", Optional64->SizeOfHeaders, Optional64->SizeOfHeaders);
#ifndef NO_CHECKSUM
    fprintf(fp, "  CheckSum: 0x%08lX (%s)\n", Optional64->CheckSum, (Optional64->CheckSum == 0 || Optional64->CheckSum == CheckSum ? "valid" : "invalid"));
#else
    fprintf(fp, "  CheckSum: 0x%08lX\n", Optional64->CheckSum);
#endif
    fprintf(fp, "  Subsystem: 0x%04X (%s)\n", Optional64->Subsystem, CrGetSubsystemString(Optional64->Subsystem));
    fprintf(fp, "  DllCharacteristics: 0x%04X (%s)\n", Optional64->DllCharacteristics, CrGetDllCharacteristicsString(Optional64->DllCharacteristics));

    char a[64];
    _i64toa(Optional64->SizeOfStackReserve, a, 10);
    fprintf(fp, "  SizeOfStackReserve: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfStackReserve), LOLONG(Optional64->SizeOfStackReserve), a);
    _i64toa(Optional64->SizeOfStackCommit, a, 10);
    fprintf(fp, "  SizeOfStackCommit: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfStackCommit), LOLONG(Optional64->SizeOfStackCommit), a);
    _i64toa(Optional64->SizeOfHeapReserve, a, 10);
    fprintf(fp, "  SizeOfHeapReserve: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfHeapReserve), LOLONG(Optional64->SizeOfHeapReserve), a);
    _i64toa(Optional64->SizeOfHeapCommit, a, 10);
    fprintf(fp, "  SizeOfHeapCommit: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfHeapCommit), LOLONG(Optional64->SizeOfHeapCommit), a);

    fprintf(fp, "  LoaderFlags: 0x%08lX\n", Optional64->LoaderFlags);
    fprintf(fp, "  NumberOfRvaAndSizes: 0x%08lX (%lu)\n", Optional64->NumberOfRvaAndSizes, Optional64->NumberOfRvaAndSizes);

    fprintf(fp, "\n  ### Directory Entries ###\n");
    DataDirectories = Optional64->DataDirectory;
    for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        DataDirectory = &DataDirectories[i];
        if (DataDirectory->VirtualAddress != 0 || DataDirectory->Size != 0) {
            CrDumpDataDirectory(fp, DataDirectory, i);
        }
    }
} // CrDumpOptionalHeader64

void CrDumpSectionHeader(std::FILE *fp, LPVOID Data) {
    auto SectionHeader = reinterpret_cast<REAL_IMAGE_SECTION_HEADER *>(Data);
    fprintf(fp, "  Name: ");
    for (DWORD i = 0; i < 8 && SectionHeader->Name[i] != 0; ++i)
        fprintf(fp, "%c", SectionHeader->Name[i]);
    fprintf(fp, "\n");

    fprintf(fp, "  VirtualSize: 0x%08lX (%lu)\n", SectionHeader->Misc.VirtualSize, SectionHeader->Misc.VirtualSize);
    fprintf(fp, "  RVA: 0x%08lX\n", SectionHeader->RVA);
    fprintf(fp, "  SizeOfRawData: 0x%08lX (%lu)\n", SectionHeader->SizeOfRawData, SectionHeader->SizeOfRawData);
    fprintf(fp, "  PointerToRawData: 0x%08lX\n", SectionHeader->PointerToRawData);
    fprintf(fp, "  PointerToRelocations: 0x%08lX\n", SectionHeader->PointerToRelocations);
    fprintf(fp, "  PointerToLinenumbers: 0x%08lX\n", SectionHeader->PointerToLinenumbers);
    fprintf(fp, "  NumberOfRelocations: 0x%08X (%u)\n", SectionHeader->NumberOfRelocations, SectionHeader->NumberOfRelocations);
    fprintf(fp, "  NumberOfLinenumbers: 0x%08X (%u)\n", SectionHeader->NumberOfLinenumbers, SectionHeader->NumberOfLinenumbers);
    fprintf(fp, "  Characteristics: 0x%08lX (%s)\n", SectionHeader->Characteristics, CrGetSectionFlagsString(SectionHeader->Characteristics));
} // CrDumpSectionHeader

void CrDumpCodes(std::FILE *fp, const CR_DataBytes& codes, INT bits) {
    std::size_t codesperline;

    if (bits == 64)
        codesperline = 16;
    else if (bits == 32)
        codesperline = 12;
    else
        codesperline = 9;

    std::size_t i;
    for (i = 0; i < codesperline; ++i) {
        if (i < codes.size()) {
            fprintf(fp, "%02X ", codes[i]);
        } else {
            fprintf(fp, "   ");
        }
    }

    for (; i < codes.size(); ++i) {
        fprintf(fp, "%02X ", codes[i]);
    }
} // CrDumpCodes

////////////////////////////////////////////////////////////////////////////
// CR_Module dumping

void CR_Module::DumpHeaders(std::FILE *fp) {
    if (!IsModuleLoaded())
        return;

#ifdef _UNICODE
    fprintf(fp, "FileName: %ls, FileSize: 0x%08lX (%lu)\n",
        m_strFileName.c_str(), m_dwFileSize, m_dwFileSize);
#else
    fprintf(fp, "FileName: %s, FileSize: 0x%08lX (%lu)\n",
        m_strFileName.c_str(), m_dwFileSize, m_dwFileSize);
#endif

    if (m_pDOSHeader) {
        CrDumpDOSHeader(fp, m_pDOSHeader);
    }
    if (m_pFileHeader) {
        CrDumpFileHeader(fp, m_pFileHeader);
    }
    
    if (m_pOptional32) {
        CrDumpOptionalHeader32(fp, m_pOptional32, m_dwCheckSum);
    } else if (m_pOptional64) {
        CrDumpOptionalHeader64(fp, m_pOptional64, m_dwCheckSum);
    }

    if (m_pSectionHeaders) {
        DWORD size = NumberOfSections();
        for (DWORD i = 0; i < size; ++i) {
            fprintf(fp, "\n### Section #%lu ###\n", i);
            CrDumpSectionHeader(fp, &m_pSectionHeaders[i]);
        }
    }
} // CR_Module::DumpHeaders

void CR_Module::_DumpImportSymbols32(std::FILE *fp) {
    DWORD i = 0;
    for (auto& name : ImportDllNames()) {
        fprintf(fp, "  %s\n", name.c_str());
        fprintf(fp, "    RVA      VA       HINT FUNCTION NAME\n");

        for (auto& symbol : ImportSymbols()) {
            if (symbol.iDLL != i) {
                continue;
            }
            CR_Addr32 addr = VA32FromRVA(symbol.dwRVA);
            fprintf(fp, "    %08lX %08lX ", symbol.dwRVA, addr);
            if (symbol.Name.wImportByName)
                fprintf(fp, "%4X %s\n", symbol.wHint, symbol.pszName);
            else
                fprintf(fp, "Ordinal %d\n", symbol.Name.wOrdinal);
        }
        fprintf(fp, "  \n");
        ++i;
    }
} // CR_Module::_DumpImportSymbols32

void CR_Module::_DumpImportSymbols64(std::FILE *fp) {
    DWORD i = 0;
    for (auto& name : ImportDllNames()) {
        fprintf(fp, "  %s\n", name.c_str());
        fprintf(fp, "    RVA      VA               HINT FUNCTION NAME\n");

        for (auto& symbol : ImportSymbols()) {
            if (symbol.iDLL != i) {
                continue;
            }
            CR_Addr64 addr = VA64FromRVA(symbol.dwRVA);
            fprintf(fp, "    %08lX %08lX%08lX ", symbol.dwRVA,
                HILONG(addr), LOLONG(addr));
            if (symbol.Name.wImportByName)
                fprintf(fp, "%4X %s\n", symbol.wHint, symbol.pszName);
            else
                fprintf(fp, "Ordinal %d\n", symbol.Name.wOrdinal);
        }
        fprintf(fp, "  \n");
        ++i;
    }
} // CR_Module::_DumpImportSymbols32

void CR_Module::DumpImportSymbols(std::FILE *fp) {
    auto descs = ImportDescriptors();
    if (descs == NULL)
        return;

    fprintf(fp, "\n### IMPORTS ###\n");
    fprintf(fp, "  Characteristics: 0x%08lX\n", descs->Characteristics);
    fprintf(fp, "  TimeDateStamp: 0x%08lX (%s)\n", descs->TimeDateStamp,
        CrGetTimeStampString(descs->TimeDateStamp));
    fprintf(fp, "  ForwarderChain: 0x%08lX\n", descs->ForwarderChain);
    fprintf(fp, "  Name: 0x%08lX (%s)\n", descs->Name, reinterpret_cast<char *>(GetData(descs->Name)));
    fprintf(fp, "  \n");

    if (ImportDllNames().empty() || ImportSymbols().empty()) {
        return;
    }

    if (Is64Bit()) {
        _DumpImportSymbols64(fp);
    } else if (Is32Bit()) {
        _DumpImportSymbols32(fp);
    }
} // CR_Module::DumpImportSymbols

void CR_Module::_DumpExportSymbols32(std::FILE *fp) {
    for (auto& symbol : ExportSymbols()) {
        if (symbol.dwRVA) {
            CR_Addr32 va = VA32FromRVA(symbol.dwRVA);
            if (symbol.pszName)
                fprintf(fp, "  %-50s @%-4lu ; %08lX %08lX\n", 
                    symbol.pszName, symbol.dwOrdinal, symbol.dwRVA, va);
            else
                fprintf(fp, "  %-50s @%-4lu ; %08lX %08lX\n", 
                    "(No Name)", symbol.dwOrdinal, symbol.dwRVA, va);
        } else {
            if (symbol.pszName)
                fprintf(fp, "  %-50s @%-4lu ; (forwarded to %s)\n", 
                    "(No Name)", symbol.dwOrdinal, symbol.pszForwarded);
            else
                fprintf(fp, "  %-50s @%-4lu ; (forwarded to %s)\n",
                    "(No Name)", symbol.dwOrdinal, symbol.pszForwarded);
        }
    }
} // CR_Module::_DumpExportSymbols32

void CR_Module::_DumpExportSymbols64(std::FILE *fp) {
    for (auto& symbol : ExportSymbols()) {
        if (symbol.dwRVA) {
            CR_Addr64 va = VA64FromRVA(symbol.dwRVA);
            if (symbol.pszName)
                fprintf(fp, "  %-50s @%-4lu ; %08lX %08lX%08lX\n", 
                    symbol.pszName, symbol.dwOrdinal, symbol.dwRVA,
                    HILONG(va), LOLONG(va));
            else
                fprintf(fp, "  %-50s @%-4lu ; %08lX %08lX%08lX\n", 
                    "(No Name)", symbol.dwOrdinal, symbol.dwRVA,
                    HILONG(va), LOLONG(va));
        } else {
            if (symbol.pszName)
                fprintf(fp, "  %-50s @%-4lu ; (forwarded to %s)\n", 
                    "(No Name)", symbol.dwOrdinal, symbol.pszForwarded);
            else
                fprintf(fp, "  %-50s @%-4lu ; (forwarded to %s)\n",
                    "(No Name)", symbol.dwOrdinal, symbol.pszForwarded);
        }
    }
} // CR_Module::_DumpExportSymbols64

void CR_Module::DumpExportSymbols(std::FILE *fp) {
    auto pDir = ExportDirectory();
    if (pDir == NULL)
        return;

    //DWORD dwNumberOfNames = pDir->NumberOfNames;
    //DWORD dwAddressOfFunctions = pDir->AddressOfFunctions;
    //DWORD dwAddressOfNames = pDir->AddressOfNames;
    //DWORD dwAddressOfOrdinals = pDir->AddressOfNameOrdinals;
    //LPDWORD pEAT = (LPDWORD)GetData(dwAddressOfFunctions);
    //LPDWORD pENPT = (LPDWORD)GetData(dwAddressOfNames);
    //LPWORD pOT = (LPWORD)GetData(dwAddressOfOrdinals);

    fprintf(fp, "\n### EXPORTS ###\n");
    fprintf(fp, "  Characteristics: 0x%08lX\n", pDir->Characteristics);
    fprintf(fp, "  TimeDateStamp: 0x%08lX (%s)\n", pDir->TimeDateStamp, CrGetTimeStampString(pDir->TimeDateStamp));
    fprintf(fp, "  Version: %u.%u\n", pDir->MajorVersion, pDir->MinorVersion);
    fprintf(fp, "  Name: 0x%08lX (%s)\n", pDir->Name, reinterpret_cast<char *>(GetData(pDir->Name)));
    fprintf(fp, "  Base: 0x%08lX (%lu)\n", pDir->Base, pDir->Base);
    fprintf(fp, "  NumberOfFunctions: 0x%08lX (%lu)\n", pDir->NumberOfFunctions, pDir->NumberOfFunctions);
    fprintf(fp, "  NumberOfNames: 0x%08lX (%lu)\n", pDir->NumberOfNames, pDir->NumberOfNames);
    fprintf(fp, "  AddressOfFunctions: 0x%08lX\n", pDir->AddressOfFunctions);
    fprintf(fp, "  AddressOfNames: 0x%08lX\n", pDir->AddressOfNames);
    fprintf(fp, "  AddressOfNameOrdinals: 0x%08lX\n", pDir->AddressOfNameOrdinals);
    fprintf(fp, "  \n");

    fprintf(fp, "  %-50s %-5s ; %-8s %-8s\n", "FUNCTION NAME", "ORDI.", "RVA", "VA");

    if (Is64Bit()) {
        _DumpExportSymbols64(fp);
    } else if (Is32Bit()) {
        _DumpExportSymbols32(fp);
    }

    printf("\n\n");
} // CR_Module::DumpExportSymbols

void CR_Module::_DumpDelayLoad32(std::FILE *fp) {
    CR_Addr32 addr;
    DWORD rva;

    int i = 0;
    for (auto& desc : DelayLoadDescriptors()) {
        fprintf(fp, "  ### Descr #%u ###\n", i);
        fprintf(fp, "    NAME       %-8s %-8s\n", "RVA", "VA");

        rva = desc.grAttrs;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    Attrs:     %08lX %08lX\n", rva, addr);

        rva = desc.rvaDLLName;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    DLL Name:  %s\n", (LPCSTR)(m_pLoadedImage + rva));
        fprintf(fp, "            :  %08lX %08lX\n", rva, addr);

        rva = desc.rvaHmod;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    Module:    %08lX %08lX\n", rva, addr);

        rva = desc.rvaIAT;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    IAT:       %08lX %08lX\n", rva, addr);

        rva = desc.rvaINT;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    INT:       %08lX %08lX\n", rva, addr);

        rva = desc.rvaBoundIAT;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    BoundIAT:  %08lX %08lX\n", rva, addr);

        rva = desc.rvaUnloadIAT;
        addr = VA32FromRVA(rva);
        fprintf(fp, "    UnloadIAT: %08lX %08lX\n", rva, addr);

        const char *pszTime = CrGetTimeStampString(desc.dwTimeStamp);
        fprintf(fp, "    dwTimeStamp:  0x%08lX (%s)",
            desc.dwTimeStamp, pszTime);
    }
} // CR_Module::_DumpDelayLoad32

void CR_Module::_DumpDelayLoad64(std::FILE *fp) {
    CR_Addr64 addr;
    DWORD rva;

    int i = 0;
    for (auto& desc : DelayLoadDescriptors()) {
        fprintf(fp, "  ### Descr #%u ###\n", i);
        fprintf(fp, "    NAME       %-8s %-8s\n", "RVA", "VA");

        rva = desc.grAttrs;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    Attrs:     %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        rva = desc.rvaDLLName;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    DLL Name:  %s\n", (LPCSTR)(m_pLoadedImage + rva));
        fprintf(fp, "            :  %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        rva = desc.rvaHmod;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    Module:    %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        rva = desc.rvaIAT;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    IAT:       %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        rva = desc.rvaINT;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    INT:       %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        rva = desc.rvaBoundIAT;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    BoundIAT:  %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        rva = desc.rvaUnloadIAT;
        addr = VA64FromRVA(rva);
        fprintf(fp, "    UnloadIAT: %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

        const char *pszTime = CrGetTimeStampString(desc.dwTimeStamp);
        fprintf(fp, "    dwTimeStamp:  0x%08lX (%s)",
            desc.dwTimeStamp, pszTime);

        ++i;
    }
} // CR_Module::_DumpDelayLoad64

void CR_Module::DumpDelayLoad(std::FILE *fp) {
    if (DelayLoadDescriptors().empty())
        return;

    fprintf(fp, "\n### DELAY LOAD ###\n");
    if (Is64Bit()) {
        _DumpDelayLoad64(fp);
    } else if (Is32Bit()) {
        _DumpDelayLoad32(fp);
    }

    fprintf(fp, "\n\n");
} // CR_Module::DumpDelayLoad

////////////////////////////////////////////////////////////////////////////

void CrDumpFuncFlags(std::FILE *fp, CR_FuncFlags flags) {
    if (flags & cr_FF_CDECL) {
        fprintf(fp, " cr_FF_CDECL");
    }
    if (flags & cr_FF_STDCALL) {
        fprintf(fp, " cr_FF_STDCALL");
    }
    if (flags & cr_FF_FASTCALL) {
        fprintf(fp, " cr_FF_FASTCALL");
    }
    if (flags & cr_FF_THISCALL) {
        fprintf(fp, " cr_FF_THISCALL");
    }
    if (flags & cr_FF_64BITFUNC) {
        fprintf(fp, " cr_FF_64BITFUNC");
    }
    if (flags & cr_FF_JUMPERFUNC) {
        fprintf(fp, " cr_FF_JUMPERFUNC");
    }
    if (flags & cr_FF_FUNCINFUNC) {
        fprintf(fp, " cr_FF_FUNCINFUNC");
    }
    if (flags & cr_FF_LEAFFUNC) {
        fprintf(fp, " cr_FF_LEAFFUNC");
    }
    if (flags & cr_FF_RETURNONLY) {
        fprintf(fp, " cr_FF_RETURNONLY");
    }
    if (flags & cr_FF_NOTSTDCALL) {
        fprintf(fp, " cr_FF_NOTSTDCALL");
    }
    if (flags & cr_FF_INVALID) {
        fprintf(fp, " cr_FF_INVALID");
    }
    if (flags & cr_FF_IGNORE) {
        fprintf(fp, " cr_FF_IGNORE");
    }
}

void CrDumpFuncExtra32(std::FILE *fp, CR_CodeFunc32 *cf) {
    for (auto& jumpee : cf->Jumpees()) {
        fprintf(fp, "JUMPEE: %08lX\n", jumpee);
    }
    for (auto& jumper : cf->Jumpers()) {
        fprintf(fp, "JUMPER: %08lX\n", jumper);
    }
    for (auto& callee : cf->Callees()) {
        fprintf(fp, "CALLEE: %08lX\n", callee);
    }
    for (auto& caller : cf->Callers()) {
        fprintf(fp, "CALLER: %08lX\n", caller);
    }
}

void CrDumpFuncExtra64(std::FILE *fp, CR_CodeFunc64 *cf) {
    for (auto& jumpee : cf->Jumpees()) {
        fprintf(fp, "JUMPEE: %08lX%08lX\n", HILONG(jumpee), LOLONG(jumpee));
    }
    for (auto& jumper : cf->Jumpers()) {
        fprintf(fp, "JUMPER: %08lX%08lX\n", HILONG(jumper), LOLONG(jumper));
    }
    for (auto& callee : cf->Callees()) {
        fprintf(fp, "CALLEE: %08lX%08lX\n", HILONG(callee), LOLONG(callee));
    }
    for (auto& caller : cf->Callers()) {
        fprintf(fp, "CALLER: %08lX%08lX\n", HILONG(caller), LOLONG(caller));
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Module::DumpDisAsm32

BOOL CR_Module::DumpDisAsm32(std::FILE *fp, CR_DecompInfo32& info) {
    printf("\n### DISASSEMBLY ###\n\n");

    for (auto& entrance : info.Entrances()) {
        CR_CodeFunc32 *cf = info.CodeFuncFromAddr(entrance);
        assert(cf);
        if (cf->FuncFlags() & cr_FF_IGNORE)
            continue;

        const char *pszName = FuncNameFromVA32(cf->Addr());
        if (pszName)
            fprintf(fp, ";; Function %s @ L%08lX\n", pszName, cf->Addr());
        else
            fprintf(fp, ";; Function L%08lX\n", cf->Addr());

        fprintf(fp, "flags =");
        CrDumpFuncFlags(fp, cf->FuncFlags());
        fprintf(fp, "\n");

        auto& range = cf->StackArgSizeRange();
        fprintf(fp, "StackArgSizeRange == %s\n", range.str().c_str());

        CrDumpFuncExtra32(fp, cf);

        _DumpDisAsmFunc32(fp, info, entrance);

        if (pszName)
            fprintf(fp, ";; End of Function %s @ L%08lX\n\n", pszName, cf->Addr());
        else
            fprintf(fp, ";; End of Function L%08lX\n\n", cf->Addr());
    }
    return TRUE;
} // CR_Module::DumpDisAsm32

BOOL CR_Module::_DumpDisAsmFunc32(std::FILE *fp, CR_DecompInfo32& info, CR_Addr32 func) {
    auto end = info.MapAddrToOpCode().end();
    for (auto it = info.MapAddrToOpCode().begin(); it != end; it++) {
        CR_OpCode32 *oc = it->second.get();
        assert(oc);

        if (func != 0 && !oc->FuncAddrs().count(func))
            continue;

        fprintf(fp, "L%08lX: ", oc->Addr());

        CrDumpCodes(fp, oc->Codes(), 32);

        switch (oc->Operands().size()) {
        case 3:
            fprintf(fp, "%s %s,%s,%s\n", oc->Name().c_str(),
                oc->Operand(0)->Text().c_str(), oc->Operand(1)->Text().c_str(),
                oc->Operand(2)->Text().c_str());
            break;

        case 2:
            fprintf(fp, "%s %s,%s\n", oc->Name().c_str(),
                oc->Operand(0)->Text().c_str(), oc->Operand(1)->Text().c_str());
            break;

        case 1:
            fprintf(fp, "%s %s\n", oc->Name().c_str(),
                oc->Operand(0)->Text().c_str());
            break;

        case 0:
            fprintf(fp, "%s\n", oc->Name().c_str());
            break;
        }
    }

    return TRUE;
} // CR_Module::_DumpDisAsmFunc32

////////////////////////////////////////////////////////////////////////////
// CR_Module::DumpDisAsm64

BOOL CR_Module::DumpDisAsm64(std::FILE *fp, CR_DecompInfo64& info) {
    printf("\n### DISASSEMBLY ###\n\n");

    for (auto& entrance : info.Entrances()) {
        CR_CodeFunc64 *cf = info.CodeFuncFromAddr(entrance);
        assert(cf);
        if (cf->FuncFlags() & cr_FF_IGNORE)
            continue;

        const char *pszName = FuncNameFromVA64(cf->Addr());

        if (pszName)
            fprintf(fp, ";; Function %s @ L%08lX%08lX\n", pszName,
                HILONG(cf->Addr()), LOLONG(cf->Addr()));
        else
            fprintf(fp, ";; Function L%08lX%08lX\n", HILONG(cf->Addr()), LOLONG(cf->Addr()));

        fprintf(fp, "flags =");
        CrDumpFuncFlags(fp, cf->FuncFlags());
        fprintf(fp, "\n");

        auto& range = cf->StackArgSizeRange();
        fprintf(fp, "StackArgSizeRange == %s\n", range.str().c_str());

        CrDumpFuncExtra64(fp, cf);

        _DumpDisAsmFunc64(fp, info, entrance);

        if (pszName)
            fprintf(fp, ";; End of Function %s @ L%08lX%08lX\n\n", pszName,
                HILONG(cf->Addr()), LOLONG(cf->Addr()));
        else
            fprintf(fp, ";; End of Function L%08lX%08lX\n\n",
                HILONG(cf->Addr()), LOLONG(cf->Addr()));
    }
    return TRUE;
} // CR_Module::DumpDisAsm64

BOOL CR_Module::_DumpDisAsmFunc64(std::FILE *fp, CR_DecompInfo64& info, CR_Addr64 func) {
    auto end = info.MapAddrToOpCode().end();
    for (auto it = info.MapAddrToOpCode().begin(); it != end; it++) {
        CR_OpCode64 *oc = it->second.get();
        assert(oc);

        if (func != 0 && !oc->FuncAddrs().count(func))
            continue;

        fprintf(fp, "L%08lX%08lX: ", HILONG(oc->Addr()), LOLONG(oc->Addr()));

        CrDumpCodes(fp, oc->Codes(), 64);

        switch (oc->Operands().size())
        {
        case 3:
            fprintf(fp, "%s %s,%s,%s\n", oc->Name().c_str(),
                oc->Operand(0)->Text().c_str(), oc->Operand(1)->Text().c_str(),
                oc->Operand(2)->Text().c_str());
            break;

        case 2:
            fprintf(fp, "%s %s,%s\n", oc->Name().c_str(),
                oc->Operand(0)->Text().c_str(), oc->Operand(1)->Text().c_str());
            break;

        case 1:
            fprintf(fp, "%s %s\n", oc->Name().c_str(),
                oc->Operand(0)->Text().c_str());
            break;

        case 0:
            fprintf(fp, "%s\n", oc->Name().c_str());
            break;
        }
    }

    return TRUE;
} // CR_Module::_DumpDisAsmFunc64

////////////////////////////////////////////////////////////////////////////

BOOL CR_Module::DumpDecompile32(std::FILE *fp, CR_DecompInfo32& info) {
    return TRUE;
}

BOOL CR_Module::DumpDecompile64(std::FILE *fp, CR_DecompInfo64& info) {
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
