/*!
    @file GuestAgent.c

    @brief GuestAgent code.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "GuestAgent.h"

#if defined(MV_PLATFORM_WINDOWS)
#include <ntimage.h>
#else
#include <IndustryStandard/PeImage.h>

typedef EFI_IMAGE_DOS_HEADER        IMAGE_DOS_HEADER;
typedef EFI_IMAGE_NT_HEADERS64      IMAGE_NT_HEADERS64;
typedef EFI_IMAGE_DATA_DIRECTORY    IMAGE_DATA_DIRECTORY;
typedef EFI_IMAGE_EXPORT_DIRECTORY  IMAGE_EXPORT_DIRECTORY;
#define IMAGE_DOS_SIGNATURE             EFI_IMAGE_DOS_SIGNATURE
#define IMAGE_NT_SIGNATURE              EFI_IMAGE_NT_SIGNATURE
#define IMAGE_DIRECTORY_ENTRY_EXPORT    EFI_IMAGE_DIRECTORY_ENTRY_EXPORT

//
// Things required to copy and paste Windows things.
//
typedef UINT8 UCHAR;
typedef UINT32 POOL_TYPE;
typedef UINT64 SIZE_T;
typedef VOID* PVOID;
typedef unsigned long ULONG;
typedef CONST CHAR* PCSTR;
#define NTAPI __stdcall
#define DPFLTR_IHVDRIVER_ID     77
#define DPFLTR_ERROR_LEVEL      0

#endif

#include <Zydis/Zydis.h>
#include "HostUtils.h"
#include "Logger.h"


PVOID
NTAPI
AsmExAllocatePoolWithTag (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

//
// Windows-specific:
//
// The trap frame structure for x64 systems. This is structure is used to help
// Windbg to construct call stack while VM-exit handlers are being executed.
// Since this is for Windbg, this is a Windows specific structure, and its
// layout can be found as nt!_KTRAP_FRAME. In our case, only the Rip and Rsp
// members are used since those are only fields needed to be set for Windbg to
// show proper call stack.
//
typedef struct _WINDOWS_KTRAP_FRAME
{
    UINT64 Reserved1[45];
    UINT64 Rip;
    UINT64 Reserved2[2];
    UINT64 Rsp;
    UINT64 Reserved3;
} WINDOWS_KTRAP_FRAME;
C_ASSERT(sizeof(WINDOWS_KTRAP_FRAME) == 0x190);

typedef struct _INITIAL_GUEST_AGENT_STACK
{
    GUEST_REGISTERS GuestRegisters;
    WINDOWS_KTRAP_FRAME TrapFrame;
    HOST_GUEST_AGENT_CONTEXT GuestAgentContext;
} INITIAL_GUEST_AGENT_STACK;

//
// A byte array that represents the below x64 code.
//  90               nop
//  ff2500000000     jmp     qword ptr cs:jmp_addr
// jmp_addr:
//  0000000000000000 dq 0
//
#pragma pack(push, 1)
typedef struct _JMP_CODE
{
    UCHAR Nop;
    UCHAR Jmp[6];
    PVOID Address;
} JMP_CODE;
C_ASSERT(sizeof(JMP_CODE) == 15);
#pragma pack(pop)

typedef
ULONG
(__cdecl*DBGPRINTEX_TYPE) (
    _In_ ULONG ComponentId,
    _In_ ULONG Level,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

typedef
PVOID
(NTAPI*EXALLOCATEPOOLWITHTAG_TYPE) (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

typedef
PVOID
(NTAPI*RTLPCTOFILEHEADER_TYPE) (
    _In_ PVOID PcValue,
    _Out_ PVOID *BaseOfImage
    );

typedef struct _GUEST_AGENT_CONTEXT
{
    VOID* NtoskrnlBase;
    DBGPRINTEX_TYPE DbgPrintEx;
    RTLPCTOFILEHEADER_TYPE RtlPcToFileHeader;
} GUEST_AGENT_CONTEXT;

//
// The global guest agent data. This must be per-processor to be MP-safe. As of
// now, we only invoke the guest agent once, so this is not MP-safe but ok.
//
static GUEST_AGENT_CONTEXT g_GuestAgent;

static
UINT64
FindImageBase2 (
    _In_ UINT64 VirtualAddress
    )
{
    UINT64 imageBase;

    //
    // Starting with the page aligned address, and search up IMAGE_DOS_SIGNATURE
    // every page up to 16MB (0x1000000). Ntoskrnl.exe can be mapped at the page
    // boundary and not the 64KB boundary unlike other images.
    //
    imageBase = (VirtualAddress & ~(PAGE_SIZE - 1));

    for (int i = 0; i < 0x1000; i++, imageBase -= PAGE_SIZE)
    {
        if (*((UINT16*)imageBase) == 0x5A4D)
        {
            goto Exit;
        }
    }

    imageBase = 0;

Exit:
    return imageBase;
}

static
VOID*
GetProcedureAddress (
    _In_ UINT64 DllBase,
    _In_ CONST CHAR* RoutineName
    )
{
    CONST IMAGE_DOS_HEADER* dosHeader;
    CONST IMAGE_NT_HEADERS64* ntHeaders;
    CONST IMAGE_DATA_DIRECTORY* imageDirectories;
    UINT32 exportDirRva;
    UINT32 exportDirSize;
    CONST IMAGE_EXPORT_DIRECTORY* exportDirectory;
    UINT32* addressOfFunctions;
    UINT16* addressOfNameOrdinals;
    UINT32* addressOfNames;
    INT32 low, middle, high;
    UINT32 functionRva;

    //
	// Find and verify PE headers
    //
	dosHeader = (IMAGE_DOS_HEADER*)DllBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }
	ntHeaders = (IMAGE_NT_HEADERS64*)(DllBase + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    //
    // Get the export directory RVA and size
    //
    imageDirectories = ntHeaders->OptionalHeader.DataDirectory;
    exportDirRva = imageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    exportDirSize = imageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    //
    // Read the export directory
    //
    exportDirectory = (IMAGE_EXPORT_DIRECTORY*)(DllBase + exportDirRva);
    addressOfFunctions = (UINT32*)(DllBase + exportDirectory->AddressOfFunctions);
    addressOfNameOrdinals = (UINT16*)(DllBase + exportDirectory->AddressOfNameOrdinals);
    addressOfNames = (UINT32*)(DllBase + exportDirectory->AddressOfNames);

    //
    // Look up the import name in the name table using a binary search
    //
    low = 0;
    middle = 0;
    high = exportDirectory->NumberOfNames - 1;

    while (high >= low)
    {
        INT64 result;

        //
        // Compute the next probe index and compare the import name
        //
        middle = (low + high) >> 1;
        result = strcmp(RoutineName, (CHAR*)(DllBase + addressOfNames[middle]));
        if (result < 0)
        {
            high = middle - 1;
        }
        else if (result > 0)
        {
            low = middle + 1;
        }
        else
        {
            break;
        }
    }

    //
    // If the high index is less than the low index, then a matching table entry
    // was not found. Otherwise, get the ordinal number from the ordinal table
    //
    if (high < low || middle >= (INT32)exportDirectory->NumberOfFunctions)
    {
        return NULL;
    }
    functionRva = addressOfFunctions[addressOfNameOrdinals[middle]];
    if (functionRva >= exportDirRva && functionRva < exportDirRva + exportDirSize)
    {
        return NULL; // Ignore forward exports
    }

    return (VOID*)(DllBase + functionRva);
}

typedef union _POOL_TAG_STRING
{
    UINT64 AsUInt64;
    CHAR AsString[8];
} POOL_TAG_STRING;

static
POOL_TAG_STRING
ConvertTagToString (
    _In_ ULONG Tag
    )
{
    POOL_TAG_STRING poolTag;

    poolTag.AsUInt64 = Tag;
    for (int i = 0; i < 4; ++i)
    {
        if ((poolTag.AsString[i] == ANSI_NULL) ||
            (poolTag.AsString[i] == '\t') ||
            (poolTag.AsString[i] == '\r') ||
            (poolTag.AsString[i] == '\n'))
        {
            poolTag.AsString[i] = ' ';
        }
        else if ((0x20 <= poolTag.AsString[i]) && (poolTag.AsString[i] <= 0x7e))
        {
            NOTHING;
        }
        else
        {
            poolTag.AsString[i] = '.';
        }
    }
    return poolTag;
}

static
PVOID
NTAPI
HandleExAllocatePoolWithTag (
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    )
{
    VOID* pointer;
    VOID* callerAddress;
    VOID* callerImageBase;

    pointer = AsmExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag);

    //
    // Print debug messages if the caller does not belong to any image. That is
    // likely PatchGuard.
    //
    callerAddress = _ReturnAddress();
    if (g_GuestAgent.RtlPcToFileHeader(callerAddress, &callerImageBase) != NULL)
    {
        goto Exit;
    }

    g_GuestAgent.DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                            DPFLTR_ERROR_LEVEL,
                            "%p : ExAllocatePoolWithTag(POOL_TYPE= %8x,"
                            " NumberOfBytes= %8Ix, Tag= %s) => %p\n",
                            callerAddress,
                            PoolType,
                            NumberOfBytes,
                            ConvertTagToString(Tag).AsString,
                            pointer);

Exit:
    return pointer;
}

static
JMP_CODE
CreateJumpCode (
    _In_ UINT64 Destination
    )
{
    //
    //  90               nop
    //  ff2500000000     jmp     qword ptr cs:jmp_addr
    // jmp_addr:
    //  0000000000000000 dq 0
    //
    static CONST UCHAR jumpInst[] = { 0xff, 0x25, 0x00, 0x00, 0x00, 0x00, };
    JMP_CODE jmpCode;

    jmpCode.Nop = 0x90;
    RtlCopyMemory(jmpCode.Jmp, jumpInst, sizeof(jumpInst));
    jmpCode.Address = (VOID*)Destination;
    return jmpCode;
}

static
BOOLEAN
InstallHook (
    _In_ UINT64 TargetAddress,
    _In_ UINT64 HandlerAddress,
    _In_ UINT64 OriginalCallStub
    )
{
    BOOLEAN ok;
    ZydisDecoder decoder;
    ZydisDecodedInstruction instruction;
    UINT8 hookBytes;
    JMP_CODE JmpToHandlerCode, jmpToOriginal;
    CR0 cr0;

    ok = FALSE;

    if (ZYAN_FAILED(ZydisDecoderInit(&decoder,
                                     ZYDIS_MACHINE_MODE_LONG_64,
                                     ZYDIS_ADDRESS_WIDTH_64)))
    {
        goto Exit;
    }

    //
    // Disassembly each instruction (which is at most 15 bytes) until we discover
    // space enough to patch the jump code (ie, sizeof(JMP_CODE)).
    //
    hookBytes = 0;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder,
                                                 MV_ADD2PTR(TargetAddress, hookBytes),
                                                 15,
                                                 &instruction)))
    {
        hookBytes += instruction.length;
        if (hookBytes >= sizeof(JMP_CODE))
        {
            break;
        }
    }
    if (hookBytes < sizeof(JMP_CODE))
    {
        goto Exit;
    }

    //
    // Create arrays of bytes that represents JMP-to-hook and JMP-to-original.
    //
    JmpToHandlerCode = CreateJumpCode(HandlerAddress);
    jmpToOriginal = CreateJumpCode(TargetAddress + hookBytes);

    //
    // Disable interrupt so that this processor does not go anywhere while doing
    // nasty things below due to context switch or other interrupt. This assumes
    // that there is no other active processor on the system.
    //
    _disable();

    //
    // Disable write protection and invalidate TLBs of the addresses this needs
    // to effect.
    //
    cr0.Flags = __readcr0();
    cr0.WriteProtect = FALSE;
    __writecr0(cr0.Flags);
    __invlpg((void*)TargetAddress);
    __invlpg((void*)HandlerAddress);

    //
    // Update the stub so that it contains original instructions copied from
    // the original and jump to the rest of original code.
    //
    RtlCopyMemory((void*)OriginalCallStub, (void*)TargetAddress, hookBytes);
    RtlCopyMemory((void*)(OriginalCallStub + hookBytes),
                  &jmpToOriginal,
                  sizeof(jmpToOriginal));

    //
    // Update the original function to jump to the specified handler.
    //
    RtlCopyMemory((void*)TargetAddress, &JmpToHandlerCode, sizeof(JmpToHandlerCode));

    //
    // Restore state. Note that no special instructions required to reflect the
    // updated code.
    // - Modified code is not executed immediately after this, so no speculative
    //   execution issue.
    // - There is no other processors, so no "cross-modifying code". (If either
    //   of those is an issue, see 8.1.3 Handling Self- and Cross-Modifying Code)
    // - Cache and perfected instructions for the modified code are invalidated,
    //   so no need of wbinvd or clflush.
    //   "A write to a memory location in a code segment that is currently cached
    //    in the processor causes the associated cache line (or lines) to be
    //    invalidated. (...) If the write affects a prefetched instruction, the
    //    prefetch queue is invalidated."
    //   See: 11.6 SELF-MODIFYING CODE
    //
    cr0.WriteProtect = TRUE;
    __writecr0(cr0.Flags);
    _enable();

    ok = TRUE;

Exit:
    return ok;
}

static
VOID
HandleInitializeGuestAgent (
    CONST INITIAL_GUEST_AGENT_STACK* Stack,
    GUEST_AGENT_CONTEXT* GuestAgent
    )
{
    UINT64 ntoskrnlBase;
    DBGPRINTEX_TYPE dbgPrintEx;
    RTLPCTOFILEHEADER_TYPE rtlPcToFileHeader;
    EXALLOCATEPOOLWITHTAG_TYPE exAllocatePoolWithTag;

    MV_ASSERT(GuestAgent->NtoskrnlBase == NULL);

    //
    // Must be PASSIVE_LEVEL IRQL.
    //
    MV_ASSERT(__readcr8() == 0);

    LOG_INFO("Initializing the guest agent.");

    //
    // Retrieve the NT image base and resolve exports.
    //
    ntoskrnlBase = FindImageBase2(Stack->GuestAgentContext.OriginalGuestRip);
    if (ntoskrnlBase == 0)
    {
        MV_PANIC();
    }

    dbgPrintEx = (DBGPRINTEX_TYPE)GetProcedureAddress(ntoskrnlBase,
                                                      "DbgPrintEx");
    rtlPcToFileHeader = (RTLPCTOFILEHEADER_TYPE)GetProcedureAddress(
                                                            ntoskrnlBase,
                                                            "RtlPcToFileHeader");
    exAllocatePoolWithTag = (EXALLOCATEPOOLWITHTAG_TYPE)GetProcedureAddress(
                                                        ntoskrnlBase,
                                                        "ExAllocatePoolWithTag");
    if ((dbgPrintEx == NULL) ||
        (rtlPcToFileHeader == NULL) ||
        (exAllocatePoolWithTag == NULL))
    {
        MV_PANIC();
    }

    LOG_INFO("Found ntoskrnl.exe at %016llx", ntoskrnlBase);
    LOG_INFO("Found ExAllocatePoolWithTag at %p", exAllocatePoolWithTag);

    //
    // Patch ExAllocatePoolWithTag.
    //
    if (!InstallHook((UINT64)exAllocatePoolWithTag,
                     (UINT64)HandleExAllocatePoolWithTag,
                     (UINT64)AsmExAllocatePoolWithTag))
    {
        MV_PANIC();
    }

    LOG_INFO("Hooked ExAllocatePoolWithTag successfully.");
    GuestAgent->NtoskrnlBase = (VOID*)ntoskrnlBase;
    GuestAgent->DbgPrintEx = dbgPrintEx;
    GuestAgent->RtlPcToFileHeader = rtlPcToFileHeader;
}

VOID
GuestAgentEntryPoint (
    INITIAL_GUEST_AGENT_STACK* Stack
    )
{
    //
    // Help Windbg reconstruct call stack.
    //
    Stack->TrapFrame.Rsp = Stack->GuestAgentContext.OriginalGuestRsp;
    Stack->TrapFrame.Rip = Stack->GuestAgentContext.OriginalGuestRip;

    switch (Stack->GuestAgentContext.CommandNumber)
    {
    case GuestAgentCommandInitialize:
        HandleInitializeGuestAgent(Stack, &g_GuestAgent);
        break;

    default:
        MV_PANIC();
    }
}
