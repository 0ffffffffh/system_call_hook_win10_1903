#pragma comment(lib,"ntoskrnl.lib")

#include <wdm.h>


#define DLOG(x,...) DbgPrint(x "\n",__VA_ARGS__)
#define NTOS_OFFSET(off, type) ((type *)(KhpNtosBase + (off)))


typedef NTSTATUS(NTAPI *PKESETSYSTEMSERVICECALLBACKPTR)(
    PCHAR systemCallString, 
    BOOLEAN isEntry, 
    ULONG64 callback, 
    PVOID callbackArg
    );

typedef NTSTATUS(NTAPI *PNTCLOSEPTR)(HANDLE);


extern ULONG64 NTAPI KhpGetCr0();

extern void NTAPI KhpSetCr0(ULONG64 value);

extern NTSTATUS NTAPI KhpHookHandler();

ULONG64 KhpNtosBase = 0;



ULONG64 KhpKeSetSystemServiceCallbackOffset =   0x87D5E0;

PNTCLOSEPTR KhpOriginalNtClose = 0;

PKESETSYSTEMSERVICECALLBACKPTR KeSetSystemServiceCallback = NULL;

PULONG64 KhpHookCallback = NULL;

typedef struct __SYSTEM_MEMORY
{
    PMDL        mdl;
    ULONG64     addr;
    PUCHAR      memoryBuffer;
    ULONG       length;
}SYSTEM_MEMORY, *PSYSTEM_MEMORY;

BOOLEAN NTAPI KhpLockCodeMemory(ULONG64 addr, ULONG length, PSYSTEM_MEMORY sysMemInfo)
{
    PUCHAR buffer;
    PMDL mdl = NULL;

    DLOG("locking memory %llx for %d bytes", addr, length);

    RtlZeroMemory(sysMemInfo, sizeof(SYSTEM_MEMORY));

    mdl = IoAllocateMdl(addr, length, FALSE, FALSE, NULL);

    if (!mdl)
    {
        DLOG("mdl alloc error");
        return FALSE;
    }

    __try
    {
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DLOG("lock page error");
        return FALSE;
    }

    buffer = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

    if (!buffer)
    {
        DLOG("cant get system addr for mdl");
        return FALSE;
    }

    if (MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS)
    {
        DLOG("protection set error");
        return FALSE;
    }

    sysMemInfo->memoryBuffer = buffer;
    sysMemInfo->addr = addr;
    sysMemInfo->length = length;
    sysMemInfo->mdl = mdl;

    return TRUE;
}

BOOLEAN NTAPI KhpUnlockCodeMemory(PSYSTEM_MEMORY memInfo)
{
    MmProtectMdlSystemAddress(memInfo->mdl, PAGE_EXECUTE_READ);

    __try
    {
        MmUnlockPages(memInfo->mdl);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DLOG("unlock error");
        return FALSE;
    }

    IoFreeMdl(memInfo->mdl);

    RtlZeroMemory(memInfo, sizeof(SYSTEM_MEMORY));

    return TRUE;
}

void NTAPI KhpEnableDisableWriteProtection(BOOLEAN disable)
{
    ULONG64 cr0 = KhpGetCr0();

    if (disable)
        cr0 &= ~0x10000;
    else
        cr0 |= 0x10000;

    KhpSetCr0(cr0);
}



ULONG64 NTAPI KhpMapAddressForLockedPage(ULONG64 addr, PSYSTEM_MEMORY mem)
{
    ULONG64 aoffset = addr - mem->addr;

    return ((ULONG64)mem->memoryBuffer) + aoffset;
}

ULONG64 NTAPI KhpMapKernelOffsetForLockedPage(ULONG offset, PSYSTEM_MEMORY mem)
{
    PUCHAR paddr = NTOS_OFFSET(offset, UCHAR);

    return KhpMapAddressForLockedPage((ULONG64)paddr, mem);
}

#define MAPPED_OFFSET_MEM(offset, mem) ((PUCHAR)KhpMapKernelOffsetForLockedPage((offset),mem))
#define ALIGN(x,align) ( ( ( (x) / (align) ) + 1 ) * align )

BOOLEAN NTAPI KhpPatchKiTrackSystemCallEntry()
{
    SYSTEM_MEMORY meminfo;

    const ULONG callbackAllowCheckOffset = 0x87D93A;
    const ULONG enableCheckLogicOffset = 0x87D9A6;
    const ULONG callbackAddressLoadOffset = 0x87D9AF;
    
    const ULONG blockSize = ALIGN(callbackAddressLoadOffset - callbackAllowCheckOffset + 32, 8);

    //UCHAR oldOffset[] = { 0x7A, 0x20, 0xCF, 0xFF };

    PUCHAR beginAddr = NTOS_OFFSET(callbackAllowCheckOffset, UCHAR);

    if (!KhpLockCodeMemory(beginAddr, blockSize, &meminfo))
    {
        DLOG("lock mem error for kitracksystemcallentry");
        return FALSE;
    }


    *MAPPED_OFFSET_MEM(enableCheckLogicOffset, &meminfo) = 0x75;

    //MOV RAX, {OFFSET}
    //48 8B 05
    *MAPPED_OFFSET_MEM(callbackAddressLoadOffset + 3, &meminfo) += 0x30;

    *MAPPED_OFFSET_MEM(callbackAllowCheckOffset + 1, &meminfo) = 0x85;

    KhpUnlockCodeMemory(&meminfo);

    return TRUE;
}

void NTAPI KhpPlantHookCallbackFunction(ULONG64 addr)
{
    KhpHookCallback = NTOS_OFFSET(0x56FA60, ULONG64);

    DLOG("Hook callback %llx", KhpHookCallback);

    *KhpHookCallback = addr;
}

BOOLEAN NTAPI KhpReverseCallbackSetLogic()
{
    BOOLEAN status = FALSE;
    SYSTEM_MEMORY sysMemory;
    const ULONG routineOffset = 0x29;
    
    PUCHAR paddr = NTOS_OFFSET(KhpKeSetSystemServiceCallbackOffset + routineOffset, UCHAR);
    
    if (!KhpLockCodeMemory(paddr, sizeof(ULONG64), &sysMemory))
    {
        DLOG("page lock fail");
        return FALSE;
    }

    PUCHAR inst = sysMemory.memoryBuffer;

    if (*inst == 0x74)
    {
        *inst = 0x75;
        status = TRUE;
    }
    else if (*inst == 0x75)
    {
        *inst = 0x74;
        status = FALSE;
    }

    KhpUnlockCodeMemory(&sysMemory);

    return status;
}

ULONG64 NTAPI KhpGetAddressBySymbol(PWSTR procName)
{
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, procName);

    return (ULONG64)MmGetSystemRoutineAddress(&sym);
}

ULONG64 NTAPI KhpGetNtosBase()
{
    ULONG64 refAddr;
    ULONG64 *PsNtosImageBase;

    if (KhpNtosBase)
        return KhpNtosBase;

    refAddr = KhpGetAddressBySymbol(L"PsInitialSystemProcess");

    if (!refAddr)
        return 0;

    PsNtosImageBase = (ULONG64 *)(refAddr + 0x50);
    KhpNtosBase = *PsNtosImageBase;

    //quick w.a to set Kd_DEFAULT_MASK, Kd_IHVDRIVER_MASK 
    //to able to see dbgprint,kdprint messages from the windbg
    *((ULONG *)(KhpNtosBase + 0x5069E8)) = 0xF;
    *((ULONG *)(KhpNtosBase + 0x506A48)) = 0xF;

    DLOG("Ntos base: %p", KhpNtosBase);
    
    return KhpNtosBase;
}

#pragma optimize("",off)

NTSTATUS NTAPI KhpHooked_NtClose(HANDLE khandle)
{
    NTSTATUS status;
    UCHAR processName[15];

    PUCHAR process = (PUCHAR)IoGetCurrentProcess();

    process += 0x450;
    
    RtlCopyMemory(processName, process, sizeof(processName));

    if (!_stricmp(processName, "notepad.exe"))
    {
        DLOG("notepad has kicked the kernel!");
        return STATUS_ACCESS_DENIED; 
    }

    status = KhpOriginalNtClose(khandle);

    //DLOG("%s : NtClose returned: %x", processName, status);

    return status;
}

#pragma optimize("",on)


BOOLEAN NTAPI KhpInit()
{
    ULONG64 ntosBase;
    
    DLOG("Locating NTOS base");

    ntosBase = KhpGetNtosBase();

    if (!ntosBase)
        return FALSE;

    DLOG("Debugger enabled?: %d, Debugger attached?: %d", *KdDebuggerEnabled, !*KdDebuggerNotPresent);
    DLOG("KiDynamicTraceEnabled? %s", (*NTOS_OFFSET(0x56F470, ULONG)) != 0 ? "Enabled" : "Disabled");

    KhpOriginalNtClose = KhpGetAddressBySymbol(L"NtClose");
    KeSetSystemServiceCallback = (PKESETSYSTEMSERVICECALLBACKPTR)(ntosBase + KhpKeSetSystemServiceCallbackOffset);

    DLOG("KeSetSystemServiceCallback is at: %p", KeSetSystemServiceCallback);
    DLOG("Original NtClose: %p", KhpOriginalNtClose);

    return TRUE;
}


BOOLEAN NTAPI KhInitiazeHookSystem()
{
    BOOLEAN status = FALSE;

    if (!KhpInit())
        return FALSE;

    
    DLOG("planting hook handler");

    KhpPlantHookCallbackFunction(KhpHookHandler);

    DLOG("Patching track entry fn");

    KhpEnableDisableWriteProtection(TRUE);

    status = KhpPatchKiTrackSystemCallEntry();

    KhpEnableDisableWriteProtection(FALSE);
    
    if (status)
        DLOG("Hooking system initialized! It's ready to hook syscalls");

    return status;
}

NTSTATUS NTAPI KhSetResetHook(PCHAR syscallName, BOOLEAN set)
{
    PULONG64 callback = NULL;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOLEAN status = FALSE;

    KhpEnableDisableWriteProtection(TRUE);

    if (set)
    {
        callback = KhpHookCallback;
        status = KhpReverseCallbackSetLogic();

        if (!status)
        {
            ntstatus = STATUS_UNSUCCESSFUL;
            goto exit;
        }
    }

    if (!NT_SUCCESS(KeSetSystemServiceCallback("Close", TRUE, callback, NULL)))
    {
        ntstatus = STATUS_UNSUCCESSFUL;
        goto exit;
    }

exit:

    if (status)
        KhpReverseCallbackSetLogic();

    KhpEnableDisableWriteProtection(FALSE);

    return ntstatus;
}



NTSTATUS NTAPI DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PIRP Irp)
{

    if (!KhInitiazeHookSystem())
        return STATUS_UNSUCCESSFUL;
    
    DLOG("setting up hook for NtClose via KeSetSystemServiceCallback");
    
    //NtClose
    if (!NT_SUCCESS(KhSetResetHook("Close",TRUE)))
    {
        DLOG("service callback could not registered");
        return STATUS_UNSUCCESSFUL;
    }
    
    DLOG("The hook set for NtClose success.");

    return STATUS_SUCCESS;
}