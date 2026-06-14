#include "KratosCommon.h"
#include "KratosContext.h"
#include "KratosCallbacks.h"
#include "KratosBlacklist.h"
#include "KratosDetection.h"


// Local declarations
#ifdef __cplusplus
extern "C" {
#endif
    // PROTOTYPES
    NTSTATUS KS_InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
    NTSTATUS KS_InstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
    NTSTATUS KS_KratosUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

    VOID     KS_InstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);
    VOID     KS_InstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags);
    VOID     KS_ProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
    VOID     KS_DefineMiniFilterAltitude(NTSTATUS status, OBJECT_ATTRIBUTES keyAttr);


#ifdef __cplusplus
}
#endif

// Callbacks table

const FLT_OPERATION_REGISTRATION Callbacks[] = {


    {
        IRP_MJ_CREATE,
        0,
        KS_PreCreateCallback,
        KS_PostCreateCallback
    },

    {
        IRP_MJ_WRITE,
        0,
        KS_PreWriteCallback,
        KS_PostWriteCallback
    },

    {
        IRP_MJ_READ,
        0,
        KS_PreReadCallback,
        nullptr
    },

    {
        IRP_MJ_SET_INFORMATION,
        0,
        KS_PreSetInformationCallback,
        nullptr
    },

    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
    {
        FLT_FILE_CONTEXT,
        0,
        nullptr, //(PFLT_CONTEXT_CLEANUP_CALLBACK)KS_FileContext_Cleanup,
        sizeof(KS_FILE_CONTEXT),
        'ctx1'
    },
    {
        FLT_STREAMHANDLE_CONTEXT,
        0,
        nullptr, //(PFLT_CONTEXT_CLEANUP_CALLBACK)KS_HandleContext_Cleanup,
        sizeof(KS_STREAMHANDLE_CONTEXT),
        'ctx2'
    },
    { FLT_CONTEXT_END}
};


const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    ContextRegistration,
    Callbacks,
    KS_KratosUnload,
    KS_InstanceSetup,
    KS_InstanceQueryTeardown,
    KS_InstanceTeardownStart,
    KS_InstanceTeardownComplete,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    nullptr
};

// Define globals
KS_GLOBALS    g_Globals;
RTL_AVL_TABLE g_ProcessCtxTable;
LIST_ENTRY    g_ProcessList;
KSPIN_LOCK    g_ProcessListLock;
FAST_MUTEX    g_ProcessCtxTableLock;
BOOLEAN       g_CallbackRegistred = FALSE;



extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;

    DbgPrint("======================================\n");
    DbgPrint("[Kratos] Driver Initialization        \n");
    DbgPrint("======================================\n");

    OBJECT_ATTRIBUTES keyAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(
        RegistryPath, OBJ_KERNEL_HANDLE);

    KS_DefineMiniFilterAltitude(status, keyAttr);

    ExInitializeFastMutex(&g_ProcessCtxTableLock);
    KeInitializeSpinLock(&g_ProcessListLock);

    RtlInitializeGenericTableAvl(&g_ProcessCtxTable, CompareProcessContextEntries, AllocateAvl, FreeAvl, NULL);

    InitializeListHead(&g_ProcessList);

    // Initialize global resource lock
    status = ExInitializeResourceLite(&g_Globals.GlobalLock);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[kratos] Failed to initialize globals: 0x%08X\n", status);
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx(
        KS_ProcessNotifyCallback,
        FALSE);

    if (!NT_SUCCESS(status))
        return status;
    DbgPrint("[kratos] Registering minifilter...");
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_Globals.FilterHandler);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[kratos] FltRegisterFilter failed: 0x%08X\n", status);
        ExDeleteResourceLite(&g_Globals.GlobalLock);
        return status;
    }

    if (NT_SUCCESS(status)) {
        status = FltStartFiltering(g_Globals.FilterHandler);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[kratos] FltStartFiltering failed: 0x%08X", status);

        }
    }

    if (!NT_SUCCESS(status)) {
        DbgPrint("[kratos] Driver initialization failed, cleaning up...\n");
        if (g_Globals.FilterHandler != NULL) {
            FltUnregisterFilter(g_Globals.FilterHandler);
            g_Globals.FilterHandler = NULL;
        }

        ExDeleteResourceLite(&g_Globals.GlobalLock);
    }

    g_CallbackRegistred = TRUE;

    return status;
}

NTSTATUS KS_KratosUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("======================================\n");
    DbgPrint("[Kratos] Driver Unloading \n");
    DbgPrint("======================================\n");

    if (g_Globals.FilterHandler != nullptr) {
        FltUnregisterFilter(g_Globals.FilterHandler);
        g_Globals.FilterHandler = nullptr;
    }

    if (g_CallbackRegistred) {
        PsSetCreateProcessNotifyRoutineEx(
            KS_ProcessNotifyCallback,
            TRUE);
        g_CallbackRegistred = FALSE;
    }

    KIRQL oldIrql1;
    KeAcquireSpinLock(&g_ProcessListLock, &oldIrql1);

    while (!IsListEmpty(&g_ProcessList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_ProcessList);
        PKS_PROCESS_ENTRY pEntry = CONTAINING_RECORD(entry, KS_PROCESS_ENTRY, ProcessListEntry);

        if (pEntry->ImageFileName.Buffer) {
            ExFreePoolWithTag(pEntry->ImageFileName.Buffer, 'abcs');
            pEntry->ImageFileName.Buffer = NULL;
        }
        ExFreePoolWithTag(pEntry, 'Npsc');
    }

    KeReleaseSpinLock(&g_ProcessListLock, oldIrql1);

    ExAcquireFastMutex(&g_ProcessCtxTableLock);

    while (!RtlIsGenericTableEmptyAvl(&g_ProcessCtxTable)) {
        PVOID element = RtlGetElementGenericTableAvl(&g_ProcessCtxTable, 0);
        if (element) {
            RtlFreeUnicodeString(&((PKS_PROCESS_CONTEXT)element)->ImageFileName);
            RtlDeleteElementGenericTableAvl(&g_ProcessCtxTable, element);
        }
    }
    ExReleaseFastMutex(&g_ProcessCtxTableLock);

    DbgPrint("[Kratos] Cleaning up global state...\n");
    ExDeleteResourceLite(&g_Globals.GlobalLock);

    return STATUS_SUCCESS;
}


VOID KS_ProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);



    if (CreateInfo != nullptr) {

        // Checking of blacklist
        if (KS_IsBlacklisted(ProcessId)) {
            DbgPrint("[Kratos] BLOCKED LAUNCH PID=%lu %wZ\n",
                HandleToULong(ProcessId),
                CreateInfo->ImageFileName);
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }

        // Creating of context
        PKS_PROCESS_CONTEXT procCtx =
            KS_FindOrCreateProcessContext(ProcessId);

        if (procCtx) {
            PEPROCESS process = nullptr;

            if (NT_SUCCESS(PsLookupProcessByProcessId(
                ProcessId, &process)))
            {
                PUCHAR shortName =
                    PsGetProcessImageFileName(process);

                // Whitelist Name + Path
                procCtx->IsWhitelisted = KS_IsWhitelistedFull(
                    shortName,
                    CreateInfo->ImageFileName);

                // Imposter detection
                if (!procCtx->IsWhitelisted && shortName) {
                    if (KS_IsWhitelisted(shortName)) {
                        procCtx->ThreatScore = 40;
                        procCtx->IsSuspicious = TRUE;
                        DbgPrint("[Kratos] IMPERSONATOR PID=%lu "
                            "name=%s path=%wZ\n",
                            HandleToULong(ProcessId),
                            shortName,
                            CreateInfo->ImageFileName);
                    }
                }

                ObDereferenceObject(process);
            }
        }

        PKS_PROCESS_ENTRY newProcess = (PKS_PROCESS_ENTRY)
            ExAllocatePool2(POOL_FLAG_NON_PAGED,
                sizeof(KS_PROCESS_ENTRY), 'Npsc');

        if (newProcess == nullptr) {
            DbgPrint("[Kratos] Allocation failed for PID=%p\n",
                ProcessId);
            return;
        }

        RtlZeroMemory(newProcess, sizeof(*newProcess));
        newProcess->ProcessId = ProcessId;
        newProcess->ParentProcessId = CreateInfo->ParentProcessId;
        KeQuerySystemTime(&newProcess->CreateTime);

        if (CreateInfo->ImageFileName &&
            CreateInfo->ImageFileName->Length > 0)
        {
            USHORT lengthBytes = CreateInfo->ImageFileName->Length;
            SIZE_T sizeAlloc = (SIZE_T)lengthBytes + sizeof(WCHAR);

            PWCHAR buff = (PWCHAR)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeAlloc, 'abcs');

            if (buff != NULL) {
                RtlCopyMemory(buff,
                    CreateInfo->ImageFileName->Buffer,
                    lengthBytes);
                buff[lengthBytes / sizeof(WCHAR)] = L'\0';

                newProcess->ImageFileName.Length = lengthBytes;
                newProcess->ImageFileName.MaximumLength = (USHORT)sizeAlloc;
                newProcess->ImageFileName.Buffer = buff;
            }
            else {
                DbgPrint("[Kratos] ImageFileName alloc failed "
                    "for PID=%p\n", ProcessId);
            }
        }

        // Insert into ProcessList
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_ProcessListLock, &oldIrql);
        InsertTailList(&g_ProcessList, &newProcess->ProcessListEntry);
        KeReleaseSpinLock(&g_ProcessListLock, oldIrql);
    }
    else {


        DbgPrint("[Kratos] Process %lu removed\n",
            HandleToULong(ProcessId));

        KS_PROCESS_CONTEXT lookup = { 0 };
        lookup.ProcessId = ProcessId;

        ExAcquireFastMutex(&g_ProcessCtxTableLock);

        PKS_PROCESS_CONTEXT actualCtx =
            (PKS_PROCESS_CONTEXT)RtlLookupElementGenericTableAvl(
                &g_ProcessCtxTable, &lookup);

        if (actualCtx) {

            if (actualCtx->ImageFileName.Buffer) {

                RtlFreeUnicodeString(&actualCtx->ImageFileName);
                actualCtx->ImageFileName.Buffer = nullptr;
            }

            RtlDeleteElementGenericTableAvl(
                &g_ProcessCtxTable, &lookup);
        }

        ExReleaseFastMutex(&g_ProcessCtxTableLock);

        KIRQL oldIrql2;
        KeAcquireSpinLock(&g_ProcessListLock, &oldIrql2);

        PLIST_ENTRY entry = g_ProcessList.Flink;
        while (entry != &g_ProcessList) {
            PLIST_ENTRY nextEntry = entry->Flink;
            PKS_PROCESS_ENTRY pEntry = CONTAINING_RECORD(
                entry, KS_PROCESS_ENTRY, ProcessListEntry);

            if (pEntry->ProcessId == ProcessId) {
                RemoveEntryList(entry);
                if (pEntry->ImageFileName.Buffer) {
                    ExFreePoolWithTag(
                        pEntry->ImageFileName.Buffer, 'abcs');
                    pEntry->ImageFileName.Buffer = NULL;
                }
                ExFreePoolWithTag(pEntry, 'Npsc');
                break;
            }
            entry = nextEntry;
        }

        KeReleaseSpinLock(&g_ProcessListLock, oldIrql2);
    }

}
VOID KS_DefineMiniFilterAltitude(NTSTATUS status, OBJECT_ATTRIBUTES keyAttr)
{
    HANDLE hKey = NULL;
    HANDLE hSubKey = NULL;
    HANDLE hInstKey = NULL;

    __try {
        status = ZwOpenKey(&hKey, KEY_WRITE, &keyAttr);
        if (!NT_SUCCESS(status)) __leave;

        UNICODE_STRING subKey = RTL_CONSTANT_STRING(L"Instances");
        OBJECT_ATTRIBUTES subKeyAttr;
        InitializeObjectAttributes(&subKeyAttr, &subKey,
            OBJ_KERNEL_HANDLE, hKey, NULL);

        status = ZwCreateKey(&hSubKey, KEY_WRITE,
            &subKeyAttr, 0, NULL, 0, NULL);
        if (!NT_SUCCESS(status)) __leave;

        UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"DefaultInstance");
        WCHAR name[] = L"kratos";
        status = ZwSetValueKey(hSubKey, &valueName, 0,
            REG_SZ, name, sizeof(name));
        if (!NT_SUCCESS(status)) __leave;

        UNICODE_STRING instKeyName;
        RtlInitUnicodeString(&instKeyName, name);
        InitializeObjectAttributes(&subKeyAttr, &instKeyName,
            OBJ_KERNEL_HANDLE, hSubKey, NULL);

        status = ZwCreateKey(&hInstKey, KEY_WRITE,
            &subKeyAttr, 0, NULL, 0, NULL);
        if (!NT_SUCCESS(status)) __leave;

        WCHAR altitude[] = L"425342";
        UNICODE_STRING altitudeName = RTL_CONSTANT_STRING(L"Altitude");
        ZwSetValueKey(hInstKey, &altitudeName, 0,
            REG_SZ, altitude, sizeof(altitude));

        UNICODE_STRING flagsName = RTL_CONSTANT_STRING(L"Flags");
        ULONG flags = 0;
        ZwSetValueKey(hInstKey, &flagsName, 0,
            REG_DWORD, &flags, sizeof(flags));
    }
    __finally {
        if (hInstKey) ZwClose(hInstKey);
        if (hSubKey)  ZwClose(hSubKey);
        if (hKey)     ZwClose(hKey);
    }
}

VOID KS_InstanceTeardownStart(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

VOID KS_InstanceTeardownComplete(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

NTSTATUS KS_InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);

    // Only attach to NTFS and ReFS volumes
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS &&
        VolumeFilesystemType != FLT_FSTYPE_REFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    // Don't attach to network file systems
    if (VolumeFilesystemType == FLT_FSTYPE_LANMAN ||
        VolumeFilesystemType == FLT_FSTYPE_WEBDAV ||
        VolumeFilesystemType == FLT_FSTYPE_NFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    DbgPrint("[Kratos] Attached to volume (Instance: %p)\n", FltObjects->Instance);

    return STATUS_SUCCESS;
}
NTSTATUS KS_InstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    return STATUS_SUCCESS;
}
