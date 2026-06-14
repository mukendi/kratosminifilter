#include "KratosBlacklist.h"

KS_HASH64 KS_FNV1a64(PUCHAR data, ULONG size)
{
    KS_HASH64 hash = FNV_OFFSET_BASIS_64;

    for (ULONG i = 0; i < size; i++) {
        hash ^= (KS_HASH64)data[i];
        hash *= FNV_PRIME_64;
    }
    return hash;
}

NTSTATUS KS_KillProcess(HANDLE ProcessId)
{
    NTSTATUS status;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES objAttributes;
    CLIENT_ID clientId;

    // Initialize the structures to open the process
    InitializeObjectAttributes(&objAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    // Open the process with termination privileges
    status = ZwOpenProcess(
        &processHandle,
        PROCESS_TERMINATE,
        &objAttributes,
        &clientId
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Kratos] KS_KillProcess: Failed to open process PID=%lu (Status: 0x%X)\n",
            HandleToULong(ProcessId), status);
        return status;
    }

    // Kill the process (0x1C often corresponds to a custom exit error code)
    status = ZwTerminateProcess(processHandle, STATUS_ACCESS_DENIED);

    if (NT_SUCCESS(status)) {
        DbgPrint("[Kratos] SUCCESS Process PID=%lu has been terminated.\n", HandleToULong(ProcessId));
    }
    else {
        DbgPrint("[Kratos] KS_KillProcess: ZwTerminateProcess failed for PID=%lu (Status: 0x%X)\n",
            HandleToULong(ProcessId), status);
    }

    ZwClose(processHandle);

    return status;
}
NTSTATUS KS_ComputeProcessHash(_In_  HANDLE ProcessId, _Out_ KS_HASH64* OutHash)
{
    *OutHash = 0;

    if (KeGetCurrentIrql() > PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    PEPROCESS process = NULL;
    NTSTATUS  status = PsLookupProcessByProcessId(ProcessId,
        &process);
    if (!NT_SUCCESS(status)) return status;

    PUNICODE_STRING imagePath = NULL;
    status = SeLocateProcessImageName(process, &imagePath);
    ObDereferenceObject(process);

    if (!NT_SUCCESS(status) || !imagePath) return status;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa,
        imagePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    IO_STATUS_BLOCK iosb = { 0 };
    HANDLE          hFile = NULL;

    status = ZwOpenFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

    ExFreePool(imagePath);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Kratos] Hash: ZwOpenFile failed 0x%X\n", status);
        return status;
    }

    PUCHAR buffer = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, HASH_SAMPLE_SIZE, 'KHSH');

    if (!buffer) {
        ZwClose(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LARGE_INTEGER offset = { 0 };
    ULONG         bytesRead = 0;

    status = ZwReadFile(
        hFile, NULL, NULL, NULL,
        &iosb,
        buffer, HASH_SAMPLE_SIZE,
        &offset, NULL);

    ZwClose(hFile);

    if (!NT_SUCCESS(status) && status != STATUS_END_OF_FILE) {
        ExFreePool(buffer);
        DbgPrint("[Kratos] Hash: ZwReadFile failed 0x%X\n", status);
        return status;
    }

    bytesRead = (ULONG)iosb.Information;

    *OutHash = KS_FNV1a64(buffer, bytesRead);

    DbgPrint("[Kratos] Hash computed: %016llX (%lu bytes sampled)\n",
        *OutHash, bytesRead);

    ExFreePool(buffer);
    return STATUS_SUCCESS;
}

VOID KS_BlacklistProcess(PKS_PROCESS_CONTEXT ctx, KS_HASH64 hash)
{
    if (!ctx) return;

    NTSTATUS          status;
    HANDLE            hParent = NULL;
    HANDLE            hKey = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING    path;

    RtlInitUnicodeString(&path,
        L"\\Registry\\Machine\\SOFTWARE\\Kratos");

    InitializeObjectAttributes(&oa, &path,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, NULL);

    status = ZwCreateKey(
        &hParent,
        KEY_CREATE_SUB_KEY,
        &oa, 0, NULL,
        REG_OPTION_NON_VOLATILE,
        NULL);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Kratos] Blacklist: parent key failed 0x%X\n",
            status);
        return;
    }

    UNICODE_STRING subKeyName =
        RTL_CONSTANT_STRING(L"Blacklist");

    InitializeObjectAttributes(&oa, &subKeyName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        hParent,
        NULL);

    status = ZwCreateKey(
        &hKey,
        KEY_SET_VALUE,
        &oa, 0, NULL,
        REG_OPTION_NON_VOLATILE,
        NULL);

    ZwClose(hParent);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Kratos] Blacklist: ZwCreateKey failed 0x%X\n",
            status);
        return;
    }


    WCHAR          valueName[20] = { 0 };
    UNICODE_STRING valueStr;

    RtlStringCchPrintfW(valueName, ARRAYSIZE(valueName),
        L"%016llX", hash);
    RtlInitUnicodeString(&valueStr, valueName);

    PWCHAR dataBuffer = ctx->ImageFileName.Buffer
        ? ctx->ImageFileName.Buffer
        : L"Unknown";

    ULONG dataSize = ctx->ImageFileName.Buffer
        ? (ctx->ImageFileName.Length + sizeof(WCHAR))
        : sizeof(L"Unknown");

    status = ZwSetValueKey(hKey, &valueStr, 0,
        REG_SZ, dataBuffer, dataSize);

    if (NT_SUCCESS(status)) {
        DbgPrint("[Kratos] BLACKLISTED: hash=%016llX | %wZ\n",
            hash, &ctx->ImageFileName);
    }

    ZwClose(hKey);
}

VOID KS_KillProcessWorkerRoutine(PVOID Context)
{
    PKS_KILL_WORKER_CTX workerCtx = (PKS_KILL_WORKER_CTX)Context;
    if (!workerCtx) return;


    KS_KillProcess(workerCtx->ProcessId);

    LARGE_INTEGER delay;
    delay.QuadPart = -5000000LL;
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    ExFreePoolWithTag(workerCtx, 'wKIL');
}


BOOLEAN KS_IsBlacklisted(HANDLE ProcessId)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FALSE;
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId,
        &process)))
        return FALSE;

    PUCHAR name = PsGetProcessImageFileName(process);

    if (name && KS_IsWhitelisted(name)) {
        ObDereferenceObject(process);
        return FALSE;
    }

    ObDereferenceObject(process);
    KS_HASH64 hash = 0;
    NTSTATUS  status = KS_ComputeProcessHash(ProcessId, &hash);

    if (!NT_SUCCESS(status) || hash == 0) return FALSE;

    HANDLE            hKey = NULL;
    OBJECT_ATTRIBUTES keyAttr;
    UNICODE_STRING    keyPath;

    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\SOFTWARE\\Kratos\\Blacklist");

    InitializeObjectAttributes(
        &keyAttr,
        &keyPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &keyAttr);
    if (!NT_SUCCESS(status)) return FALSE;

    WCHAR          valueName[20] = { 0 };
    UNICODE_STRING valueStr;

    RtlStringCchPrintfW(valueName, ARRAYSIZE(valueName),
        L"%016llX", hash);
    RtlInitUnicodeString(&valueStr, valueName);

    UCHAR  buf[512] = { 0 };
    ULONG  resultLen = 0;

    KEY_VALUE_PARTIAL_INFORMATION* info =
        (KEY_VALUE_PARTIAL_INFORMATION*)buf;

    status = ZwQueryValueKey(
        hKey,
        &valueStr,
        KeyValuePartialInformation,
        info,
        sizeof(buf),
        &resultLen);

    ZwClose(hKey);

    if (NT_SUCCESS(status)) {
        DbgPrint("[Kratos] BLACKLIST HIT: hash=%016llX  BLOCKED\n", hash);
        return TRUE;
    }

    return FALSE;
}

BOOLEAN KS_IsWhitelisted(PUCHAR processName)
{
    if (!processName) return FALSE;

    for (int i = 0; g_TrustedProcesses[i].Name != NULL; i++) {
        if (_stricmp((PCHAR)processName,
            g_TrustedProcesses[i].Name) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}
