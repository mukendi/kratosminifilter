#include "KratosCallbacks.h"
#include "KratosDetection.h"
#include "KratosContext.h"


FLT_PREOP_CALLBACK_STATUS  KS_PreSetInformationCallback(PFLT_CALLBACK_DATA    Data, PCFLT_RELATED_OBJECTS   FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    // Filtering of paging operations and non-hidden I/O
    if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_NOCACHE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (PsIsThreadTerminating(PsGetCurrentThread())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE pid = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(Data);

    // Ignore System process
    if (pid == (HANDLE)4 || PsGetCurrentProcessId() == (HANDLE)4) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PKS_PROCESS_CONTEXT procCtx = KS_FindOrCreateProcessContext(pid);
    if (!procCtx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // ENFORCEMENT BLOCK: If the process is already marked as malicious
    if (procCtx->IsBlocked) {
        if (infoClass == FileDispositionInformation ||
            infoClass == FileDispositionInformationEx ||
            infoClass == FileRenameInformation ||
            infoClass == FileRenameInformationEx)
        {
            DbgPrint("[Kratos] ENFORCEMENT: Safely Blocking Rename/Delete for PID=%lu (Class=%d)\n",
                HandleToULong(pid), infoClass);

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // DELETION PROCESSING (FileDisposition)
    if (infoClass == FileDispositionInformation || infoClass == FileDispositionInformationEx)
    {
        PFILE_DISPOSITION_INFORMATION info = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (info && info->DeleteFile) {
            procCtx->DeleteCount++;

            // Securely retrieve filenames
            PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
                FltParseFileNameInformation(nameInfo);
                FltReleaseFileNameInformation(nameInfo);
            }

            DbgPrint("[Kratos] DELETE PID=%lu total=%lu\n", HandleToULong(pid), procCtx->DeleteCount);

            // Behavioral assessment
            KS_EvaluateThreatScore(procCtx, FltObjects->Instance);

            // ATOMIC CORRECTION: If Hercules' score exceeded 90 during this call, we block the I/O immediately!
            if (procCtx->IsBlocked) {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // RENAMING PROCESSING (FileRename)
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        PFILE_RENAME_INFORMATION info = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        if (info && info->FileNameLength > 0) {
            UNICODE_STRING newName;
            newName.Buffer = info->FileName;
            newName.Length = (USHORT)info->FileNameLength;
            newName.MaximumLength = (USHORT)info->FileNameLength;

            procCtx->RenameCount++;

            PFLT_FILE_NAME_INFORMATION orgInfo = nullptr;
            BOOLEAN   originalWasValue = FALSE;

            if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &orgInfo))) {
                FltParseFileNameInformation(orgInfo);
                originalWasValue = KS_IsValuableFile(&orgInfo->Name);
            }

            UNICODE_STRING newExt = { 0 };
            USHORT nameChars = newName.Length / sizeof(WCHAR);

            for (USHORT i = nameChars; i > 0; i--) {
                if (newName.Buffer[i - 1] == L'.') {
                    newExt.Buffer = &newName.Buffer[i - 1];
                    newExt.Length = newName.Length - ((i - 1) * sizeof(WCHAR));
                    newExt.MaximumLength = newExt.Length;
                    break;
                }
                if (newName.Buffer[i - 1] == L'\\') break;
            }

            // Evaluate Score 

            if (originalWasValue && newExt.Buffer != nullptr) {

                if (!KS_IsLegitExtension(&newExt)) {

                    procCtx->RenameToSuspicious++;

                    DbgPrint("[Kratos] SUSPICIOUS RENAME with unkwon ext"
                        ": %wZ -  %wZ "
                        "PID=%lu\n",
                        (orgInfo ? &orgInfo->Name : NULL),
                        &newExt,
                        HandleToULong(pid));
                }

            }

            KS_EvaluateThreatScore(procCtx, FltObjects->Instance);

            if (KS_HasSuspiciousExtension(&newName)) {
                procCtx->RenameToSuspicious++;
                DbgPrint("[Kratos] SUSPICIOUS RENAME : %wZ PID=%lu\n", &newName, HandleToULong(pid));

                PKS_FILE_CONTEXT fileCtx = NULL;
                NTSTATUS status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&fileCtx);

                if (NT_SUCCESS(status) && fileCtx != NULL) {
                    FltReleaseContext((PFLT_CONTEXT)fileCtx);
                }
            }

            if (orgInfo) {
                FltReleaseFileNameInformation(orgInfo);
                orgInfo = NULL;
            }
            KS_EvaluateThreatScore(procCtx, FltObjects->Instance);

            // Post-evaluation check for renaming as well
            if (procCtx->IsBlocked) {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
FLT_POSTOP_CALLBACK_STATUS KS_PostSetInformationCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileDispositionInformation ||
        infoClass == FileDispositionInformationEx ||
        infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx)
    {
        //DbgPrint("[Kratos] PostSetInfo confirmed | ""PID=%lu | Class=%d\n",FltGetRequestorProcessId(Data), infoClass);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS  KS_PreReadCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_NOCACHE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (PsIsThreadTerminating(PsGetCurrentThread())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    BOOLEAN isDir = FALSE;
    if (NT_SUCCESS(FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir)) && isDir) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Retrieve the file context
    PKS_FILE_CONTEXT fileCtx = NULL;
    NTSTATUS status = FltGetFileContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&fileCtx
    );

    if (!NT_SUCCESS(status) || fileCtx == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    InterlockedIncrement((LONG*)&fileCtx->ReadCount);
    FltReleaseContext((PFLT_CONTEXT)fileCtx);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS KS_PostReadCallback(
    _Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS  FltObjects, _In_opt_ PVOID  CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Flags & FLTFL_POST_OPERATION_DRAINING)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (Data->Iopb->IrpFlags & IRP_PAGING_IO)
        return FLT_POSTOP_FINISHED_PROCESSING;


    PKS_FILE_CONTEXT fileCtx = NULL;
    NTSTATUS status = FltGetFileContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&fileCtx);

    if (!NT_SUCCESS(status) || !fileCtx)
        return FLT_POSTOP_FINISHED_PROCESSING;

    FltReleaseContext((PFLT_CONTEXT)fileCtx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS KS_PreCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_NOCACHE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (PsIsThreadTerminating(PsGetCurrentThread())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS KS_PostCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags) {
    if (!NT_SUCCESS(Data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (Flags & FLTFL_POST_OPERATION_DRAINING)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        return KS_PostCreateCallbackSafe(
            Data, FltObjects, CompletionContext, Flags);
    }

    FLT_POSTOP_CALLBACK_STATUS retStatus =
        FLT_POSTOP_FINISHED_PROCESSING;

    BOOLEAN queued = FltDoCompletionProcessingWhenSafe(
        Data,
        FltObjects,
        CompletionContext,
        Flags,
        KS_PostCreateCallbackSafe,
        &retStatus);

    if (!queued) {

        //DbgPrint("[Kratos] FltDoCompletionProcessingWhenSafe "failed\n");
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_MORE_PROCESSING_REQUIRED;

}

FLT_POSTOP_CALLBACK_STATUS KS_PostCreateCallbackSafe(PFLT_CALLBACK_DATA  Data, PCFLT_RELATED_OBJECTS  FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    BOOLEAN isDir = FALSE;
    FltIsDirectory(
        FltObjects->FileObject,
        FltObjects->Instance,
        &isDir);
    if (isDir) return FLT_POSTOP_FINISHED_PROCESSING;


    PKS_FILE_CONTEXT fileCtx = NULL;
    NTSTATUS status = FltGetFileContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&fileCtx);
    if (!NT_SUCCESS(status)) {
        status = FltAllocateContext(
            g_Globals.FilterHandler,
            FLT_FILE_CONTEXT,
            sizeof(KS_FILE_CONTEXT),
            NonPagedPool,
            (PFLT_CONTEXT*)&fileCtx);

        if (!NT_SUCCESS(status))
            return FLT_POSTOP_FINISHED_PROCESSING;

        RtlZeroMemory(fileCtx, sizeof(KS_FILE_CONTEXT));
        KeInitializeSpinLock(&fileCtx->Lock);

        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        {
            FltParseFileNameInformation(nameInfo);
            ULONG len = min(
                (ULONG)nameInfo->Name.Length,
                (ULONG)(sizeof(fileCtx->FileName) - sizeof(WCHAR)));
            RtlCopyMemory(fileCtx->FileName,
                nameInfo->Name.Buffer, len);

            FltReleaseFileNameInformation(nameInfo);
        }

        PKS_FILE_CONTEXT oldCtx = NULL;
        status = FltSetFileContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            fileCtx,
            (PFLT_CONTEXT*)&oldCtx);

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            FltReleaseContext((PFLT_CONTEXT)fileCtx);
            fileCtx = oldCtx;
        }
        else if (!NT_SUCCESS(status)) {
            FltReleaseContext((PFLT_CONTEXT)fileCtx);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }


    FltReleaseContext((PFLT_CONTEXT)fileCtx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS KS_PreWriteCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    if (FLT_IS_SYSTEM_BUFFER(Data))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if ((Data->Iopb->IrpFlags & IRP_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ||
        (Data->Iopb->IrpFlags & IRP_NOCACHE))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (PsIsThreadTerminating(PsGetCurrentThread())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() > APC_LEVEL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (!FltSupportsFileContexts(FltObjects->FileObject)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE pid = (HANDLE)(ULONG_PTR)FltGetRequestorProcessId(Data);

    NTSTATUS status;
    PKS_FILE_CONTEXT fileCtx = NULL;
    PKS_STREAMHANDLE_CONTEXT handleCtx = NULL;

    status = FltGetFileContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        (PFLT_CONTEXT*)&fileCtx);

    if (!NT_SUCCESS(status) || !fileCtx) {

        status = FltAllocateContext(
            g_Globals.FilterHandler,
            FLT_FILE_CONTEXT,
            sizeof(KS_FILE_CONTEXT),
            NonPagedPool,
            (PFLT_CONTEXT*)&fileCtx);

        if (!NT_SUCCESS(status) || fileCtx == NULL) {
            DbgPrint("[Kratos] PreWrite: FltAllocateContext "
                "failed 0x%X\n", status);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        RtlZeroMemory(fileCtx, sizeof(KS_FILE_CONTEXT));
        KeInitializeSpinLock(&fileCtx->Lock);

        // Retrieve the file name
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED |
            FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo)))
        {
            FltParseFileNameInformation(nameInfo);

            ULONG len = min(
                (ULONG)nameInfo->Name.Length,
                (ULONG)(sizeof(fileCtx->FileName) - sizeof(WCHAR)));
            RtlCopyMemory(fileCtx->FileName,
                nameInfo->Name.Buffer, len);
            FltReleaseFileNameInformation(nameInfo);
        }

        // Attach to file
        PKS_FILE_CONTEXT oldCtx = NULL;
        status = FltSetFileContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS,
            fileCtx,
            (PFLT_CONTEXT*)&oldCtx);

        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            FltReleaseContext((PFLT_CONTEXT)fileCtx);
            fileCtx = oldCtx;
        }
        else if (!NT_SUCCESS(status)) {
            DbgPrint("[Kratos] PreWrite: FltSetFileContext ""failed 0x%X\n", status);
            FltReleaseContext((PFLT_CONTEXT)fileCtx);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        status = FltGetStreamHandleContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            (PFLT_CONTEXT*)&handleCtx);

        if (!NT_SUCCESS(status) || handleCtx == NULL) {

            status = FltAllocateContext(
                g_Globals.FilterHandler,
                FLT_STREAMHANDLE_CONTEXT,
                sizeof(KS_STREAMHANDLE_CONTEXT),
                NonPagedPool,
                (PFLT_CONTEXT*)&handleCtx);

            if (NT_SUCCESS(status) && handleCtx) {
                RtlZeroMemory(handleCtx, sizeof(KS_STREAMHANDLE_CONTEXT));
                handleCtx->ProcessId = HandleToULong(pid);

                FltSetStreamHandleContext(
                    FltObjects->Instance,
                    FltObjects->FileObject,
                    FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                    handleCtx,
                    NULL);
            }
        }
    }


    PKS_PROCESS_CONTEXT procCtx = KS_FindOrCreateProcessContext(pid);
    if (!procCtx) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PVOID buffer = NULL;
    ULONG length = Data->Iopb->Parameters.Write.Length;

    if (Data->Iopb->Parameters.Write.MdlAddress) {
        buffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
    }
    else {
        buffer = Data->Iopb->Parameters.Write.WriteBuffer;
    }

    if (buffer && length > 0 && fileCtx) {

        ULONG sampleSize = min(length, 512UL);
        ULONG currentEntropy = KS_CalculateEntropyFast((PUCHAR)buffer, sampleSize);


        if (!fileCtx->EntropyBeforeCaptured) {
            fileCtx->EntropyBefore = currentEntropy;
            fileCtx->EntropyBeforeCaptured = TRUE;
        }

        LONG delta = (LONG)(currentEntropy)-(LONG)fileCtx->EntropyBefore;

        if ((fileCtx->EntropyBefore < 6 && delta >= 3) || (fileCtx->EntropyBefore >= 6 && currentEntropy == 8)) {
            if (procCtx) {
                procCtx->HighEntropyWrites++;
                KS_EvaluateThreatScore(procCtx, FltObjects->Instance);

                if (procCtx->ThreatScore >= 80) {

                    DbgPrint("[Kratos] BLOCKED PID=%lu\n", HandleToULong(pid));
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;

                    FltReleaseContext((PFLT_CONTEXT)fileCtx);
                    if (handleCtx) FltReleaseContext((PFLT_CONTEXT)handleCtx);
                    return FLT_PREOP_COMPLETE;
                }
            }
        }
    }

    KS_COMPLETION_CTX* cc = (KS_COMPLETION_CTX*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KS_COMPLETION_CTX), 'CCTX');
    if (cc) {
        cc->File = fileCtx;
        cc->Handle = handleCtx;
        *CompletionContext = cc;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    FltReleaseContext((PFLT_CONTEXT)fileCtx);
    if (handleCtx) FltReleaseContext((PFLT_CONTEXT)handleCtx);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS KS_PostWriteCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    UNREFERENCED_PARAMETER(FltObjects);

    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        KS_COMPLETION_CTX* cc = (KS_COMPLETION_CTX*)CompletionContext;
        if (cc) {
            if (cc->File) FltReleaseContext((PFLT_CONTEXT)cc->File);
            if (cc->Handle) FltReleaseContext((PFLT_CONTEXT)cc->Handle);
            ExFreePoolWithTag(cc, 'CCTX');
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    KS_COMPLETION_CTX* cc = (KS_COMPLETION_CTX*)CompletionContext;
    if (!cc) return FLT_POSTOP_FINISHED_PROCESSING;

    PKS_FILE_CONTEXT fileCtx = cc->File;
    PKS_STREAMHANDLE_CONTEXT handleCtx = cc->Handle;

    if (NT_SUCCESS(Data->IoStatus.Status) && fileCtx) {
        KIRQL oldIrql;

        KeAcquireSpinLock(&fileCtx->Lock, &oldIrql);

        fileCtx->WriteCount++;
        if (handleCtx) {
            handleCtx->WriteCount++;
        }

        KeReleaseSpinLock(&fileCtx->Lock, oldIrql);
    }

    if (fileCtx)   FltReleaseContext((PFLT_CONTEXT)fileCtx);
    if (handleCtx) FltReleaseContext((PFLT_CONTEXT)handleCtx);

    ExFreePoolWithTag(cc, 'CCTX');

    return FLT_POSTOP_FINISHED_PROCESSING;
}
