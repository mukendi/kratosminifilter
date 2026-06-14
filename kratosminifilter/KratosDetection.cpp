#include "KratosDetection.h"
#include "KratosBlacklist.h"

VOID KS_EvaluateThreatScore(PKS_PROCESS_CONTEXT ctx, PFLT_INSTANCE Instance)
{
    if (!ctx) return;
    if (ctx->IsWhitelisted) return;
    if (ctx->IsBlocked) return;

    ULONG score = 0;

    if (ctx->TotalWriteOperations > 100)          score += 25;
    if (ctx->DeleteCount > 20)                    score += 5;
    if (ctx->RenameToSuspicious > 2)              score += 40;
    if (ctx->RansomNoteCreated)                   score += 60;
    if (ctx->ShadowCopyDeleted)                   score += 75;
    if (ctx->HighEntropyWrites > 3)               score += 40;
    else if (ctx->HighEntropyWrites > 0)          score += 20;
    if (ctx->WriteWithoutRead > 10)               score += 25;

    if (ctx->ValuableDeleteCount > 10)            score += 10;
    else if (ctx->ValuableDeleteCount > 5)        score += 5;
    else if (ctx->ValuableDeleteCount > 2)        score += 2;

    ctx->ThreatScore = score;

    if (score >= 60 && score < 80) {
        ctx->IsSuspicious = TRUE;
        DbgPrint("[Kratos] WARNING PID=%lu %wZ score=%lu "
            "VD:%lu R:%lu HE:%lu\n",
            HandleToULong(ctx->ProcessId),
            ctx->ImageFileName.Buffer
            ? &ctx->ImageFileName
            : NULL,
            score,
            ctx->ValuableDeleteCount,
            ctx->RenameToSuspicious,
            ctx->HighEntropyWrites);
    }

    if (score >= 80) {
        ctx->IsSuspicious = TRUE;
        ctx->IsBlocked = TRUE;

        DbgPrint("[Kratos] CRITICAL PID=%lu %wZ score=%lu\n",
            HandleToULong(ctx->ProcessId),
            ctx->ImageFileName.Buffer ? &ctx->ImageFileName : NULL,
            score);


        KS_HASH64 hash = 0;
        NTSTATUS  hstatus = KS_ComputeProcessHash(
            ctx->ProcessId, &hash);

        if (NT_SUCCESS(hstatus) && hash != 0) {
            KS_BlacklistProcess(ctx, hash);
        }
        else {
            DbgPrint("[Kratos] Hash failed 0x%X � blacklist skipped\n",
                hstatus);
        }

        PKS_KILL_WORKER_CTX workerCtx = (PKS_KILL_WORKER_CTX)
            ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(KS_KILL_WORKER_CTX),
                'wKIL');

        if (!workerCtx) {
            if (KeGetCurrentIrql() == PASSIVE_LEVEL)
                KS_KillProcess(ctx->ProcessId);
            return;
        }

        RtlZeroMemory(workerCtx, sizeof(KS_KILL_WORKER_CTX));
        workerCtx->ProcessId = ctx->ProcessId;
        workerCtx->Instance = Instance;
        workerCtx->FileCount = 0;
        InitializeListHead(&workerCtx->FilesToRestore);

        ExInitializeWorkItem(
            &workerCtx->WorkItem,
            KS_KillProcessWorkerRoutine,
            workerCtx);
        ExQueueWorkItem(&workerCtx->WorkItem, CriticalWorkQueue);
    }
}

ULONG KS_CalculateEntropyFast(PUCHAR Buffer, ULONG Size) {
    if (!Buffer || Size == 0) return 0;

    ULONG freq[256] = { 0 };
    ULONG sampleSize = (Size < 512) ? Size : 512;
    for (ULONG i = 0; i < sampleSize; i++) {
        freq[Buffer[i]]++;
    }

    ULONG totalEntropy100000 = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;

        ULONG index = freq[i];
        if (sampleSize < 512) {
            index = (freq[i] * 512) / sampleSize;
        }

        if (index > 512) index = 512;

        totalEntropy100000 += KratosEntropyLUT512[index];
    }
    return totalEntropy100000 / 1000;
}

BOOLEAN KS_HasSuspiciousExtension(PUNICODE_STRING FileName)
{
    if (!FileName || !FileName->Buffer) return FALSE;

    for (int i = 0; g_SuspiciousExtensions[i] != NULL; i++) {
        UNICODE_STRING ext;
        RtlInitUnicodeString(&ext, g_SuspiciousExtensions[i]);
        if (RtlSuffixUnicodeString(&ext, FileName, TRUE))
            return TRUE;
    }
    return FALSE;
}

BOOLEAN KS_IsRansomNote(PUNICODE_STRING FileName)
{
    if (!FileName || !FileName->Buffer) return FALSE;

    for (int i = 0; g_RansomNoteNames[i] != NULL; i++) {
        UNICODE_STRING note;
        RtlInitUnicodeString(&note, g_RansomNoteNames[i]);
        if (RtlPrefixUnicodeString(&note, FileName, TRUE))
            return TRUE;
    }
    return FALSE;
}

BOOLEAN KS_PathContainsCI(PCUNICODE_STRING FullPath,
    PCWSTR           SubPath)
{
    if (!FullPath || !FullPath->Buffer || !SubPath) return FALSE;

    USHORT subLen = (USHORT)wcslen(SubPath);
    USHORT pathLen = FullPath->Length / sizeof(WCHAR);

    if (subLen > pathLen) return FALSE;

    for (USHORT i = 0; i <= pathLen - subLen; i++) {
        if (_wcsnicmp(&FullPath->Buffer[i], SubPath, subLen) == 0)
            return TRUE;
    }
    return FALSE;
}
BOOLEAN KS_IsWhitelistedFull(PUCHAR  processName, PCUNICODE_STRING  fullImagePath) {

    if (!processName) return FALSE;

    for (int i = 0; g_TrustedProcesses[i].Name != NULL; i++) {

        if (_stricmp((PCHAR)processName,
            g_TrustedProcesses[i].Name) != 0)
            continue;


        if (!fullImagePath || !fullImagePath->Buffer) {

            return FALSE;
        }

        if (KS_PathContainsCI(fullImagePath,
            g_TrustedProcesses[i].ExpectedPath))
        {
            return TRUE;
        }

        DbgPrint("[Kratos] IMPERSONATION: %s from unexpected "
            "path %wZ\n",
            processName, fullImagePath);

        return FALSE;
    }

    return FALSE;
}


BOOLEAN KS_IsValuableFile(PUNICODE_STRING FilePath)
{
    if (!FilePath || !FilePath->Buffer) return FALSE;

    for (int i = 0; g_IgnoredPaths[i] != NULL; i++) {
        if (wcsstr(FilePath->Buffer, g_IgnoredPaths[i]) != NULL)
            return FALSE;
    }

    USHORT totalChars = FilePath->Length / sizeof(WCHAR);
    USHORT extStart = totalChars;

    for (USHORT i = totalChars; i > 0; i--) {
        WCHAR c = FilePath->Buffer[i - 1];
        if (c == L'.') {
            extStart = i - 1;
            break;
        }
        if (c == L'\\') break;
    }

    if (extStart == totalChars) return FALSE;

    UNICODE_STRING ext;
    ext.Buffer = &FilePath->Buffer[extStart];
    ext.Length = FilePath->Length
        - (USHORT)(extStart * sizeof(WCHAR));
    ext.MaximumLength = ext.Length;

    for (int i = 0; g_LegitExtensions[i] != NULL; i++) {
        UNICODE_STRING cmp;
        RtlInitUnicodeString(&cmp, g_LegitExtensions[i]);
        if (RtlEqualUnicodeString(&ext, &cmp, TRUE))
            return TRUE;
    }

    return FALSE;
}

BOOLEAN KS_IsLegitExtension(PUNICODE_STRING Extension)
{
    if (!Extension || !Extension->Buffer ||
        Extension->Length == 0)
        return FALSE;

    for (int i = 0; g_LegitExtensions[i] != NULL; i++) {
        UNICODE_STRING legit;
        RtlInitUnicodeString(&legit, g_LegitExtensions[i]);
        if (RtlEqualUnicodeString(Extension, &legit, TRUE))
            return TRUE;
    }
    return FALSE;
}