#include "KratosContext.h"
#include "KratosDetection.h"

PKS_PROCESS_CONTEXT KS_FindOrCreateProcessContext(HANDLE Pid)
{
    KS_PROCESS_CONTEXT lookup = { 0 };
    lookup.ProcessId = Pid;

    ExAcquireFastMutex(&g_ProcessCtxTableLock);

    PKS_PROCESS_CONTEXT ctx = (PKS_PROCESS_CONTEXT)
        RtlLookupElementGenericTableAvl(&g_ProcessCtxTable, &lookup);

    if (ctx == NULL) {
        KS_PROCESS_CONTEXT newCtx = { 0 };
        newCtx.ProcessId = Pid;

        PEPROCESS process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &process))) {
            PUCHAR ansiName = PsGetProcessImageFileName(process);
            if (ansiName) {
                newCtx.IsWhitelisted = KS_IsWhitelisted(ansiName);
                ANSI_STRING ansi;
                RtlInitAnsiString(&ansi, (PCSZ)ansiName);
                RtlAnsiStringToUnicodeString(
                    &newCtx.ImageFileName, &ansi, TRUE);
            }
            ObDereferenceObject(process);
        }

        BOOLEAN newElement = FALSE;
        ctx = (PKS_PROCESS_CONTEXT)RtlInsertElementGenericTableAvl(
            &g_ProcessCtxTable,
            &newCtx,
            sizeof(KS_PROCESS_CONTEXT),
            &newElement);

        if (!ctx && newCtx.ImageFileName.Buffer)
            RtlFreeUnicodeString(&newCtx.ImageFileName);
    }

    ExReleaseFastMutex(&g_ProcessCtxTableLock);
    return ctx;
}

// Cleanup context fichier
VOID KS_FileContext_Cleanup(
    PFLT_CONTEXT        Context,
    FLT_CONTEXT_TYPE    ContextType)
{
    UNREFERENCED_PARAMETER(ContextType);
    PKS_FILE_CONTEXT ctx = (PKS_FILE_CONTEXT)Context;


    DbgPrint("[Kratos] FileContext freed: %ws "
        "Writes=%lu Suspicious=%d\n",
        ctx->FileName,
        ctx->WriteCount,
        ctx->IsSuspicious);
}


// Cleanup context handle
VOID KS_HandleContext_Cleanup(PFLT_CONTEXT Context)
{

    PKS_STREAMHANDLE_CONTEXT ctx = (PKS_STREAMHANDLE_CONTEXT)Context;

    if (ctx) {

        DbgPrint("[Kratos] HandleContext freed: PID=%lu Process=%ws\n",
            ctx->ProcessId,
            ctx->ProcessName);
    }


}

RTL_GENERIC_COMPARE_RESULTS CompareProcessContextEntries(PRTL_AVL_TABLE Table, PVOID First, PVOID Second) {
    UNREFERENCED_PARAMETER(Table);

    PKS_PROCESS_CONTEXT p1 = (PKS_PROCESS_CONTEXT)First;
    PKS_PROCESS_CONTEXT p2 = (PKS_PROCESS_CONTEXT)Second;

    if (p1->ProcessId < p2->ProcessId) return GenericLessThan;
    if (p1->ProcessId > p2->ProcessId) return GenericGreaterThan;

    return GenericEqual;
}

PVOID AllocateAvl(PRTL_AVL_TABLE Table, CLONG ByteSize) {
    UNREFERENCED_PARAMETER(Table);
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, ByteSize, 'avlR');
}

VOID FreeAvl(PRTL_AVL_TABLE Table, PVOID Buffer) {
    UNREFERENCED_PARAMETER(Table);
    ExFreePool(Buffer);
}
