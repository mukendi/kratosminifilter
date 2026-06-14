#pragma once
#include "KratosCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

    KS_HASH64 KS_FNV1a64(PUCHAR data, ULONG size);
    NTSTATUS  KS_KillProcess(HANDLE ProcessId);
    NTSTATUS  KS_ComputeProcessHash(HANDLE ProcessId, KS_HASH64* OutHash);
    VOID      KS_BlacklistProcess(PKS_PROCESS_CONTEXT ctx, KS_HASH64 hash);
    VOID      KS_KillProcessWorkerRoutine(PVOID Context);
    BOOLEAN   KS_IsBlacklisted(HANDLE ProcessId);
    BOOLEAN   KS_IsWhitelisted(PUCHAR processName);

#ifdef __cplusplus
}
#endif