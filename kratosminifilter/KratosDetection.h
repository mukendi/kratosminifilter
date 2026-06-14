#pragma once
#include "KratosCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

    VOID    KS_EvaluateThreatScore(PKS_PROCESS_CONTEXT ctx,PFLT_INSTANCE Instance);
    ULONG   KS_CalculateEntropyFast(PUCHAR Buffer, ULONG Size);
    BOOLEAN KS_HasSuspiciousExtension(PUNICODE_STRING FileName);
    BOOLEAN KS_IsRansomNote(PUNICODE_STRING FileName);
    BOOLEAN KS_IsValuableFile(PUNICODE_STRING FilePath);
    BOOLEAN KS_IsLegitExtension(PUNICODE_STRING Extension);
    //BOOLEAN KS_IsWhitelisted(PUCHAR processName);
    BOOLEAN KS_IsWhitelistedFull(PUCHAR processName, PCUNICODE_STRING fullImagePath);
    BOOLEAN KS_PathContainsCI(PCUNICODE_STRING FullPath, PCWSTR SubPath);

#ifdef __cplusplus
}
#endif