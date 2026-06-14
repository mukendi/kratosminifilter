#pragma once
#include "KratosCommon.h"
#include "KratosBlacklist.h"
#ifdef __cplusplus
extern "C" {
#endif

    PKS_PROCESS_CONTEXT KS_FindOrCreateProcessContext(HANDLE Pid);
    VOID KS_FileContext_Cleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType);
    VOID KS_HandleContext_Cleanup(PFLT_CONTEXT Context);

    // Callbacks AVL
    RTL_GENERIC_COMPARE_RESULTS CompareProcessContextEntries(PRTL_AVL_TABLE Table, PVOID First, PVOID Second);
    PVOID AllocateAvl(PRTL_AVL_TABLE Table, CLONG ByteSize);
    VOID  FreeAvl(PRTL_AVL_TABLE Table, PVOID Buffer);

#ifdef __cplusplus
}
#endif