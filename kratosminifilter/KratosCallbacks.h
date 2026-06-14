#pragma once
#include "KratosCommon.h"

#ifdef __cplusplus
extern "C" {
#endif

    FLT_PREOP_CALLBACK_STATUS KS_PreCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

    FLT_POSTOP_CALLBACK_STATUS KS_PostCreateCallback(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags);

    FLT_POSTOP_CALLBACK_STATUS KS_PostCreateCallbackSafe(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags);

    FLT_PREOP_CALLBACK_STATUS  KS_PreWriteCallback(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext);

    FLT_POSTOP_CALLBACK_STATUS KS_PostWriteCallback(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID CompletionContext,
        FLT_POST_OPERATION_FLAGS Flags
    );

    FLT_PREOP_CALLBACK_STATUS  KS_PreReadCallback(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext);

    FLT_PREOP_CALLBACK_STATUS  KS_PreSetInformationCallback(
        PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS FltObjects,
        PVOID* CompletionContext);

#ifdef __cplusplus
}
#endif