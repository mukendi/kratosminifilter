#pragma once
#include <ntifs.h>        
#include <ntddk.h>
#include <fltKernel.h>
#include <ntstrsafe.h>
#include "KratosEntropyTable.h"

#define PROCESS_TERMINATE    0x0001
#define FNV_OFFSET_BASIS_64  0xCBF29CE484222325ULL
#define FNV_PRIME_64         0x100000001B3ULL
#define HASH_SAMPLE_SIZE     4096
#define BLACKLIST_KEY        L"\\Registry\\Machine\\SOFTWARE\\Kratos\\Blacklist"


extern "C" PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);


typedef ULONGLONG KS_HASH64;
typedef struct _KS_PROCESS_CONTEXT KS_PROCESS_CONTEXT, * PKS_PROCESS_CONTEXT;
typedef struct _KS_STREAM_CONTEXT  KS_STREAM_CONTEXT, * PKS_STREAM_CONTEXT;
typedef struct _KS_STREAMHANDLE_CONTEXT KS_STREAMHANDLE_CONTEXT, * PKS_STREAMHANDLE_CONTEXT;

// KratosMinifilter Global State
typedef struct _KS_GLOBALS {
    PFLT_FILTER FilterHandler;
    ERESOURCE   GlobalLock;
}KS_GLOBALS, * PKS_GLOBALS;

typedef struct _KS_FILE_CONTEXT {
    ULONG           WriteCount;
    ULONG           ReadCount;

    ULONG          EntropyBefore;
    ULONG          EntropyAfter;

    BOOLEAN         EntropyBeforeCaptured;
    BOOLEAN         IsSuspicious;

    WCHAR           FileName[256];
    KSPIN_LOCK      Lock;
} KS_FILE_CONTEXT, * PKS_FILE_CONTEXT;

typedef struct _KS_STREAMHANDLE_CONTEXT {
    ULONG       ProcessId;
    WCHAR       ProcessName[64];
    ULONG       WriteCount;
}KS_STREAMHANDLE_CONTEXT, * PKS_STREAMHANDLE_CONTEXT;


typedef struct _KS_COMPLETION_CTX {

    PKS_FILE_CONTEXT           File;
    PKS_STREAMHANDLE_CONTEXT   Handle;

} KS_COMPLETION_CTX;

typedef struct _KS_PROCESS_ENTRY {

    LIST_ENTRY     ProcessListEntry;
    HANDLE         ProcessId;
    HANDLE         ParentProcessId;
    UNICODE_STRING ImageFileName;
    LARGE_INTEGER  CreateTime;

}KS_PROCESS_ENTRY, * PKS_PROCESS_ENTRY;


typedef struct _KS_PROCESS_CONTEXT {
    HANDLE          ProcessId;
    HANDLE          ParentProcessId;
    UNICODE_STRING  ImageFileName;
    LARGE_INTEGER   CreateTime;
    ULONG           TotalWriteOperations;
    ULONG           DeleteCount;
    ULONG           RenameCount;
    ULONG           ValuableDeleteCount;
    ULONG           UserDirDeleteCount;
    ULONG           RenameToSuspicious;
    ULONG           TmpWriteCount;
    LARGE_INTEGER   FirstActivityTime;
    ULONG           BurstCreateCount;
    ULONG           HighEntropyWrites;
    ULONG           WriteWithoutRead;
    ULONG           ThreatScore;
    BOOLEAN         RansomNoteCreated;
    BOOLEAN         ShadowCopyDeleted;
    BOOLEAN         IsSuspicious;
    BOOLEAN         IsBlocked;
    BOOLEAN         IsWhitelisted;

}KS_PROCESS_CONTEXT, * PKS_PROCESS_CONTEXT;

typedef struct _KS_KILL_WORKER_CTX {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE          ProcessId;
    PFLT_INSTANCE   Instance;
    LIST_ENTRY      FilesToRestore;
    ULONG           FileCount;
}KS_KILL_WORKER_CTX, * PKS_KILL_WORKER_CTX;

typedef struct _KS_BACKED_UP_FILE {
    LIST_ENTRY  ListEntry;
    WCHAR       FilePath[256];
} KS_BACKED_UP_FILE, * PKS_BACKED_UP_FILE;

typedef struct _KS_RESTORE_WORKER_CTX {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE          ProcessId;
    PFLT_INSTANCE   Instance;
    LIST_ENTRY      FilesToRestore;
    ULONG           FileCount;
} KS_RESTORE_WORKER_CTX, * PKS_RESTORE_WORKER_CTX;

typedef struct _KS_TRUSTED_PROCESS {
    const CHAR* Name;
    const WCHAR* ExpectedPath;
} KS_TRUSTED_PROCESS;

extern KS_GLOBALS g_Globals;

extern RTL_AVL_TABLE g_ProcessCtxTable;
extern LIST_ENTRY    g_ProcessList;
extern KSPIN_LOCK    g_ProcessListLock;
extern FAST_MUTEX    g_ProcessCtxTableLock;

extern BOOLEAN       g_CallbackRegistred;

static const WCHAR* g_SuspiciousExtensions[] = {
    L".locked", L".enc", L".encrypted",
    L".crypto", L".crypt", L".lockbit",
    L".alphv",  L".wncry", L".wnncry",
    NULL
};

static const WCHAR* g_RansomNoteNames[] = {
    L"README",   L"DECRYPT",  L"RECOVER",
    L"HOW_TO",   L"RESTORE",  L"@RESTORE",
    L"@DECRYPT", L"HELP_",    L"!!!",
    NULL
};


static const KS_TRUSTED_PROCESS g_TrustedProcesses[] = {
    // Browsers
    { "chrome.exe",
      L"\\Program Files\\Google\\Chrome\\Application\\" },
    { "msedge.exe",
      L"\\Program Files (x86)\\Microsoft\\Edge\\Application\\" },
    { "msedgewebview2",
      L"\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" },
    { "firefox.exe",
      L"\\Program Files\\Mozilla Firefox\\" },

      // Windows System
      { "svchost.exe",
        L"\\Windows\\System32\\" },
      { "SearchIndexer.exe",
        L"\\Windows\\System32\\" },
      { "MsMpEng.exe",
        L"\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" },
      { "wermgr.exe",
        L"\\Windows\\System32\\" },
      { "WerFault.exe",
        L"\\Windows\\System32\\" },
      { "RuntimeBroker.exe",
        L"\\Windows\\System32\\" },
      { "dllhost.exe",
        L"\\Windows\\System32\\" },
      { "taskhostw.exe",
        L"\\Windows\\System32\\" },
      { "TiWorker.exe",
        L"\\Windows\\" },

      { NULL, NULL }
};

// Files that only ransomware targets
static const WCHAR* g_LegitExtensions[] = {
    L".docx", L".doc",  L".pdf",  L".txt",
    L".xlsx", L".xls",  L".pptx", L".ppt",
    L".odt",  L".ods",  L".odp",  L".rtf",
    L".csv",  L".xml",  L".json", L".html",
    L".jpg",  L".jpeg", L".png",  L".bmp",
    L".gif",  L".tiff", L".webp", L".svg",
    L".mp4",  L".mp3",  L".avi",  L".mkv",
    L".wav",  L".flac", L".mov",
    L".zip",  L".rar",  L".7z",   L".tar",
    L".gz",
    L".py",   L".js",   L".cpp",  L".h",
    L".cs",   L".java", L".sql",
    L".bak",  L".tmp",  L".log",  L".dat",
    L".exe",  L".dll",  L".sys",  L".mui",
    L".inf",  L".cat",
    NULL
};

// System directories , deletions ignored
static const WCHAR* g_IgnoredPaths[] = {
    L"\\AppData\\Local\\Temp\\",
    L"\\AppData\\Local\\Microsoft\\",
    L"\\AppData\\Roaming\\Microsoft\\",
    L"\\AppData\\Local\\Google\\",
    L"\\AppData\\Local\\Mozilla\\",
    L"\\Windows\\Temp\\",
    L"\\Windows\\CbsTemp\\",
    NULL
};
