#include <fltKernel.h>
#include <dontuse.h>

#define BLACKSHARD_PROTOCOL_MAGIC 0x35485342UL
#define BLACKSHARD_PROTOCOL_VERSION 7
#define BLACKSHARD_PORT_NAME L"\\BlackshardPort"
#define BLACKSHARD_STREAM_CONTEXT_TAG 'cShB'
#define MAX_FILE_PATH_LENGTH 1024

#define BLACKSHARD_OPERATION_OPEN 1UL
#define BLACKSHARD_OPERATION_EXECUTE_SECTION 2UL
#define BLACKSHARD_OPERATION_PROTECTED_WRITE 3UL
#define BLACKSHARD_OPERATION_PROTECTED_METADATA 4UL
#define BLACKSHARD_CONTROL_GET_HEALTH 1UL
#define BLACKSHARD_CONTROL_SET_READY_GENERATION 2UL
#define BLACKSHARD_CONTROL_SET_STOPPING 3UL
#define BLACKSHARD_ENTROPY_NOT_MEASURED 0UL
#define BLACKSHARD_ENTROPY_LOW 1UL
#define BLACKSHARD_ENTROPY_NORMAL 2UL
#define BLACKSHARD_ENTROPY_HIGH 3UL

//
// How long each operation waits for the service. An execution waits as long as a scan of a large
// program can take: the image section cannot be created without the verdict, and this FsFilter
// operation cannot be pended to a worker (only IRP-based operations can), so the thread creating
// the section waits here. A protected write waits for the service to copy the original document
// (at most 16 MB) to the rollback vault before the write may change it. An open only audits.
//
#define BLACKSHARD_FEATURE_HANDLE_PROTECTION 0x1UL
#define BLACKSHARD_FEATURE_REGISTRY_PROTECTION 0x2UL
#define BLACKSHARD_CALLBACK_ALTITUDE L"320000.4242"

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif

//
// Rights other processes, administrators included, never get on the service: enough to kill,
// freeze or inject into it. Its threads are covered too, or killing each thread would do.
//
#define BLACKSHARD_DENIED_PROCESS_ACCESS \
    (PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
     PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD)
#define BLACKSHARD_DENIED_THREAD_ACCESS \
    (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT)

#define BLACKSHARD_EXECUTE_TIMEOUT_MS 30000LL
#define BLACKSHARD_PROTECTED_TIMEOUT_MS 5000LL
#define BLACKSHARD_OPEN_TIMEOUT_MS 1500LL

typedef enum _BLACKSHARD_OPERATIONAL_PHASE {
    BlackshardPhaseEarlyBoot = 0,
    BlackshardPhaseStarting = 1,
    BlackshardPhaseReady = 2,
    BlackshardPhaseRecovering = 3,
    BlackshardPhaseStopping = 4,
    BlackshardPhaseSafeMode = 5
} BLACKSHARD_OPERATIONAL_PHASE;

typedef enum _BLACKSHARD_FAILURE_REASON {
    BlackshardFailureServiceUnavailable,
    BlackshardFailureTimeout,
    BlackshardFailureInvalidReply,
    BlackshardFailureObjectResolution,
    BlackshardFailurePathResolution,
    BlackshardFailurePathTooLong,
    BlackshardFailureUnsupportedIrql,
    BlackshardFailureInternalError,
    BlackshardFailureQueueOverload,
    BlackshardFailureProtocolMismatch,
    BlackshardFailureContentRace
} BLACKSHARD_FAILURE_REASON;

typedef enum _BLACKSHARD_FAILURE_DECISION {
    BlackshardFailureAllowTrustedCached,
    BlackshardFailureAllowBootPolicy,
    BlackshardFailureBlock,
    BlackshardFailureAuditAllow
} BLACKSHARD_FAILURE_DECISION;






typedef struct _BLACKSHARD_NOTIFICATION {
    ULONG Magic;
    USHORT Version;
    USHORT Size;
    ULONG ProcessId;
    ULONG DesiredAccess;
    ULONG Operation;
    ULONG PathLength;
    WCHAR FilePath[MAX_FILE_PATH_LENGTH];
    ULONGLONG FileId;
    ULONGLONG ContentGeneration;
    ULONGLONG ProcessStartKey;
    ULONG MustEnforce;
    ULONG Reserved;
} BLACKSHARD_NOTIFICATION, *PBLACKSHARD_NOTIFICATION;

typedef enum _BLACKSHARD_VERDICT {
    VERDICT_ALLOW = 0,
    VERDICT_BLOCK = 1
} BLACKSHARD_VERDICT;

typedef struct _BLACKSHARD_REPLY {
    ULONG Magic;
    USHORT Version;
    USHORT Size;
    BLACKSHARD_VERDICT Verdict;
    ULONG RiskScore;
} BLACKSHARD_REPLY, *PBLACKSHARD_REPLY;

typedef struct _BLACKSHARD_CONTROL_REQUEST {
    ULONG Magic;
    USHORT Version;
    USHORT Size;
    ULONG Command;
    ULONGLONG Generation;
} BLACKSHARD_CONTROL_REQUEST, *PBLACKSHARD_CONTROL_REQUEST;

typedef struct _BLACKSHARD_HEALTH_REPLY {
    ULONG Magic;
    USHORT Version;
    USHORT Size;
    ULONGLONG ScanRequests;
    ULONGLONG Blocks;
    ULONGLONG Timeouts;
    ULONGLONG ServiceUnavailableBypasses;
    ULONGLONG ObjectResolutionBypasses;
    ULONGLONG OversizePathBypasses;
    ULONGLONG IrqlBypasses;
    ULONGLONG InvalidReplies;
    ULONGLONG DirtyWrites;
    ULONGLONG EnforcementBypasses;
    ULONGLONG ContentRaceBlocks;
    ULONGLONG PathResolutionFailures;
    ULONGLONG ProtocolMismatches;
    ULONGLONG CacheAllows;
    ULONGLONG BootPolicyAllows;
    ULONGLONG RequiredEnforcementBlocks;
    ULONGLONG QueueOverloads;
    ULONGLONG ReadyGeneration;
    ULONG OperationalPhase;
    ULONG Features;
} BLACKSHARD_HEALTH_REPLY, *PBLACKSHARD_HEALTH_REPLY;

typedef struct _BLACKSHARD_STREAM_CONTEXT {
    volatile LONG64 FileId;
    volatile LONG IdentityValid;
    volatile LONG Reserved;
    volatile LONG64 ContentGeneration;
    volatile LONG LastWriteProcessId;
    volatile LONG WriteReserved;
    volatile LONG64 LastWriteNotificationTick;
} BLACKSHARD_STREAM_CONTEXT, *PBLACKSHARD_STREAM_CONTEXT;

typedef struct _BLACKSHARD_DATA {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    HANDLE ClientProcessId;
    PEPROCESS volatile ClientProcess;
    PVOID ObjectCallbacks;
    LARGE_INTEGER RegistryCookie;
    ULONG Features;
    volatile LONG64 ScanRequests;
    volatile LONG64 Blocks;
    volatile LONG64 Timeouts;
    volatile LONG64 ServiceUnavailableBypasses;
    volatile LONG64 ObjectResolutionBypasses;
    volatile LONG64 OversizePathBypasses;
    volatile LONG64 IrqlBypasses;
    volatile LONG64 InvalidReplies;
    volatile LONG64 DirtyWrites;
    volatile LONG64 EnforcementBypasses;
    volatile LONG64 ContentRaceBlocks;
    volatile LONG64 PathResolutionFailures;
    volatile LONG64 ProtocolMismatches;
    volatile LONG64 CacheAllows;
    volatile LONG64 BootPolicyAllows;
    volatile LONG64 RequiredEnforcementBlocks;
    volatile LONG64 QueueOverloads;
    volatile LONG64 ReadyGeneration;
    volatile LONG OperationalPhase;
    volatile LONG EverReady;
    PFLT_VOLUME SystemVolume;
} BLACKSHARD_DATA, *PBLACKSHARD_DATA;

C_ASSERT(FIELD_OFFSET(BLACKSHARD_NOTIFICATION, FilePath) == 24);
C_ASSERT(FIELD_OFFSET(BLACKSHARD_NOTIFICATION, FileId) == 2072);
C_ASSERT(FIELD_OFFSET(BLACKSHARD_NOTIFICATION, ContentGeneration) == 2080);
C_ASSERT(FIELD_OFFSET(BLACKSHARD_NOTIFICATION, ProcessStartKey) == 2088);
C_ASSERT(FIELD_OFFSET(BLACKSHARD_NOTIFICATION, MustEnforce) == 2096);
C_ASSERT(sizeof(BLACKSHARD_NOTIFICATION) == 2104);
C_ASSERT(sizeof(BLACKSHARD_REPLY) == 16);
C_ASSERT(sizeof(BLACKSHARD_CONTROL_REQUEST) == 24);
C_ASSERT(sizeof(BLACKSHARD_HEALTH_REPLY) == 160);

BLACKSHARD_DATA gBlackshardData;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
BlackshardUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
BlackshardPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
BlackshardPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
BlackshardPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
BlackshardPreSetInformation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
BlackshardPreAcquireForSectionSynchronization (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
BlackshardPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
BlackshardPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
BlackshardPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    );

BOOLEAN
BlackshardShouldScanName (
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ACCESS_MASK DesiredAccess
    );

BOOLEAN
BlackshardIsProtectedDocumentName (
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo
    );

BOOLEAN
BlackshardNameContainsInsensitive (
    _In_ PCUNICODE_STRING Name,
    _In_ PCUNICODE_STRING Fragment
    );

BOOLEAN
BlackshardEvaluateOpenedObject (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Operation,
    _In_ ULONG MustEnforce,
    _In_ ULONG DesiredAccess,
    _In_ BOOLEAN RestrictToHighRiskName
    );

ULONG
BlackshardClassifyWriteEntropy (
    _Inout_ PFLT_CALLBACK_DATA Data
    );

BLACKSHARD_FAILURE_DECISION
BlackshardApplyFailurePolicy (
    _In_ BLACKSHARD_FAILURE_REASON Reason,
    _In_ ULONG MustEnforce,
    _In_ BOOLEAN AdministratorOnlyImage
    );

BOOLEAN
BlackshardFailureRequiresBlock (
    _In_ BLACKSHARD_FAILURE_REASON Reason,
    _In_ ULONG MustEnforce,
    _In_ BOOLEAN AdministratorOnlyImage
    );

BOOLEAN
BlackshardFailsClosed (
    VOID
    );

BOOLEAN
BlackshardIsAdministratorOnlyImage (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo
    );

VOID
BlackshardRememberSystemVolume (
    VOID
    );

VOID
BlackshardRegisterSelfProtection (
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
BlackshardUnregisterSelfProtection (
    VOID
    );

BOOLEAN
BlackshardSelfProtectionActive (
    VOID
    );

OB_PREOP_CALLBACK_STATUS
BlackshardPreObjectHandle (
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

EX_CALLBACK_FUNCTION BlackshardRegistryCallback;

BOOLEAN
BlackshardIsProtectedRegistryKey (
    _In_ PCUNICODE_STRING KeyName
    );

NTSTATUS
BlackshardGetOrCreateStreamContext (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN IdentityValid,
    _In_ ULONGLONG FileId,
    _Outptr_ PBLACKSHARD_STREAM_CONTEXT *ReturnedContext
    );

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, BlackshardUnload)
#pragma alloc_text(PAGE, BlackshardPortConnect)
#pragma alloc_text(PAGE, BlackshardPortDisconnect)
#pragma alloc_text(PAGE, BlackshardPortMessage)
#pragma alloc_text(PAGE, BlackshardShouldScanName)
#pragma alloc_text(PAGE, BlackshardIsProtectedDocumentName)
#pragma alloc_text(PAGE, BlackshardNameContainsInsensitive)
#pragma alloc_text(PAGE, BlackshardEvaluateOpenedObject)
#pragma alloc_text(PAGE, BlackshardIsAdministratorOnlyImage)
#pragma alloc_text(INIT, BlackshardRememberSystemVolume)
#pragma alloc_text(INIT, BlackshardRegisterSelfProtection)
#pragma alloc_text(PAGE, BlackshardUnregisterSelfProtection)
#pragma alloc_text(PAGE, BlackshardRegistryCallback)
#pragma alloc_text(PAGE, BlackshardIsProtectedRegistryKey)

CONST FLT_CONTEXT_REGISTRATION Contexts[] = {
    {
        FLT_STREAM_CONTEXT,
        0,
        NULL,
        sizeof(BLACKSHARD_STREAM_CONTEXT),
        BLACKSHARD_STREAM_CONTEXT_TAG,
        NULL,
        NULL,
        NULL
    },
    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        BlackshardPreCreate,
        BlackshardPostCreate
    },
    {
        IRP_MJ_WRITE,
        0,
        BlackshardPreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        BlackshardPreSetInformation,
        NULL
    },
    {
        IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        0,
        BlackshardPreAcquireForSectionSynchronization,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

//
// Not stoppable through the service control manager, and the unload callback refuses every
// unload it may refuse, so `sc stop` and `fltmc unload` both fail. A new driver loads at restart.
//
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP,
    Contexts,
    Callbacks,
    BlackshardUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&gBlackshardData, sizeof(gBlackshardData));
    gBlackshardData.OperationalPhase = BlackshardPhaseEarlyBoot;

    status = FltRegisterFilter(
        DriverObject,
        &FilterRegistration,
        &gBlackshardData.FilterHandle
        );

    FLT_ASSERT(NT_SUCCESS(status));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(
        &securityDescriptor,
        FLT_PORT_ALL_ACCESS
        );
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gBlackshardData.FilterHandle);
        gBlackshardData.FilterHandle = NULL;
        return status;
    }

    RtlInitUnicodeString(&portName, BLACKSHARD_PORT_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
        );

    status = FltCreateCommunicationPort(
        gBlackshardData.FilterHandle,
        &gBlackshardData.ServerPort,
        &objectAttributes,
        NULL,
        BlackshardPortConnect,
        BlackshardPortDisconnect,
        BlackshardPortMessage,
        1
        );

    FltFreeSecurityDescriptor(securityDescriptor);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gBlackshardData.FilterHandle);
        gBlackshardData.FilterHandle = NULL;
        return status;
    }

    BlackshardRegisterSelfProtection(DriverObject);

    status = FltStartFiltering(gBlackshardData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        BlackshardUnregisterSelfProtection();
        FltCloseCommunicationPort(gBlackshardData.ServerPort);
        gBlackshardData.ServerPort = NULL;
        FltUnregisterFilter(gBlackshardData.FilterHandle);
        gBlackshardData.FilterHandle = NULL;
        return status;
    }

    BlackshardRememberSystemVolume();
    return status;
}

VOID
BlackshardRememberSystemVolume (
    VOID
    )
{
    UNICODE_STRING systemRoot = RTL_CONSTANT_STRING(L"\\SystemRoot");
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatus;
    HANDLE handle;
    PFILE_OBJECT fileObject;
    NTSTATUS status;

    InitializeObjectAttributes(
        &attributes,
        &systemRoot,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
        );
    status = ZwCreateFile(
        &handle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes,
        &ioStatus,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
        );
    if (!NT_SUCCESS(status)) {
        return;
    }
    status = ObReferenceObjectByHandle(
        handle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID *)&fileObject,
        NULL
        );
    if (NT_SUCCESS(status)) {
        status = FltGetVolumeFromFileObject(
            gBlackshardData.FilterHandle,
            fileObject,
            &gBlackshardData.SystemVolume
            );
        if (!NT_SUCCESS(status)) {
            gBlackshardData.SystemVolume = NULL;
        }
        ObDereferenceObject(fileObject);
    }
    ZwClose(handle);
}

BOOLEAN
BlackshardFailsClosed (
    VOID
    )
{
    //
    // Once protection has been established this boot, an execution the service cannot judge is
    // refused: a hung, crashed or killed service must not open the door. Before that (early boot,
    // or a service that never got ready) nothing was promised, and an orderly stop through the
    // service control manager announces itself as Stopping and keeps the old allow behaviour.
    //
    return (BOOLEAN)(
        InterlockedCompareExchange(&gBlackshardData.EverReady, 0, 0) != 0 &&
        InterlockedCompareExchange(&gBlackshardData.OperationalPhase, 0, 0) !=
            BlackshardPhaseStopping
        );
}

BLACKSHARD_FAILURE_DECISION
BlackshardApplyFailurePolicy (
    _In_ BLACKSHARD_FAILURE_REASON Reason,
    _In_ ULONG MustEnforce,
    _In_ BOOLEAN AdministratorOnlyImage
    )
{
    BLACKSHARD_OPERATIONAL_PHASE phase;

    switch (Reason) {
    case BlackshardFailureServiceUnavailable:
        InterlockedIncrement64(&gBlackshardData.ServiceUnavailableBypasses);
        break;
    case BlackshardFailureTimeout:
        InterlockedIncrement64(&gBlackshardData.Timeouts);
        break;
    case BlackshardFailureInvalidReply:
        InterlockedIncrement64(&gBlackshardData.InvalidReplies);
        break;
    case BlackshardFailureObjectResolution:
    case BlackshardFailureInternalError:
        InterlockedIncrement64(&gBlackshardData.ObjectResolutionBypasses);
        break;
    case BlackshardFailurePathResolution:
        InterlockedIncrement64(&gBlackshardData.PathResolutionFailures);
        break;
    case BlackshardFailurePathTooLong:
        InterlockedIncrement64(&gBlackshardData.OversizePathBypasses);
        break;
    case BlackshardFailureUnsupportedIrql:
        InterlockedIncrement64(&gBlackshardData.IrqlBypasses);
        break;
    case BlackshardFailureQueueOverload:
        InterlockedIncrement64(&gBlackshardData.QueueOverloads);
        break;
    case BlackshardFailureProtocolMismatch:
        InterlockedIncrement64(&gBlackshardData.ProtocolMismatches);
        break;
    case BlackshardFailureContentRace:
        InterlockedIncrement64(&gBlackshardData.ContentRaceBlocks);
        break;
    default:
        InterlockedIncrement64(&gBlackshardData.ObjectResolutionBypasses);
        break;
    }

    if (MustEnforce == 0) {
        return BlackshardFailureAuditAllow;
    }

    phase = (BLACKSHARD_OPERATIONAL_PHASE)InterlockedCompareExchange(
        &gBlackshardData.OperationalPhase,
        0,
        0
        );
    //
    // A path of MAX_FILE_PATH_LENGTH characters or more cannot be sent to the service, so
    // nothing could ever scan it; allowing it would let any program hide at a long enough
    // path. A legitimate image at such a path is essentially nonexistent (the loader and
    // most tools cannot open one), so an image load there is blocked once the filter is ready.
    //
    if (phase == BlackshardPhaseReady &&
        (Reason == BlackshardFailureContentRace ||
         Reason == BlackshardFailurePathTooLong)) {
        InterlockedIncrement64(&gBlackshardData.RequiredEnforcementBlocks);
        return BlackshardFailureBlock;
    }

    //
    // Windows' own folders and Program Files stay runnable without a verdict, so the service can
    // restart and the desktop keeps working while it does; standard users cannot write there.
    //
    if (!AdministratorOnlyImage &&
        BlackshardFailsClosed() &&
        (Reason == BlackshardFailureServiceUnavailable ||
         Reason == BlackshardFailureTimeout ||
         Reason == BlackshardFailureInvalidReply ||
         Reason == BlackshardFailureProtocolMismatch)) {
        InterlockedIncrement64(&gBlackshardData.RequiredEnforcementBlocks);
        return BlackshardFailureBlock;
    }

    InterlockedIncrement64(&gBlackshardData.EnforcementBypasses);
    if (phase == BlackshardPhaseReady) {
        return BlackshardFailureAuditAllow;
    }
    InterlockedIncrement64(&gBlackshardData.BootPolicyAllows);
    return BlackshardFailureAllowBootPolicy;
}

BOOLEAN
BlackshardFailureRequiresBlock (
    _In_ BLACKSHARD_FAILURE_REASON Reason,
    _In_ ULONG MustEnforce,
    _In_ BOOLEAN AdministratorOnlyImage
    )
{
    return (BOOLEAN)(
        BlackshardApplyFailurePolicy(Reason, MustEnforce, AdministratorOnlyImage) ==
        BlackshardFailureBlock
        );
}

NTSTATUS
BlackshardUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    PAGED_CODE();

    if (!FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY)) {
        return STATUS_FLT_DO_NOT_DETACH;
    }

    BlackshardUnregisterSelfProtection();

    if (gBlackshardData.ServerPort != NULL) {
        FltCloseCommunicationPort(gBlackshardData.ServerPort);
        gBlackshardData.ServerPort = NULL;
    }

    if (gBlackshardData.SystemVolume != NULL) {
        FltObjectDereference(gBlackshardData.SystemVolume);
        gBlackshardData.SystemVolume = NULL;
    }

    if (gBlackshardData.FilterHandle != NULL) {
        FltUnregisterFilter(gBlackshardData.FilterHandle);
        gBlackshardData.FilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
BlackshardPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    ULONG requestorProcessId;
    UCHAR createDisposition;
    ACCESS_MASK desiredAccess;

    UNREFERENCED_PARAMETER(FltObjects);

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    if (Data->RequestorMode != UserMode ||
        Data->Iopb->Parameters.Create.SecurityContext == NULL ||
        FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE) ||
        FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestorProcessId = FltGetRequestorProcessId(Data);
    if (requestorProcessId == 0 ||
        (gBlackshardData.ClientProcessId != NULL &&
         requestorProcessId == HandleToULong(gBlackshardData.ClientProcessId))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    createDisposition = (UCHAR)(Data->Iopb->Parameters.Create.Options >> 24);
    if (createDisposition == FILE_CREATE ||
        createDisposition == FILE_SUPERSEDE ||
        createDisposition == FILE_OVERWRITE ||
        createDisposition == FILE_OVERWRITE_IF) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if ((desiredAccess &
         (FILE_READ_DATA | FILE_EXECUTE | GENERIC_READ | GENERIC_EXECUTE)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (gBlackshardData.ClientPort == NULL) {
        (VOID)BlackshardApplyFailurePolicy(
            BlackshardFailureServiceUnavailable,
            FALSE,
            FALSE
            );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }


    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
BlackshardPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    ACCESS_MASK desiredAccess;
    BOOLEAN block;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
        !NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Status == STATUS_REPARSE ||
        Data->IoStatus.Information != FILE_OPENED ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_STREAM_FILE | FO_VOLUME_OPEN)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (Data->Iopb->Parameters.Create.SecurityContext == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        KeAreAllApcsDisabled() ||
        IoGetTopLevelIrp() != NULL) {
        (VOID)BlackshardApplyFailurePolicy(
            BlackshardFailureUnsupportedIrql,
            FALSE,
            FALSE
            );
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    block = BlackshardEvaluateOpenedObject(
        Data,
        FltObjects,
        BLACKSHARD_OPERATION_OPEN,
        FALSE,
        desiredAccess,
        TRUE
        );

    if (!block) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    if (FlagOn(FltObjects->FileObject->Flags, FO_HANDLE_CREATED)) {
        InterlockedIncrement64(&gBlackshardData.EnforcementBypasses);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    InterlockedIncrement64(&gBlackshardData.Blocks);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
BlackshardPreWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;
    PBLACKSHARD_STREAM_CONTEXT streamContext;
    ULONG requestorProcessId;
    ULONGLONG now;
    ULONGLONG previousTick;
    LONG previousProcessId;
    BOOLEAN sendTelemetry;
    BOOLEAN block;
    ULONG writeEntropy;

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    if (Data->RequestorMode != UserMode ||
        KeGetCurrentIrql() > APC_LEVEL ||
        Data->Iopb->Parameters.Write.Length == 0 ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_STREAM_FILE | FO_VOLUME_OPEN)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    sendTelemetry = FALSE;
    requestorProcessId = FltGetRequestorProcessId(Data);
    status = BlackshardGetOrCreateStreamContext(
        FltObjects,
        FALSE,
        0,
        &streamContext
        );
    if (NT_SUCCESS(status)) {
        now = KeQueryInterruptTime();
        previousProcessId = InterlockedCompareExchange(
            &streamContext->LastWriteProcessId,
            0,
            0
            );
        previousTick = (ULONGLONG)InterlockedCompareExchange64(
            &streamContext->LastWriteNotificationTick,
            0,
            0
            );
        if (requestorProcessId != 0 &&
            (previousProcessId != (LONG)requestorProcessId ||
             now - previousTick >= 10ULL * 1000ULL * 1000ULL)) {
            InterlockedExchange(
                &streamContext->LastWriteProcessId,
                (LONG)requestorProcessId
                );
            InterlockedExchange64(
                &streamContext->LastWriteNotificationTick,
                (LONG64)now
                );
            sendTelemetry = TRUE;
        }
        FltReleaseContext(streamContext);
    }

    if (sendTelemetry &&
        gBlackshardData.ClientPort != NULL &&
        KeGetCurrentIrql() == PASSIVE_LEVEL &&
        !KeAreAllApcsDisabled() &&
        IoGetTopLevelIrp() == NULL) {
        writeEntropy = BlackshardClassifyWriteEntropy(Data);
        block = BlackshardEvaluateOpenedObject(
            Data,
            FltObjects,
            BLACKSHARD_OPERATION_PROTECTED_WRITE,
            FALSE,
            writeEntropy,
            TRUE
            );
        if (block) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            InterlockedIncrement64(&gBlackshardData.Blocks);
            return FLT_PREOP_COMPLETE;
        }
    }

    status = BlackshardGetOrCreateStreamContext(
        FltObjects,
        FALSE,
        0,
        &streamContext
        );
    if (NT_SUCCESS(status)) {
        InterlockedIncrement64(&streamContext->ContentGeneration);
        InterlockedIncrement64(&gBlackshardData.DirtyWrites);
        FltReleaseContext(streamContext);
    }


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

ULONG
BlackshardClassifyWriteEntropy (
    _Inout_ PFLT_CALLBACK_DATA Data
    )
{
    NTSTATUS status;
    PMDL mdl;
    PUCHAR bytes;
    ULONG sampleLength;
    ULONG index;
    ULONG uniqueCount;
    ULONGLONG seen[4];

    if (Data == NULL || Data->Iopb->Parameters.Write.Length < 64) {
        return BLACKSHARD_ENTROPY_NOT_MEASURED;
    }

    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status)) {
        return BLACKSHARD_ENTROPY_NOT_MEASURED;
    }
    mdl = Data->Iopb->Parameters.Write.MdlAddress;
    if (mdl == NULL) {
        return BLACKSHARD_ENTROPY_NOT_MEASURED;
    }
    bytes = (PUCHAR)MmGetSystemAddressForMdlSafe(
        mdl,
        NormalPagePriority | MdlMappingNoExecute
        );
    if (bytes == NULL) {
        return BLACKSHARD_ENTROPY_NOT_MEASURED;
    }

    sampleLength = min(Data->Iopb->Parameters.Write.Length, 1024UL);
    RtlZeroMemory(seen, sizeof(seen));
    uniqueCount = 0;
    for (index = 0; index < sampleLength; index++) {
        ULONG bucket = bytes[index] >> 6;
        ULONGLONG mask = 1ULL << (bytes[index] & 63);
        if ((seen[bucket] & mask) == 0) {
            seen[bucket] |= mask;
            uniqueCount++;
        }
    }

    if (uniqueCount <= 64) {
        return BLACKSHARD_ENTROPY_LOW;
    }
    if (sampleLength >= 256 && uniqueCount >= 160) {
        return BLACKSHARD_ENTROPY_HIGH;
    }
    return BLACKSHARD_ENTROPY_NORMAL;
}

FLT_PREOP_CALLBACK_STATUS
BlackshardPreSetInformation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    FILE_INFORMATION_CLASS informationClass;
    BOOLEAN relevant;
    BOOLEAN block;

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    if (Data->RequestorMode != UserMode ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_STREAM_FILE | FO_VOLUME_OPEN)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    informationClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    relevant = (BOOLEAN)(
        informationClass == FileDispositionInformation ||
        informationClass == FileDispositionInformationEx ||
        informationClass == FileRenameInformation ||
        informationClass == FileRenameInformationEx
        );
    if (!relevant) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        KeAreAllApcsDisabled() ||
        IoGetTopLevelIrp() != NULL) {
        (VOID)BlackshardApplyFailurePolicy(
            BlackshardFailureUnsupportedIrql,
            FALSE,
            FALSE
            );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    block = BlackshardEvaluateOpenedObject(
        Data,
        FltObjects,
        BLACKSHARD_OPERATION_PROTECTED_METADATA,
        FALSE,
        0,
        TRUE
        );
    if (block) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64(&gBlackshardData.Blocks);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
BlackshardPreAcquireForSectionSynchronization (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    ULONG pageProtection;
    BOOLEAN block;

    if (CompletionContext != NULL) {
        *CompletionContext = NULL;
    }

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType !=
            SyncTypeCreateSection ||
        FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        FlagOn(FltObjects->FileObject->Flags, FO_STREAM_FILE | FO_VOLUME_OPEN)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    pageProtection =
        Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if ((pageProtection &
         (PAGE_EXECUTE |
          PAGE_EXECUTE_READ |
          PAGE_EXECUTE_READWRITE |
          PAGE_EXECUTE_WRITECOPY)) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Without the service an image is allowed unless protection was already established. When it
    // was, the image's location decides, so the name is resolved below before refusing it.
    //
    if (gBlackshardData.ClientPort == NULL && !BlackshardFailsClosed()) {
        (VOID)BlackshardApplyFailurePolicy(
            BlackshardFailureServiceUnavailable,
            TRUE,
            FALSE
            );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }


    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        KeAreAllApcsDisabled() ||
        IoGetTopLevelIrp() != NULL) {
        if (BlackshardFailureRequiresBlock(
                BlackshardFailureUnsupportedIrql,
                TRUE,
                FALSE
                )) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            InterlockedIncrement64(&gBlackshardData.Blocks);
            return FLT_PREOP_COMPLETE;
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    block = BlackshardEvaluateOpenedObject(
        Data,
        FltObjects,
        BLACKSHARD_OPERATION_EXECUTE_SECTION,
        TRUE,
        pageProtection,
        FALSE
        );

    if (block) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        InterlockedIncrement64(&gBlackshardData.Blocks);
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN
BlackshardEvaluateOpenedObject (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG Operation,
    _In_ ULONG MustEnforce,
    _In_ ULONG DesiredAccess,
    _In_ BOOLEAN RestrictToHighRiskName
    )
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION standardInformation;
    FILE_INTERNAL_INFORMATION internalInformation;
    PFLT_FILE_NAME_INFORMATION nameInformation;
    PBLACKSHARD_STREAM_CONTEXT streamContext;
    BLACKSHARD_NOTIFICATION notification;
    BLACKSHARD_REPLY reply;
    ULONG replyLength;
    ULONG requestorProcessId;
    PEPROCESS requestorProcess;
    ULONGLONG processStartKey;
    ULONG pathLength;
    ULONGLONG contentGeneration;
    LARGE_INTEGER timeout;
    BOOLEAN administratorOnlyImage;

    PAGED_CODE();

    if (FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            FALSE
            );
    }

    requestorProcessId = FltGetRequestorProcessId(Data);
    if (gBlackshardData.ClientProcessId != NULL &&
        requestorProcessId == HandleToULong(gBlackshardData.ClientProcessId)) {
        return FALSE;
    }
    if (requestorProcessId == 0) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            FALSE
            );
    }
    requestorProcess = FltGetRequestorProcess(Data);
    if (requestorProcess == NULL) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            FALSE
            );
    }
    processStartKey = PsGetProcessStartKey(requestorProcess);
    if (processStartKey == 0) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            FALSE
            );
    }

    nameInformation = NULL;
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInformation
        );
    if (!NT_SUCCESS(status)) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailurePathResolution,
            MustEnforce,
            FALSE
            );
    }

    status = FltParseFileNameInformation(nameInformation);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInformation);
        return BlackshardFailureRequiresBlock(
            BlackshardFailurePathResolution,
            MustEnforce,
            FALSE
            );
    }

    administratorOnlyImage = (BOOLEAN)(
        MustEnforce != 0 &&
        BlackshardIsAdministratorOnlyImage(FltObjects, nameInformation)
        );

    if (RestrictToHighRiskName) {
        if ((Operation == BLACKSHARD_OPERATION_PROTECTED_WRITE ||
             Operation == BLACKSHARD_OPERATION_PROTECTED_METADATA) &&
            !BlackshardIsProtectedDocumentName(nameInformation)) {
            FltReleaseFileNameInformation(nameInformation);
            return FALSE;
        }
        if (Operation != BLACKSHARD_OPERATION_PROTECTED_WRITE &&
            Operation != BLACKSHARD_OPERATION_PROTECTED_METADATA &&
            !BlackshardShouldScanName(
                nameInformation,
                (ACCESS_MASK)DesiredAccess
                )) {
            FltReleaseFileNameInformation(nameInformation);
            return FALSE;
        }
    }


    RtlZeroMemory(&standardInformation, sizeof(standardInformation));
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &standardInformation,
        sizeof(standardInformation),
        FileStandardInformation,
        NULL
        );
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInformation);
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            administratorOnlyImage
            );
    }
    if (standardInformation.Directory) {
        FltReleaseFileNameInformation(nameInformation);
        return FALSE;
    }

    RtlZeroMemory(&internalInformation, sizeof(internalInformation));
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &internalInformation,
        sizeof(internalInformation),
        FileInternalInformation,
        NULL
        );
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInformation);
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            administratorOnlyImage
            );
    }


    contentGeneration = 1;
    status = BlackshardGetOrCreateStreamContext(
        FltObjects,
        TRUE,
        (ULONGLONG)internalInformation.IndexNumber.QuadPart,
        &streamContext
        );
    if (NT_SUCCESS(status)) {
        contentGeneration = (ULONGLONG)InterlockedCompareExchange64(
            &streamContext->ContentGeneration,
            0,
            0
            );
        FltReleaseContext(streamContext);
    } else if (MustEnforce != 0) {
        FltReleaseFileNameInformation(nameInformation);
        return BlackshardFailureRequiresBlock(
            BlackshardFailureObjectResolution,
            MustEnforce,
            administratorOnlyImage
            );
    }

    pathLength = (ULONG)(nameInformation->Name.Length / sizeof(WCHAR));
    if (pathLength >= MAX_FILE_PATH_LENGTH) {
        FltReleaseFileNameInformation(nameInformation);
        return BlackshardFailureRequiresBlock(
            BlackshardFailurePathTooLong,
            MustEnforce,
            administratorOnlyImage
            );
    }

    if (gBlackshardData.ClientPort == NULL) {
        FltReleaseFileNameInformation(nameInformation);
        return BlackshardFailureRequiresBlock(
            BlackshardFailureServiceUnavailable,
            MustEnforce,
            administratorOnlyImage
            );
    }

    RtlZeroMemory(&notification, sizeof(notification));
    RtlZeroMemory(&reply, sizeof(reply));

    notification.Magic = BLACKSHARD_PROTOCOL_MAGIC;
    notification.Version = BLACKSHARD_PROTOCOL_VERSION;
    notification.Size = (USHORT)sizeof(notification);
    notification.ProcessId = requestorProcessId;
    notification.DesiredAccess = DesiredAccess;
    notification.Operation = Operation;
    notification.PathLength = pathLength;
    RtlCopyMemory(
        notification.FilePath,
        nameInformation->Name.Buffer,
        nameInformation->Name.Length
        );
    notification.FilePath[pathLength] = L'\0';
    notification.FileId = (ULONGLONG)internalInformation.IndexNumber.QuadPart;
    notification.ContentGeneration = contentGeneration;
    notification.ProcessStartKey = processStartKey;
    notification.MustEnforce = MustEnforce;

    FltReleaseFileNameInformation(nameInformation);

    replyLength = sizeof(reply);
    timeout.QuadPart = -10000LL * (
        Operation == BLACKSHARD_OPERATION_EXECUTE_SECTION
        ? BLACKSHARD_EXECUTE_TIMEOUT_MS
        : (Operation == BLACKSHARD_OPERATION_PROTECTED_WRITE ||
           Operation == BLACKSHARD_OPERATION_PROTECTED_METADATA)
        ? BLACKSHARD_PROTECTED_TIMEOUT_MS
        : BLACKSHARD_OPEN_TIMEOUT_MS);
    InterlockedIncrement64(&gBlackshardData.ScanRequests);

    status = FltSendMessage(
        gBlackshardData.FilterHandle,
        &gBlackshardData.ClientPort,
        &notification,
        sizeof(notification),
        &reply,
        &replyLength,
        &timeout
        );


    if (status == STATUS_TIMEOUT) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureTimeout,
            MustEnforce,
            administratorOnlyImage
            );
    }

    if (status != STATUS_SUCCESS) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureServiceUnavailable,
            MustEnforce,
            administratorOnlyImage
            );
    }

    if (replyLength != sizeof(reply) ||
        (reply.Verdict != VERDICT_ALLOW && reply.Verdict != VERDICT_BLOCK)) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureInvalidReply,
            MustEnforce,
            administratorOnlyImage
            );
    }
    if (reply.Magic != BLACKSHARD_PROTOCOL_MAGIC ||
        reply.Version != BLACKSHARD_PROTOCOL_VERSION ||
        reply.Size != sizeof(reply)) {
        return BlackshardFailureRequiresBlock(
            BlackshardFailureProtocolMismatch,
            MustEnforce,
            administratorOnlyImage
            );
    }






    if (MustEnforce != 0) {
        status = FltGetStreamContext(
            FltObjects->Instance,
            FltObjects->FileObject,
            &streamContext
            );
        if (NT_SUCCESS(status)) {
            ULONGLONG currentGeneration;

            currentGeneration = (ULONGLONG)InterlockedCompareExchange64(
                &streamContext->ContentGeneration,
                0,
                0
                );
            FltReleaseContext(streamContext);
            if (currentGeneration != contentGeneration) {
                return BlackshardFailureRequiresBlock(
                    BlackshardFailureContentRace,
                    MustEnforce,
                    administratorOnlyImage
                    );
            }
        } else {
            return BlackshardFailureRequiresBlock(
                BlackshardFailureContentRace,
                MustEnforce,
                administratorOnlyImage
                );
        }
    }

    return (BOOLEAN)(reply.Verdict == VERDICT_BLOCK);
}

NTSTATUS
BlackshardGetOrCreateStreamContext (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN IdentityValid,
    _In_ ULONGLONG FileId,
    _Outptr_ PBLACKSHARD_STREAM_CONTEXT *ReturnedContext
    )
{
    NTSTATUS status;
    PBLACKSHARD_STREAM_CONTEXT streamContext;
    PBLACKSHARD_STREAM_CONTEXT oldContext;

    *ReturnedContext = NULL;

    if (FltObjects->Instance == NULL ||
        FltObjects->FileObject == NULL ||
        !FltSupportsStreamContexts(FltObjects->FileObject)) {
        return STATUS_NOT_SUPPORTED;
    }

    status = FltGetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        &streamContext
        );
    if (NT_SUCCESS(status)) {
        if (IdentityValid) {
            InterlockedExchange64(&streamContext->FileId, (LONG64)FileId);
            InterlockedExchange(&streamContext->IdentityValid, TRUE);
        }
        *ReturnedContext = streamContext;
        return STATUS_SUCCESS;
    }

    if (status != STATUS_NOT_FOUND) {
        return status;
    }

    status = FltAllocateContext(
        gBlackshardData.FilterHandle,
        FLT_STREAM_CONTEXT,
        sizeof(BLACKSHARD_STREAM_CONTEXT),
        NonPagedPoolNx,
        &streamContext
        );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(streamContext, sizeof(*streamContext));
    streamContext->ContentGeneration = 1;
    if (IdentityValid) {
        streamContext->FileId = (LONG64)FileId;
        streamContext->IdentityValid = TRUE;
    }

    oldContext = NULL;
    status = FltSetStreamContext(
        FltObjects->Instance,
        FltObjects->FileObject,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        streamContext,
        &oldContext
        );

    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED && oldContext != NULL) {
        FltReleaseContext(streamContext);
        streamContext = oldContext;
        if (IdentityValid) {
            InterlockedExchange64(&streamContext->FileId, (LONG64)FileId);
            InterlockedExchange(&streamContext->IdentityValid, TRUE);
        }
        status = STATUS_SUCCESS;
    } else if (!NT_SUCCESS(status)) {
        FltReleaseContext(streamContext);
        return status;
    }

    *ReturnedContext = streamContext;
    return STATUS_SUCCESS;
}

BOOLEAN
BlackshardShouldScanName (
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ ACCESS_MASK DesiredAccess
    )
{
    static const UNICODE_STRING extensions[] = {
        RTL_CONSTANT_STRING(L"exe"), RTL_CONSTANT_STRING(L"dll"),
        RTL_CONSTANT_STRING(L"sys"), RTL_CONSTANT_STRING(L"scr"),
        RTL_CONSTANT_STRING(L"com"), RTL_CONSTANT_STRING(L"cpl"),
        RTL_CONSTANT_STRING(L"msi"), RTL_CONSTANT_STRING(L"msp"),
        RTL_CONSTANT_STRING(L"ps1"), RTL_CONSTANT_STRING(L"psm1"),
        RTL_CONSTANT_STRING(L"vbs"), RTL_CONSTANT_STRING(L"vbe"),
        RTL_CONSTANT_STRING(L"js"),  RTL_CONSTANT_STRING(L"jse"),
        RTL_CONSTANT_STRING(L"wsf"), RTL_CONSTANT_STRING(L"wsh"),
        RTL_CONSTANT_STRING(L"hta"), RTL_CONSTANT_STRING(L"bat"),
        RTL_CONSTANT_STRING(L"cmd"), RTL_CONSTANT_STRING(L"lnk"),
        RTL_CONSTANT_STRING(L"doc"), RTL_CONSTANT_STRING(L"docm"),
        RTL_CONSTANT_STRING(L"xls"), RTL_CONSTANT_STRING(L"xlsm"),
        RTL_CONSTANT_STRING(L"ppt"), RTL_CONSTANT_STRING(L"pptm"),
        RTL_CONSTANT_STRING(L"rtf"), RTL_CONSTANT_STRING(L"pdf"),
        RTL_CONSTANT_STRING(L"zip"), RTL_CONSTANT_STRING(L"rar"),
        RTL_CONSTANT_STRING(L"7z"),  RTL_CONSTANT_STRING(L"iso"),
        /* Run by an interpreter that only reads them, so no executable section is ever made. */
        RTL_CONSTANT_STRING(L"jar"), RTL_CONSTANT_STRING(L"chm"),
        RTL_CONSTANT_STRING(L"one"), RTL_CONSTANT_STRING(L"msc"),
        RTL_CONSTANT_STRING(L"sct"), RTL_CONSTANT_STRING(L"wsc")
    };
    ULONG index;

    PAGED_CODE();

    if ((DesiredAccess & (FILE_EXECUTE | GENERIC_EXECUTE)) != 0) {
        return TRUE;
    }

    if (NameInfo->Extension.Length == 0) {
        return FALSE;
    }

    for (index = 0; index < RTL_NUMBER_OF(extensions); index++) {
        if (RtlEqualUnicodeString(&NameInfo->Extension, &extensions[index], TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
BlackshardIsProtectedDocumentName (
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo
    )
{
    static const UNICODE_STRING extensions[] = {
        RTL_CONSTANT_STRING(L"doc"), RTL_CONSTANT_STRING(L"docx"),
        RTL_CONSTANT_STRING(L"docm"), RTL_CONSTANT_STRING(L"xls"),
        RTL_CONSTANT_STRING(L"xlsx"), RTL_CONSTANT_STRING(L"xlsm"),
        RTL_CONSTANT_STRING(L"ppt"), RTL_CONSTANT_STRING(L"pptx"),
        RTL_CONSTANT_STRING(L"pptm"), RTL_CONSTANT_STRING(L"pdf"),
        RTL_CONSTANT_STRING(L"txt"), RTL_CONSTANT_STRING(L"rtf"),
        RTL_CONSTANT_STRING(L"csv"), RTL_CONSTANT_STRING(L"jpg"),
        RTL_CONSTANT_STRING(L"jpeg"), RTL_CONSTANT_STRING(L"png"),
        RTL_CONSTANT_STRING(L"gif"), RTL_CONSTANT_STRING(L"bmp"),
        RTL_CONSTANT_STRING(L"svg"), RTL_CONSTANT_STRING(L"mp3"),
        RTL_CONSTANT_STRING(L"wav"), RTL_CONSTANT_STRING(L"mp4"),
        RTL_CONSTANT_STRING(L"mov"), RTL_CONSTANT_STRING(L"avi"),
        RTL_CONSTANT_STRING(L"zip"), RTL_CONSTANT_STRING(L"7z"),
        RTL_CONSTANT_STRING(L"rar"), RTL_CONSTANT_STRING(L"sql"),
        RTL_CONSTANT_STRING(L"db"), RTL_CONSTANT_STRING(L"sqlite"),
        RTL_CONSTANT_STRING(L"psd"), RTL_CONSTANT_STRING(L"ai")
    };
    static const UNICODE_STRING users = RTL_CONSTANT_STRING(L"\\users\\");
    static const UNICODE_STRING protectedFolders[] = {
        RTL_CONSTANT_STRING(L"\\desktop\\"),
        RTL_CONSTANT_STRING(L"\\documents\\"),
        RTL_CONSTANT_STRING(L"\\pictures\\"),
        RTL_CONSTANT_STRING(L"\\music\\"),
        RTL_CONSTANT_STRING(L"\\videos\\"),
        RTL_CONSTANT_STRING(L"\\favorites\\"),
        RTL_CONSTANT_STRING(L"\\onedrive\\"),
        RTL_CONSTANT_STRING(L"\\onedrive - ")
    };
    ULONG index;
    BOOLEAN protectedFolder;

    PAGED_CODE();

    if (NameInfo->Extension.Length == 0 ||
        !BlackshardNameContainsInsensitive(&NameInfo->Name, &users)) {
        return FALSE;
    }
    protectedFolder = FALSE;
    for (index = 0; index < RTL_NUMBER_OF(protectedFolders); index++) {
        if (BlackshardNameContainsInsensitive(
                &NameInfo->Name,
                &protectedFolders[index]
                )) {
            protectedFolder = TRUE;
            break;
        }
    }
    if (!protectedFolder) {
        return FALSE;
    }
    for (index = 0; index < RTL_NUMBER_OF(extensions); index++) {
        if (RtlEqualUnicodeString(&NameInfo->Extension, &extensions[index], TRUE)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN
BlackshardIsAdministratorOnlyImage (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo
    )
{
    static const UNICODE_STRING roots[] = {
        RTL_CONSTANT_STRING(L"\\Windows\\"),
        RTL_CONSTANT_STRING(L"\\Program Files\\"),
        RTL_CONSTANT_STRING(L"\\Program Files (x86)\\")
    };
    /* Folders below \Windows that standard users can create files in. */
    static const UNICODE_STRING userWritable[] = {
        RTL_CONSTANT_STRING(L"\\Temp\\"), RTL_CONSTANT_STRING(L"\\Tasks\\"),
        RTL_CONSTANT_STRING(L"\\tracing\\"), RTL_CONSTANT_STRING(L"\\CRMLog\\"),
        RTL_CONSTANT_STRING(L"\\FxsTmp\\"), RTL_CONSTANT_STRING(L"\\com\\dmp\\"),
        RTL_CONSTANT_STRING(L"\\MachineKeys\\"), RTL_CONSTANT_STRING(L"\\spool\\"),
        RTL_CONSTANT_STRING(L"\\debug\\"), RTL_CONSTANT_STRING(L"\\PLA\\")
    };
    UNICODE_STRING relative;
    ULONG index;
    BOOLEAN underRoot;

    PAGED_CODE();

    if (NameInfo->Name.Length <= NameInfo->Volume.Length) {
        return FALSE;
    }
    //
    // Anyone can create \Windows on a USB stick or a second disk. Only the volume Windows runs
    // from counts; if it could not be found at load, the folder test alone decides rather than
    // refusing Windows itself whenever the service is down.
    //
    if (gBlackshardData.SystemVolume != NULL &&
        FltObjects->Volume != gBlackshardData.SystemVolume) {
        return FALSE;
    }
    relative.Buffer = NameInfo->Name.Buffer + NameInfo->Volume.Length / sizeof(WCHAR);
    relative.Length = NameInfo->Name.Length - NameInfo->Volume.Length;
    relative.MaximumLength = relative.Length;

    underRoot = FALSE;
    for (index = 0; index < RTL_NUMBER_OF(roots); index++) {
        if (RtlPrefixUnicodeString(&roots[index], &relative, TRUE)) {
            underRoot = TRUE;
            break;
        }
    }
    if (!underRoot) {
        return FALSE;
    }
    for (index = 0; index < RTL_NUMBER_OF(userWritable); index++) {
        if (BlackshardNameContainsInsensitive(&relative, &userWritable[index])) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN
BlackshardNameContainsInsensitive (
    _In_ PCUNICODE_STRING Name,
    _In_ PCUNICODE_STRING Fragment
    )
{
    USHORT nameCharacters;
    USHORT fragmentCharacters;
    USHORT start;
    USHORT offset;
    BOOLEAN match;

    PAGED_CODE();

    if (Name == NULL || Fragment == NULL ||
        Name->Buffer == NULL || Fragment->Buffer == NULL ||
        Fragment->Length == 0 || Name->Length < Fragment->Length) {
        return FALSE;
    }
    nameCharacters = Name->Length / sizeof(WCHAR);
    fragmentCharacters = Fragment->Length / sizeof(WCHAR);
    for (start = 0;
         start <= nameCharacters - fragmentCharacters;
         start++) {
        match = TRUE;
        for (offset = 0; offset < fragmentCharacters; offset++) {
            if (RtlUpcaseUnicodeChar(Name->Buffer[start + offset]) !=
                RtlUpcaseUnicodeChar(Fragment->Buffer[offset])) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS
BlackshardPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    PAGED_CODE();

    if (ConnectionPortCookie != NULL) {
        *ConnectionPortCookie = NULL;
    }

    if (gBlackshardData.ClientPort != NULL) {
        return STATUS_ALREADY_COMMITTED;
    }

    gBlackshardData.ClientProcessId = PsGetCurrentProcessId();
    ObReferenceObject(PsGetCurrentProcess());
    InterlockedExchangePointer(
        (PVOID volatile *)&gBlackshardData.ClientProcess,
        PsGetCurrentProcess()
        );
    gBlackshardData.ClientPort = ClientPort;
    InterlockedExchange(
        &gBlackshardData.OperationalPhase,
        BlackshardPhaseStarting
        );
    InterlockedExchange64(&gBlackshardData.ReadyGeneration, 0);

    return STATUS_SUCCESS;
}

VOID
BlackshardPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
{
    PEPROCESS clientProcess;

    UNREFERENCED_PARAMETER(ConnectionCookie);

    PAGED_CODE();

    FltCloseClientPort(
        gBlackshardData.FilterHandle,
        &gBlackshardData.ClientPort
        );
    gBlackshardData.ClientProcessId = NULL;
    clientProcess = (PEPROCESS)InterlockedExchangePointer(
        (PVOID volatile *)&gBlackshardData.ClientProcess,
        NULL
        );
    if (clientProcess != NULL) {
        ObDereferenceObject(clientProcess);
    }
    InterlockedExchange64(&gBlackshardData.ReadyGeneration, 0);
    //
    // A service that said it was stopping left on purpose; any other disconnect is a crash or a
    // kill, and executions stay refused until it is back.
    //
    if (InterlockedCompareExchange(&gBlackshardData.OperationalPhase, 0, 0) !=
        BlackshardPhaseStopping) {
        InterlockedExchange(
            &gBlackshardData.OperationalPhase,
            BlackshardPhaseRecovering
            );
    }
}

NTSTATUS
BlackshardPortMessage (
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength,*ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    BLACKSHARD_CONTROL_REQUEST request;
    BLACKSHARD_HEALTH_REPLY reply;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(PortCookie);

    PAGED_CODE();

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL ||
        InputBufferLength != sizeof(request)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&request, sizeof(request));
    status = STATUS_SUCCESS;
    __try {
        RtlCopyMemory(&request, InputBuffer, sizeof(request));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (request.Magic != BLACKSHARD_PROTOCOL_MAGIC ||
        request.Version != BLACKSHARD_PROTOCOL_VERSION ||
        request.Size != sizeof(request)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request.Command == BLACKSHARD_CONTROL_SET_READY_GENERATION) {
        if (request.Generation == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        InterlockedExchange64(
            &gBlackshardData.ReadyGeneration,
            (LONG64)request.Generation
            );
        InterlockedExchange(
            &gBlackshardData.OperationalPhase,
            BlackshardPhaseReady
            );
        InterlockedExchange(&gBlackshardData.EverReady, TRUE);
        return STATUS_SUCCESS;
    }

    if (request.Command == BLACKSHARD_CONTROL_SET_STOPPING) {
        InterlockedExchange64(&gBlackshardData.ReadyGeneration, 0);
        InterlockedExchange(
            &gBlackshardData.OperationalPhase,
            BlackshardPhaseStopping
            );
        return STATUS_SUCCESS;
    }

    if (request.Command != BLACKSHARD_CONTROL_GET_HEALTH) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutputBuffer == NULL ||
        OutputBufferLength < sizeof(reply)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&reply, sizeof(reply));
    reply.Magic = BLACKSHARD_PROTOCOL_MAGIC;
    reply.Version = BLACKSHARD_PROTOCOL_VERSION;
    reply.Size = (USHORT)sizeof(reply);
    reply.ScanRequests = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.ScanRequests, 0, 0);
    reply.Blocks = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.Blocks, 0, 0);
    reply.Timeouts = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.Timeouts, 0, 0);
    reply.ServiceUnavailableBypasses =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.ServiceUnavailableBypasses, 0, 0);
    reply.ObjectResolutionBypasses =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.ObjectResolutionBypasses, 0, 0);
    reply.OversizePathBypasses =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.OversizePathBypasses, 0, 0);
    reply.IrqlBypasses = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.IrqlBypasses, 0, 0);
    reply.InvalidReplies = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.InvalidReplies, 0, 0);
    reply.DirtyWrites = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.DirtyWrites, 0, 0);
    reply.EnforcementBypasses =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.EnforcementBypasses, 0, 0);
    reply.ContentRaceBlocks =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.ContentRaceBlocks, 0, 0);
    reply.PathResolutionFailures =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.PathResolutionFailures, 0, 0);
    reply.ProtocolMismatches =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.ProtocolMismatches, 0, 0);
    reply.CacheAllows = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.CacheAllows, 0, 0);
    reply.BootPolicyAllows =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.BootPolicyAllows, 0, 0);
    reply.RequiredEnforcementBlocks =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.RequiredEnforcementBlocks, 0, 0);
    reply.QueueOverloads = (ULONGLONG)InterlockedCompareExchange64(
        &gBlackshardData.QueueOverloads, 0, 0);
    reply.ReadyGeneration =
        (ULONGLONG)InterlockedCompareExchange64(
            &gBlackshardData.ReadyGeneration, 0, 0);
    reply.OperationalPhase = (ULONG)InterlockedCompareExchange(
        &gBlackshardData.OperationalPhase, 0, 0);
    reply.Features = gBlackshardData.Features;

    status = STATUS_SUCCESS;
    __try {
        RtlCopyMemory(OutputBuffer, &reply, sizeof(reply));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *ReturnOutputBufferLength = sizeof(reply);
    return STATUS_SUCCESS;
}

VOID
BlackshardRegisterSelfProtection (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    OB_OPERATION_REGISTRATION operations[2];
    OB_CALLBACK_REGISTRATION registration;
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(BLACKSHARD_CALLBACK_ALTITUDE);
    NTSTATUS status;

    //
    // Each part is optional: a driver that loads without one still filters files, and the
    // service logs which parts the health reply says are missing.
    //
    RtlZeroMemory(operations, sizeof(operations));
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = BlackshardPreObjectHandle;
    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = BlackshardPreObjectHandle;

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistrationCount = RTL_NUMBER_OF(operations);
    registration.Altitude = altitude;
    registration.OperationRegistration = operations;
    status = ObRegisterCallbacks(&registration, &gBlackshardData.ObjectCallbacks);
    if (NT_SUCCESS(status)) {
        gBlackshardData.Features |= BLACKSHARD_FEATURE_HANDLE_PROTECTION;
    } else {
        gBlackshardData.ObjectCallbacks = NULL;
    }

    status = CmRegisterCallbackEx(
        BlackshardRegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &gBlackshardData.RegistryCookie,
        NULL
        );
    if (NT_SUCCESS(status)) {
        gBlackshardData.Features |= BLACKSHARD_FEATURE_REGISTRY_PROTECTION;
    }
}

VOID
BlackshardUnregisterSelfProtection (
    VOID
    )
{
    PAGED_CODE();

    if (FlagOn(gBlackshardData.Features, BLACKSHARD_FEATURE_REGISTRY_PROTECTION)) {
        (VOID)CmUnRegisterCallback(gBlackshardData.RegistryCookie);
        ClearFlag(gBlackshardData.Features, BLACKSHARD_FEATURE_REGISTRY_PROTECTION);
    }
    if (gBlackshardData.ObjectCallbacks != NULL) {
        ObUnRegisterCallbacks(gBlackshardData.ObjectCallbacks);
        gBlackshardData.ObjectCallbacks = NULL;
        ClearFlag(gBlackshardData.Features, BLACKSHARD_FEATURE_HANDLE_PROTECTION);
    }
}

BOOLEAN
BlackshardSelfProtectionActive (
    VOID
    )
{
    LONG phase;

    //
    // Off before the service first connects this boot and after it stopped on purpose, so a
    // broken install can still be repaired and an uninstall can run. On while it runs, and
    // after it crashed or was killed until it is back.
    //
    phase = InterlockedCompareExchange(&gBlackshardData.OperationalPhase, 0, 0);
    return (BOOLEAN)(
        phase == BlackshardPhaseStarting ||
        phase == BlackshardPhaseReady ||
        phase == BlackshardPhaseRecovering
        );
}

OB_PREOP_CALLBACK_STATUS
BlackshardPreObjectHandle (
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    PEPROCESS protectedProcess;
    PEPROCESS target;
    ACCESS_MASK denied;

    UNREFERENCED_PARAMETER(RegistrationContext);

    protectedProcess = (PEPROCESS)InterlockedCompareExchangePointer(
        (PVOID volatile *)&gBlackshardData.ClientProcess,
        NULL,
        NULL
        );
    if (protectedProcess == NULL ||
        OperationInformation->KernelHandle ||
        PsGetCurrentProcess() == protectedProcess) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType == *PsProcessType) {
        target = (PEPROCESS)OperationInformation->Object;
        denied = BLACKSHARD_DENIED_PROCESS_ACCESS;
    } else {
        target = IoThreadToProcess((PETHREAD)OperationInformation->Object);
        denied = BLACKSHARD_DENIED_THREAD_ACCESS;
    }
    if (target != protectedProcess) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~denied;
    } else {
        OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~denied;
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS
BlackshardRegistryCallback (
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    PEPROCESS service;
    PVOID keyObject;
    PCUNICODE_STRING keyName;
    BOOLEAN protectedKey;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CallbackContext);

    PAGED_CODE();

    //
    // Kernel-mode callers are not refused: the I/O manager records the driver's Enum key itself,
    // and kernel code could undo this callback anyway.
    //
    if (Argument2 == NULL ||
        ExGetPreviousMode() == KernelMode ||
        !BlackshardSelfProtectionActive()) {
        return STATUS_SUCCESS;
    }
    service = (PEPROCESS)InterlockedCompareExchangePointer(
        (PVOID volatile *)&gBlackshardData.ClientProcess,
        NULL,
        NULL
        );
    if (service != NULL && PsGetCurrentProcess() == service) {
        return STATUS_SUCCESS;
    }

    switch ((REG_NOTIFY_CLASS)(ULONG_PTR)Argument1) {
    case RegNtPreSetValueKey:
        keyObject = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreDeleteValueKey:
        keyObject = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreDeleteKey:
        keyObject = ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreRenameKey:
        keyObject = ((PREG_RENAME_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreSetInformationKey:
        keyObject = ((PREG_SET_INFORMATION_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreRestoreKey:
        keyObject = ((PREG_RESTORE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreReplaceKey:
        keyObject = ((PREG_REPLACE_KEY_INFORMATION)Argument2)->Object;
        break;
    default:
        return STATUS_SUCCESS;
    }

    keyName = NULL;
    status = CmCallbackGetKeyObjectIDEx(
        &gBlackshardData.RegistryCookie,
        keyObject,
        NULL,
        &keyName,
        0
        );
    if (!NT_SUCCESS(status) || keyName == NULL) {
        return STATUS_SUCCESS;
    }
    protectedKey = BlackshardIsProtectedRegistryKey(keyName);
    CmCallbackReleaseKeyObjectIDEx(keyName);
    return protectedKey ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
}

BOOLEAN
BlackshardIsProtectedRegistryKey (
    _In_ PCUNICODE_STRING KeyName
    )
{
    static const UNICODE_STRING system = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\");
    /* Below a control set, so ControlSet001, ControlSet002 and CurrentControlSet all match. */
    static const UNICODE_STRING protectedKeys[] = {
        RTL_CONSTANT_STRING(L"\\Services\\blackshard"),
        RTL_CONSTANT_STRING(L"\\Services\\blackshard-protection-service")
    };
    UNICODE_STRING rest;
    USHORT skipped;
    ULONG index;
    USHORT keyCharacters;

    PAGED_CODE();

    if (!RtlPrefixUnicodeString(&system, KeyName, TRUE)) {
        return FALSE;
    }
    rest.Buffer = KeyName->Buffer + system.Length / sizeof(WCHAR);
    rest.Length = KeyName->Length - system.Length;
    for (skipped = 0;
         skipped < rest.Length / sizeof(WCHAR) && rest.Buffer[skipped] != L'\\';
         skipped++) {
    }
    rest.Buffer += skipped;
    rest.Length = (USHORT)(rest.Length - skipped * sizeof(WCHAR));
    rest.MaximumLength = rest.Length;

    for (index = 0; index < RTL_NUMBER_OF(protectedKeys); index++) {
        keyCharacters = protectedKeys[index].Length / sizeof(WCHAR);
        if (RtlPrefixUnicodeString(&protectedKeys[index], &rest, TRUE) &&
            (rest.Length == protectedKeys[index].Length ||
             rest.Buffer[keyCharacters] == L'\\')) {
            return TRUE;
        }
    }
    return FALSE;
}
