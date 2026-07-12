// Thread.h
#pragma once

#include <Windows.h>
#include <cstdint>
#include <winternl.h>

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex; // since WINBLUE
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO { HANDLE HandleValue; ULONG_PTR HandleCount;    ULONG_PTR PointerCount;    ULONG GrantedAccess;    ULONG ObjectTypeIndex;    ULONG HandleAttributes;    ULONG Reserved; } PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    _Field_size_(NumberOfHandles) PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;


typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32                    NumaNode;
    UINT8                     IdealProcessor;
    char                      Padding[3];
    LIST_ENTRY                ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TP_DIRECT
{
    TP_TASK     Task;
    UINT64      Lock;
    LIST_ENTRY  IoCompletionInformationList;
    PVOID       Callback;
    UINT32      NumaNode;
    UINT8       IdealProcessor;
    char        Padding[3];
} TP_DIRECT, * PTP_DIRECT;

class CThread {
public:
    static bool CreateThread(HANDLE hProcess, PVOID va);
};