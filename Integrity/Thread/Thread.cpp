#include "Thread.h"

#include <memory>
#include <cstdio>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                 ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL            ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH    ((NTSTATUS)0xC0000004L)
#endif

bool CThread::CreateThread(HANDLE hProc, PVOID function) {
    if (!hProc || !function) {
        return false;
    }

    ULONG returnLength = 0;
    SIZE_T bufferSize = 0x20000;
    std::unique_ptr<BYTE[]> handlesBuffer;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION handles = nullptr;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    for (;;) {
        handlesBuffer = std::make_unique<BYTE[]>(bufferSize);
        ZeroMemory(handlesBuffer.get(), bufferSize);

        status = NtQueryInformationProcess(
            hProc,
            (PROCESSINFOCLASS)51,
            handlesBuffer.get(),
            (ULONG)bufferSize,
            &returnLength
        );

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength ? returnLength + 0x1000 : bufferSize * 2;
            continue;
        }

        break;
    }

    if (!NT_SUCCESS(status)) {
        return false;
    }

    handles = reinterpret_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(handlesBuffer.get());
    if (!handles->NumberOfHandles) {
        return false;
    }

    std::unique_ptr<BYTE[]> typeInfoBuffer = std::make_unique<BYTE[]>(0x4000);
    POBJECT_TYPE_INFORMATION typeInfo = reinterpret_cast<POBJECT_TYPE_INFORMATION>(typeInfoBuffer.get());

    HANDLE completionHandle = nullptr;

    for (ULONG_PTR i = 0; i < handles->NumberOfHandles; i++) {
        HANDLE sourceHandle = handles->Handles[i].HandleValue;
        HANDLE duplicatedHandle = nullptr;

        if (!DuplicateHandle(
            hProc,
            sourceHandle,
            GetCurrentProcess(),
            &duplicatedHandle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS)) {
            continue;
        }

        ZeroMemory(typeInfoBuffer.get(), 0x4000);

        status = NtQueryObject(
            duplicatedHandle,
            (OBJECT_INFORMATION_CLASS)2,
            typeInfo,
            0x4000,
            nullptr
        );

        if (!NT_SUCCESS(status) || !typeInfo->TypeName.Buffer) {
            CloseHandle(duplicatedHandle);
            continue;
        }

        if (wcscmp(L"IoCompletion", typeInfo->TypeName.Buffer) == 0) {
            completionHandle = duplicatedHandle;
            break;
        }

        CloseHandle(duplicatedHandle);
    }

    if (!completionHandle) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PTP_DIRECT remoteDirectAddress = nullptr;
    PBYTE searchAddress = nullptr;
    SIZE_T minCaveSize = sizeof(TP_DIRECT);

    while (VirtualQueryEx(hProc, searchAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        searchAddress = reinterpret_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;

        if (mbi.State != MEM_COMMIT) {
            continue;
        }

        if ((mbi.Protect & PAGE_READWRITE) == 0) {
            continue;
        }

        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
            continue;
        }

        if (mbi.RegionSize < minCaveSize) {
            continue;
        }

        BYTE   buffer[4096];
        SIZE_T bytesRead = 0;
        PBYTE  regionAddress = reinterpret_cast<PBYTE>(mbi.BaseAddress);

        for (SIZE_T offset = 0; offset < mbi.RegionSize; offset += sizeof(buffer)) {
            SIZE_T remain = mbi.RegionSize - offset;
            SIZE_T readSize = remain > sizeof(buffer) ? sizeof(buffer) : remain;

            if (!ReadProcessMemory(hProc, regionAddress + offset, buffer, readSize, &bytesRead)) {
                break;
            }

            for (SIZE_T j = 0; j + minCaveSize <= bytesRead; j++) {
                bool isCave = true;

                for (SIZE_T k = 0; k < minCaveSize; k++) {
                    if (buffer[j + k] != 0) {
                        isCave = false;
                        break;
                    }
                }

                if (isCave) {
                    remoteDirectAddress = reinterpret_cast<PTP_DIRECT>(regionAddress + offset + j);
                    break;
                }
            }

            if (remoteDirectAddress) {
                break;
            }
        }

        if (remoteDirectAddress) {
            break;
        }
    }

    if (!remoteDirectAddress) {
        CloseHandle(completionHandle);
        return false;
    }

    TP_DIRECT direct = { 0 };
    direct.Callback = function;

    if (!WriteProcessMemory(
        hProc,
        remoteDirectAddress,
        &direct,
        sizeof(TP_DIRECT),
        nullptr)) {
        CloseHandle(completionHandle);
        return false;
    }

    using Tdih = NTSTATUS(NTAPI*)(
        HANDLE    IoCompletionHandle,
        PVOID     KeyContext,
        PVOID     ApcContext,
        NTSTATUS  IoStatus,
        ULONG_PTR IoStatusInformation
        );

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        CloseHandle(completionHandle);
        return false;
    }

    FARPROC dih = GetProcAddress(hNtdll, "NtSetIoCompletion");
    if (!dih) {
        CloseHandle(completionHandle);
        return false;
    }

    Tdih zwDih = reinterpret_cast<Tdih>(dih);

    status = zwDih(completionHandle, remoteDirectAddress, 0, 0, 0);
    if (!NT_SUCCESS(status)) {
        CloseHandle(completionHandle);
        return false;
    }

    CloseHandle(completionHandle);
    return true;
}