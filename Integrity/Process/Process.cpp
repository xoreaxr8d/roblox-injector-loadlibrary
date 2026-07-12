#include "Process.h"

#include <TlHelp32.h>
#include <psapi.h>
#include <vector>
#include <sstream>
#include <aclapi.h>
#include <sddl.h>




DWORD Process::GetProcessId(const std::string& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_stricmp(entry.szExeFile, processName.c_str()) == 0) {
            DWORD pid = entry.th32ProcessID;
            CloseHandle(snapshot);
            return pid;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return 0;
}

uintptr_t Process::GetModuleBaseAddress(const std::string& moduleName, HANDLE hProcess) {
    if (!hProcess) return 0x0;

    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                if (_stricmp(szModName, moduleName.c_str()) == 0) {
                    return (uint64_t)hMods[i];
                }
            }
        }
    }
    return 0x0;
}


uintptr_t Process::GetRemoteModuleProc(uintptr_t module, const std::string& func, HANDLE hProc) {
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProc, (LPCVOID)module, &dosHeader, sizeof(dosHeader), nullptr)) {
        return 0;
    }

    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProc, (LPCVOID)(module + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr)) {
        return 0;
    }

    const auto& exportDirData = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData.VirtualAddress == 0 || exportDirData.Size == 0) {
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(hProc, (LPCVOID)(module + exportDirData.VirtualAddress), &exportDir, sizeof(exportDir), nullptr)) {
        return 0;
    }

    std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);

    if (!ReadProcessMemory(hProc, (LPCVOID)(module + exportDir.AddressOfNames), nameRVAs.data(), sizeof(DWORD) * nameRVAs.size(), nullptr) ||
        !ReadProcessMemory(hProc, (LPCVOID)(module + exportDir.AddressOfNameOrdinals), ordinals.data(), sizeof(WORD) * ordinals.size(), nullptr) ||
        !ReadProcessMemory(hProc, (LPCVOID)(module + exportDir.AddressOfFunctions), functionRVAs.data(), sizeof(DWORD) * functionRVAs.size(), nullptr)) {
        return 0;
    }

    char nameBuffer[256];
    for (size_t i = 0; i < nameRVAs.size(); ++i) {
        if (!ReadProcessMemory(hProc, (LPCVOID)(module + nameRVAs[i]), nameBuffer, sizeof(nameBuffer), nullptr))
            continue;

        if (strcmp(nameBuffer, func.c_str()) == 0) {
            WORD ordinal = ordinals[i];
            if (ordinal >= functionRVAs.size()) {
                return 0;
            }

            return module + functionRVAs[ordinal];
        }
    }

    return 0;
}


void Process::SetFilePerms(const char* path, bool allowAccess) {
    PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
    PACL dacl = nullptr;

    LPCWSTR sddlString = allowAccess
        ? L"D:(D;;FA;;;WD)"
        : L"D:(A;;FA;;;WD)";

    wchar_t widePath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, widePath, MAX_PATH);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddlString,
        SDDL_REVISION_1,
        &securityDescriptor,
        nullptr)) {
        return;
    }

    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    GetSecurityDescriptorDacl(securityDescriptor, &daclPresent, &dacl, &daclDefaulted);

    SetNamedSecurityInfoW(
        widePath,
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        dacl,
        nullptr);

    LocalFree(securityDescriptor);
}