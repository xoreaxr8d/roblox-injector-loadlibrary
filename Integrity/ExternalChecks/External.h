#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <winternl.h>

typedef CLIENT_ID* PCLIENT_ID;

using tNtOpenProcess = NTSTATUS(__fastcall*)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	CLIENT_ID* ClientId
	);
struct HookContext {
	DWORD robloxProcessId;
	tNtOpenProcess fNtOpenProcess;
};

struct ThreadData {
	DWORD pid;
	DWORD currentInstancePid;

	std::vector<uint8_t> baseShellcode;
	std::atomic<int>* hooked;
};

namespace ExternalChecks {
	int InstallHook();
}