#include "External.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include "Process/Process.h"
#include "Util/Util.h"

#define STATUS_ACCESS_DENIED 0xC0000022




namespace ExternalChecks {

	inline std::vector<uint8_t> NtOpenProcessShellcode = {
		0x49, 0x89, 0xCA,				// mov r10, rcx
		0xB8, 0x26, 0x00, 0x00, 0x00,	// mov eax, 026h
		0x0F, 0x05,						// syscall
		0xC3							// ret
	};


	NTSTATUS NtOpenProcessHook(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID ClientId
	) {
		auto ctx = (HookContext*)0x10000000000;
		if (ClientId && (ClientId->UniqueProcess == (HANDLE)ctx->robloxProcessId) && DesiredAccess == MAXIMUM_ALLOWED) {
			return STATUS_ACCESS_DENIED;
		}

		return ctx->fNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	}
	bool IsProcessElevated(HANDLE hProcess)
	{
		HANDLE hToken = NULL;
		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
			return false;

		TOKEN_ELEVATION elev = {};
		DWORD dwSize = sizeof(elev);
		bool elevated = false;

		if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &dwSize))
			elevated = elev.TokenIsElevated != 0;

		CloseHandle(hToken);
		return elevated;
	}
	bool IsProcess64Bit(HANDLE hProcess)
	{
		BOOL bIsWow64 = FALSE;
		if (!IsWow64Process(hProcess, &bIsWow64))
			return false;
		return (bIsWow64 == FALSE);
	}
	void CollectNonAdminPids(std::vector<DWORD>& result)
	{
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE)
			return;
		PROCESSENTRY32W pe = {};
		pe.dwSize = sizeof(pe);
		if (!Process32FirstW(hSnap, &pe))
		{
			CloseHandle(hSnap);
			return;
		}
		do
		{
			DWORD pid = pe.th32ProcessID;
			if (pid == 0 || pid == 4)
				continue;

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
			if (!hProcess)
				continue;

			if (IsProcess64Bit(hProcess) && !IsProcessElevated(hProcess))
				result.push_back(pid);

			CloseHandle(hProcess);

		} while (Process32NextW(hSnap, &pe));

		CloseHandle(hSnap);
	}

	DWORD SafeCollect(std::vector<DWORD>* pResult)
	{
		__try
		{
			CollectNonAdminPids(*pResult);
			return 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return GetExceptionCode();
		}
	}
	std::vector<DWORD> GetNonAdminPids()
	{
		std::vector<DWORD> result;
		SafeCollect(&result);
		return result;
	}


	bool InstallHookForProcess(DWORD pid, DWORD robloxPid, const std::vector<uint8_t>& shellcode) {

		HANDLE tempHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		uintptr_t ntdllBase = (uintptr_t)GetModuleHandleA("ntdll.dll"); // same on every process
		uintptr_t pNtOpenProcess = ntdllBase ? (uintptr_t)GetProcAddress((HMODULE)ntdllBase, "NtOpenProcess") : 0x0;
		if (!pNtOpenProcess) 
			return false;
		

		std::vector<uint8_t> originalBytes(5);
		ReadProcessMemory(tempHandle, (PVOID)pNtOpenProcess, originalBytes.data(), originalBytes.size(), nullptr);

		size_t hookOffset = 0;

		uintptr_t hookMem = (uintptr_t)VirtualAllocEx(
			tempHandle,
			nullptr,
			0x1000,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
		if (!hookMem) return false;

		uintptr_t sharedMemory = (uintptr_t)VirtualAllocEx(
			tempHandle,
			nullptr,
			sizeof(HookContext),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);
		uintptr_t fNtOpenProcess = (uintptr_t)VirtualAllocEx(
			tempHandle,
			nullptr,
			NtOpenProcessShellcode.size() + 0x100,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);
		WriteProcessMemory(tempHandle, (PVOID)fNtOpenProcess, NtOpenProcessShellcode.data(), NtOpenProcessShellcode.size(), nullptr);

		HookContext local{};
		local.robloxProcessId = robloxPid;
		local.fNtOpenProcess = (tNtOpenProcess)fNtOpenProcess;
		WriteProcessMemory(tempHandle, (PVOID)sharedMemory, &local, sizeof(HookContext), nullptr);

		auto hookShellcode = shellcode;
		Util::ReplaceShellcode(hookShellcode, 0x10000000000, sharedMemory);

		DWORD op;
		WriteProcessMemory(tempHandle, (PVOID)(hookMem + hookOffset), hookShellcode.data(), hookShellcode.size(), nullptr);
		VirtualProtectEx(tempHandle, (PVOID)hookMem, 0x1000, PAGE_EXECUTE_READ, &op);

		auto jmpShellcode = Util::GetJumpShellcode(pNtOpenProcess, hookMem);

		VirtualProtectEx(tempHandle, (PVOID)pNtOpenProcess, 0x1000, PAGE_EXECUTE_READWRITE, &op);
		WriteProcessMemory(tempHandle, (PVOID)pNtOpenProcess, jmpShellcode.data(), jmpShellcode.size(), nullptr);
		VirtualProtectEx(tempHandle, (PVOID)pNtOpenProcess, 0x1000, op, &op);



		return true;
	}


	DWORD WINAPI hookThreadProc(LPVOID param) {
		auto* data = static_cast<ThreadData*>(param);

		if (InstallHookForProcess(data->pid, data->currentInstancePid, data->baseShellcode))
			(*data->hooked)++;

		delete data;
		return 0;
	}


	int InstallHook() {
		DWORD rbxPid = Process::GetProcessId("Roblox");
		DWORD currentPid = GetCurrentProcessId();


		auto pids = GetNonAdminPids();
		auto shellcode = Util::ExtractShellcode((uintptr_t)NtOpenProcessHook);

		std::atomic<int> hooked = 0;
		std::vector<HANDLE> threads;
		threads.reserve(pids.size());

		for (const auto pid : pids) {
			if (pid == rbxPid || pid == currentPid) 
				continue;
			
			auto* data = new ThreadData{ pid, rbxPid, shellcode, &hooked };
			HANDLE hThread = CreateThread(nullptr, 0, hookThreadProc, data, 0, nullptr);

			if (hThread) {
				threads.push_back(hThread);
			}
			else {
				delete data;
			}

		}
		WaitForMultipleObjects(static_cast<DWORD>(threads.size()), threads.data(), TRUE, INFINITE);

		for (HANDLE thread : threads)
			CloseHandle(thread);

		return pids.size();
	}

}