#include <iostream>

#include "ExternalChecks/External.h"
#include "Process/Process.h"
#include "Memory/Memory.h"
#include "Util/Util.h"
#include "Patches.h"

#include "Injection/Injection.h"
#include <string>


/*
	made by volx :3
*/


// if you want it to inject a DLL, uncomment this and change to your wished module name
#define INJECT "Module.dll"

int WINAPI WinMain(
	HINSTANCE,
	HINSTANCE,
	LPSTR lpCmdLine,
	int
)
{
	int argc;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

	SetConsoleTitleA("Integrity Bypass");

	DWORD pid;
	if (argc == 1) {
		pid = Process::GetProcessId("RobloxPlayerBeta.exe");
		if (!pid) {
			MessageBoxA(0, "Roblox not found!", "Essential", 0x10);
			std::cin.get();
			return 1;
		}
	}
	else {
		pid = std::stoul(argv[1]);
	}

	// 0x1 removes PROCESS_TERMINATE permission (bypass handle detection)
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS - 0x1, FALSE, pid);

	uintptr_t hyperionBase = Process::GetModuleBaseAddress("RobloxPlayerBeta.dll", hProcess);
	uintptr_t ntdllBase = Process::GetModuleBaseAddress("ntdll.dll", hProcess);

	ExternalChecks::InstallHook();

	Util::SuspendProcess(pid, true);
	Memory::RemapMemory(hProcess, hyperionBase, ".byfron");
	for (auto& p : Patches::patches) {
		for (const auto a : p.rvas) {
			Memory::PatchAddr(hProcess, a + hyperionBase, p.patch);
		}
	}
	Util::SuspendProcess(pid, false);

	
#ifdef INJECT
	if (!Injection::InjectDll(INJECT, hProcess, pid)) {
		MessageBoxA(0, "Failed to Inject!", "Essential", 0x10);
		std::cin.get();
	}
#endif


	return 0;
}
