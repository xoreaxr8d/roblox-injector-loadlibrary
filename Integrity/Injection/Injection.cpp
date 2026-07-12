#include "Injection.h"
#include <filesystem>

#include "Util/Util.h"
#include "Thread/Thread.h"
#include "Process/Process.h"
#include "Memory/Memory.h"


void InjectionStub() {
	auto ctx = (InjectionContext*)0x1000000000;

	ctx->fLoadLibraryA(ctx->dllPath);

	return;
}



bool Injection::InjectDll(const std::string& dllName, HANDLE hProc, DWORD pid) {
	std::string fullPath = (std::filesystem::current_path() / dllName).string();

	if (fullPath.empty() || !std::filesystem::exists(fullPath)) {
		return false;
	}


	uintptr_t shared = (uintptr_t)VirtualAllocEx(
		hProc,
		nullptr,
		sizeof(InjectionContext),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);

	uintptr_t remoteKernel32 = Process::GetModuleBaseAddress("kernel32.dll", hProc);
	uintptr_t kernelbase = Process::GetModuleBaseAddress("KERNELBASE.dll", hProc);
	uintptr_t hyperion = Process::GetModuleBaseAddress("RobloxPlayerBeta.dll", hProc);


	InjectionContext local{};
	sprintf_s(local.dllPath, sizeof(local.dllPath), "%s", fullPath.c_str());
	local.fLoadLibraryA = (decltype(&LoadLibraryA))(Process::GetRemoteModuleProc(remoteKernel32, "LoadLibraryA", hProc));
	WriteProcessMemory(hProc, (PVOID)shared, &local, sizeof(InjectionContext), nullptr);

	auto shellcode = Util::ExtractShellcode((uintptr_t)InjectionStub);
	Util::ReplaceShellcode(shellcode, 0x1000000000, shared);

	uintptr_t alloc = (uintptr_t)VirtualAllocEx(
		hProc,
		nullptr,
		shellcode.size(),
		(MEM_COMMIT | MEM_RESERVE),
		(PAGE_EXECUTE_READWRITE)
	);
	WriteProcessMemory(hProc, (PVOID)alloc, shellcode.data(), shellcode.size(), nullptr);

	if (!CThread::CreateThread(hProc, (PVOID)alloc)){
		return false;
	}
	uintptr_t base = 0;
	do {

		Sleep(1);
		base = Process::GetModuleBaseAddress(dllName, hProc);
	} while (!base);


	return true;
}