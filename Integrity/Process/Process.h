#pragma once
#include <iostream>
#include <Windows.h>



namespace Process {

	DWORD GetProcessId(const std::string& windowName);
	uintptr_t GetModuleBaseAddress(const std::string& moduleName, HANDLE hProcess);
	uintptr_t GetRemoteModuleProc(uintptr_t module, const std::string& func, HANDLE hProc);

	void SetFilePerms(const char* path, bool access);


}