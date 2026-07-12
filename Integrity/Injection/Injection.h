#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>


struct InjectionContext {
	char dllPath[256];
	decltype(&LoadLibraryA) fLoadLibraryA;
};

namespace Injection {
	bool InjectDll(const std::string& dllName, HANDLE hProc, DWORD pid);
}