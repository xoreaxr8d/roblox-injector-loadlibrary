#pragma once
#include <iostream>
#include <Windows.h>
#include <vector>



namespace Memory {
	bool RemapMemory(HANDLE hProc, uintptr_t modBase, const std::string& modName);
	bool PatchAddr(HANDLE hProcess, uintptr_t addr, std::vector<uint8_t>& bytes, DWORD t = 0x40);


	void RemapMemoryHard(HANDLE hProc, uintptr_t moduleBase, const std::string& sectionName);
}