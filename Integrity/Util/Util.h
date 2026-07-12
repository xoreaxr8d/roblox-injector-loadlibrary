#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>



namespace Util {
	std::vector<uint8_t> ExtractShellcode(uintptr_t func);
	void ReplaceShellcode(std::vector<BYTE>& data, uint64_t searchValue, uint64_t replaceValue);
	std::vector<uint8_t> GetJumpShellcode(uint64_t patchAddress, uint64_t targetAddress);
	uintptr_t GetJumpAddress(const std::vector<BYTE>& bytes, uint64_t instrAddress);
	std::vector<DWORD> GetThreadsFromPid(DWORD pid);

	void SuspendProcess(DWORD pid, bool state);
}