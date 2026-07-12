#include "Util.h"
#include "TlHelp32.h"



std::vector<BYTE> Util::ExtractShellcode(uintptr_t func) {
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery((void*)func, &mbi, sizeof(mbi));
	size_t functionSize = mbi.RegionSize;
	std::vector<BYTE> shellcode;
	for (size_t i = 0; i < functionSize; ++i) {
		BYTE value = *(BYTE*)(func + i);
		shellcode.push_back(value);

		if (value == 0xCC && *(BYTE*)(func + i + 1) == 0xCC && *(BYTE*)(func + i + 2) == 0xCC) {
			break;
		}
	}
	return shellcode;
}

void Util::ReplaceShellcode(std::vector<BYTE>& data, uint64_t searchValue, uint64_t replaceValue) {
	const BYTE movPrefix = 0x48;
	const BYTE movPrefix2 = 0x49;
	const BYTE movBaseOpcode = 0xB8;
	const size_t instructionSize = 10;
	for (size_t i = 0; i <= data.size() - instructionSize; ++i) {
		if ((data[i] == movPrefix || data[i] == movPrefix2) && data[i + 1] >= movBaseOpcode && data[i + 1] <= movBaseOpcode + 7) {
			uint64_t imm = *(uint64_t*)(&data[i + 2]);
			uint32_t offset = *(uint32_t*)(&data[i + 2]);
			if (imm - offset == searchValue) {
				uintptr_t newValue = replaceValue + offset;
				std::memcpy(&data[i + 2], &newValue, sizeof(newValue));
			}
		}

		uint64_t immQ = *(uint64_t*)(&data[i + 1]);
		uint32_t immO = *(uint32_t*)(&data[i + 1]);
		if ((data[i] == 0xA1 || data[i] == 0xA2 || data[i] == 0xA3) && immQ - immO == searchValue) {
			uintptr_t newValue = replaceValue + immO;
			std::memcpy(&data[i + 1], &newValue, sizeof(newValue));
		}
	}
}


inline std::vector<uint8_t> GetAbsoluteJumpShellcode(uint64_t targetAddress)
{
	std::vector<uint8_t> bytes(14);

	bytes[0] = 0xFF;
	bytes[1] = 0x25;
	bytes[2] = 0x00;
	bytes[3] = 0x00;
	bytes[4] = 0x00;
	bytes[5] = 0x00;

	std::memcpy(bytes.data() + 6, &targetAddress, sizeof(targetAddress));

	return bytes;
}

std::vector<uint8_t> Util::GetJumpShellcode(uint64_t patchAddress, uint64_t targetAddress)
{
	int64_t relOffset = static_cast<int64_t>(targetAddress) -
		static_cast<int64_t>(patchAddress) - 5;

	if (relOffset >= INT32_MIN && relOffset <= INT32_MAX)
	{
		std::vector<uint8_t> bytes(5);

		bytes[0] = 0xE9;

		int32_t offset32 = static_cast<int32_t>(relOffset);
		std::memcpy(bytes.data() + 1, &offset32, sizeof(offset32));

		return bytes;
	}

	return GetAbsoluteJumpShellcode(targetAddress);
}


void Util::SuspendProcess(DWORD pid, bool state) {
	THREADENTRY32 te32{ sizeof(te32) };
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snap == INVALID_HANDLE_VALUE) return;

	for (BOOL ok = Thread32First(snap, &te32); ok; ok = Thread32Next(snap, &te32)) {
		if (te32.th32OwnerProcessID != pid) continue;
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
		if (hThread) {
			state ? SuspendThread(hThread) : ResumeThread(hThread);
			CloseHandle(hThread);
		}
	}

	CloseHandle(snap);
}

uint64_t Util::GetJumpAddress(const std::vector<BYTE>& bytes, uint64_t instrAddress)
{
	if (bytes.empty())
		return 0;

	if (bytes.size() >= 12 &&
		bytes[0] == 0x48 && bytes[1] == 0xB8 &&
		bytes[10] == 0xFF && bytes[11] == 0xE0)
	{
		uint64_t target = 0;
		std::memcpy(&target, bytes.data() + 2, sizeof(uint64_t));
		return target;
	}

	if (bytes.size() >= 14 &&
		bytes[0] == 0xFF && bytes[1] == 0x25)
	{
		uint64_t target = 0;
		std::memcpy(&target, bytes.data() + 6, sizeof(uint64_t));
		return target;
	}

	if (bytes.size() >= 6 &&
		bytes[0] == 0xFF && bytes[1] == 0x25)
	{
		int32_t disp = 0;
		std::memcpy(&disp, bytes.data() + 2, sizeof(int32_t));

		uint64_t rip = instrAddress + 6;
		uint64_t ptrAddr = rip + disp;

		return *reinterpret_cast<uint64_t*>(ptrAddr);
	}

	if (bytes.size() >= 5 && bytes[0] == 0xE9)
	{
		int32_t relOffset = 0;
		std::memcpy(&relOffset, bytes.data() + 1, sizeof(int32_t));
		return instrAddress + 5 + relOffset;
	}

	return 0;
}



std::vector<DWORD> Util::GetThreadsFromPid(DWORD pid)
{
	std::vector<DWORD> threads;

	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return threads;

	THREADENTRY32 te;
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(snapshot, &te))
	{
		do {

			if (te.th32OwnerProcessID == pid) {
				threads.push_back(te.th32ThreadID);
			}

		} while (Thread32Next(snapshot, &te));
	}

	CloseHandle(snapshot);
	return threads;
}