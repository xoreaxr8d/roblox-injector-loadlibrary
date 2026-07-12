#include "Memory.h"
#include <psapi.h>
#include <vector>
#include <algorithm>
#include <cstdio>

#include "imports.h"

NTSTATUS UnmapMemory(HANDLE hProc, uintptr_t address) {
	NTSTATUS status = NtUnmapViewOfSection(hProc, (PVOID)address);

	return status ? status : 0;
}

bool Memory::PatchAddr(HANDLE hProcess, uintptr_t addr, std::vector<uint8_t>& bytes, DWORD t) {
	DWORD op;
	VirtualProtectEx(hProcess, (PVOID)addr, bytes.size(), t, &op);
	WriteProcessMemory(hProcess, (PVOID)addr, bytes.data(), bytes.size(), nullptr);
	VirtualProtectEx(hProcess, (PVOID)addr, bytes.size(), op, &op);

	return true;
}

bool GetSection(HANDLE hProc, uintptr_t mod, const std::string& sectionName, PIMAGE_SECTION_HEADER secHeader) {
	IMAGE_DOS_HEADER dosHeader{};
	ReadProcessMemory(hProc, (PVOID)mod, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	uintptr_t ntHeadersAddr = mod + dosHeader.e_lfanew;
	IMAGE_NT_HEADERS ntHeaders{};
	ReadProcessMemory(hProc, (PVOID)ntHeadersAddr, &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr);
	WORD numOfSections = ntHeaders.FileHeader.NumberOfSections;

	uintptr_t firstSectionAddr = ntHeadersAddr + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

	std::vector<IMAGE_SECTION_HEADER> sections(numOfSections);
	ReadProcessMemory(hProc, (PVOID)firstSectionAddr, sections.data(), numOfSections * sizeof(IMAGE_SECTION_HEADER), nullptr);

	for (int i = 0; i < numOfSections; ++i) {
		if (strncmp((const char*)sections[i].Name, sectionName.c_str(), IMAGE_SIZEOF_SHORT_NAME) == 0) {
			*secHeader = sections[i];
			return true;
		}
	}

	return false;
}

bool Memory::RemapMemory(HANDLE hProc, uintptr_t modBase, const std::string& modName) {

	IMAGE_SECTION_HEADER secHeader{};

	GetSection(hProc, modBase, modName, &secHeader);

	auto secBase = modBase + secHeader.VirtualAddress;
	auto secSize = secHeader.Misc.VirtualSize;
	std::vector<uint8_t> mappedBytes(secSize);
	ReadProcessMemory(hProc, (PVOID)secBase, mappedBytes.data(), mappedBytes.size(), nullptr);
	NtUnmapViewOfSection(hProc, (PVOID)secBase);

	if (!VirtualAllocEx(hProc, (PVOID)secBase, secSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
		return false;
	}
	WriteProcessMemory(hProc, (PVOID)secBase, mappedBytes.data(), mappedBytes.size(), nullptr);
	DWORD op;
	VirtualProtectEx(hProc, (PVOID)secBase, secSize, PAGE_EXECUTE_READ, &op);

	return true;
}




void Memory::RemapMemoryHard(HANDLE hProc, uintptr_t moduleBase, const std::string& sectionName) {
	uintptr_t codeStart = 0x0;
	uintptr_t codeSize = 0x0;

	IMAGE_DOS_HEADER dosHeader = {};
	IMAGE_NT_HEADERS ntHeaders = {};

	ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(moduleBase), &dosHeader, sizeof(dosHeader), nullptr);
	ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(moduleBase + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), nullptr);

	std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
	uintptr_t sectionHeaders = moduleBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS);

	ReadProcessMemory(
		hProc,
		reinterpret_cast<LPCVOID>(sectionHeaders),
		sections.data(),
		sizeof(IMAGE_SECTION_HEADER) * sections.size(),
		nullptr
	);

	for (const auto& section : sections) {
		if (strncmp(reinterpret_cast<const char*>(section.Name), sectionName.c_str(), strlen(sectionName.c_str())) != 0)
			continue;

		BYTE* regionPtr = reinterpret_cast<BYTE*>(moduleBase + section.VirtualAddress);
		MEMORY_BASIC_INFORMATION mbi = {};

		while (VirtualQueryEx(hProc, regionPtr, &mbi, sizeof(mbi)) != 0) {
			if (mbi.Type == MEM_MAPPED) {
				codeStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress) - moduleBase;
				codeSize = mbi.RegionSize;
				break;
			}

			regionPtr = reinterpret_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
		}

		if (codeStart && codeSize)
			break;
	}


	if (!codeStart || !codeSize) {
		return;
	}

	std::vector<BYTE> dllBuffer(codeSize);
	if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(moduleBase + codeStart), dllBuffer.data(), codeSize, nullptr)) {
		return;
	}

	char tempPath[MAX_PATH] = {};
	char tempFileName[MAX_PATH] = {};

	GetTempPathA(MAX_PATH, tempPath);
	GetTempFileNameA(tempPath, "TMP", 0, tempFileName);

	HANDLE hFile = CreateFileA(
		tempFileName,
		GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		return;
	}

	DWORD bytesWritten = 0;
	if (!WriteFile(hFile, dllBuffer.data(), static_cast<DWORD>(codeSize), &bytesWritten, nullptr)) {
		CloseHandle(hFile);
		return;
	}

	FlushFileBuffers(hFile);


	if (!NtCreateSection || !NtMapViewOfSection) {
		CloseHandle(hFile);
		return;
	}

	HANDLE hSection = nullptr;
	LARGE_INTEGER sectionMax = {};
	sectionMax.QuadPart = codeSize;

	NTSTATUS status = NtCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		nullptr,
		&sectionMax,
		PAGE_EXECUTE_WRITECOPY,
		SEC_COMMIT,
		hFile
	);

	if (!NT_SUCCESS(status)) {
		CloseHandle(hFile);
		return;
	}

	status = UnmapMemory(hProc, moduleBase + codeStart);
	if (!NT_SUCCESS(status)) {
		CloseHandle(hSection);
		CloseHandle(hFile);
		return;
	}

	PVOID targetBaseAddress = reinterpret_cast<PVOID>(moduleBase + codeStart);
	SIZE_T viewSize = 0;

	status = NtMapViewOfSection(
		hSection,
		hProc,
		&targetBaseAddress,
		0,
		0,
		nullptr,
		&viewSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_WRITECOPY
	);

	DWORD oo;
	VirtualProtectEx(hProc, (PVOID)(targetBaseAddress), viewSize, PAGE_EXECUTE_READ, &oo);

	CloseHandle(hSection);
	CloseHandle(hFile);
}
