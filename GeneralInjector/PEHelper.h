#pragma once

#include "stdafx.h"

//
// Helper class for PE file access, currently only support image mapping (not file mapping)
//
class PEHelper {
private:
	ULONG_PTR ImageBase;
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS64 NtHeader64;
	PIMAGE_NT_HEADERS32 NtHeader32;
	PIMAGE_SECTION_HEADER SecHeader;
	ULONG_PTR EntryPoint;
	ULONG_PTR DefaultBase;
	ULONG_PTR RelocBase;
	ULONG_PTR ImportBase;
	ULONG_PTR ImageSize;
	LONG_PTR RelocDelta;
	BOOLEAN Is64Mod;
public:
	PEHelper(PVOID imageBase);
	ULONG_PTR inline GetDirectoryEntryVa(ULONG Index);
	ULONG_PTR inline GetDirectoryEntryRva(ULONG Index);

	// Relocation
	PIMAGE_BASE_RELOCATION inline GetNextRelocBlock(PIMAGE_BASE_RELOCATION RelocBlock);
	ULONG inline GetRelocBlockEntryCount(PIMAGE_BASE_RELOCATION RelocBlock);
	PWORD inline GetRelocBlockEntryBase(PIMAGE_BASE_RELOCATION RelocBlock);
	ULONG_PTR inline GetRelocPointer(PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index);

	// Import
	ULONG_PTR inline GetImportOriginalThunk(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
	ULONG_PTR inline GetImportThunk(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
	LPCSTR inline  GetImportModuleName(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
	LPCSTR inline GetImportFuncName(ULONG_PTR ImportThunk);

};