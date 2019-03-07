#include "stdafx.h"
#include "PEHelper.h"

PEHelper::PEHelper(PVOID imageBase) {
	ImageBase = (ULONG_PTR)imageBase;
	DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	NtHeader64 = (PIMAGE_NT_HEADERS64)(ImageBase + DosHeader->e_lfanew);
	NtHeader32 = (PIMAGE_NT_HEADERS32)NtHeader64;
	Is64Mod = NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	if (Is64Mod) {
		SecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NtHeader64 + NtHeader64->OptionalHeader.SizeOfHeaders);
		ImageSize = NtHeader64->OptionalHeader.SizeOfImage;
		DefaultBase = NtHeader64->OptionalHeader.ImageBase;
		EntryPoint = ImageBase + NtHeader64->OptionalHeader.AddressOfEntryPoint;
		RelocBase = GetDirectoryEntryVa(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		ImportBase = GetDirectoryEntryVa(IMAGE_DIRECTORY_ENTRY_IMPORT);
	}
	else {
		SecHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NtHeader32 + NtHeader32->OptionalHeader.SizeOfHeaders);
		ImageSize = NtHeader32->OptionalHeader.SizeOfImage;
		DefaultBase = NtHeader32->OptionalHeader.ImageBase;
		EntryPoint = ImageBase + NtHeader32->OptionalHeader.AddressOfEntryPoint;
		RelocBase = GetDirectoryEntryVa(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		ImportBase = GetDirectoryEntryVa(IMAGE_DIRECTORY_ENTRY_IMPORT);
	}

	RelocDelta = ImageBase - DefaultBase;
}

ULONG_PTR PEHelper::GetDirectoryEntryVa(ULONG Index) {
	return ImageBase + GetDirectoryEntryRva(Index);
}

ULONG_PTR PEHelper::GetDirectoryEntryRva(ULONG Index) {
	return Is64Mod ?
		NtHeader64->OptionalHeader.DataDirectory[Index].VirtualAddress :
		NtHeader32->OptionalHeader.DataDirectory[Index].VirtualAddress;
}

PIMAGE_BASE_RELOCATION PEHelper::GetNextRelocBlock(PIMAGE_BASE_RELOCATION RelocBlock) {
	return (PIMAGE_BASE_RELOCATION)((ULONG_PTR)RelocBlock + RelocBlock->SizeOfBlock);
}

PWORD PEHelper::GetRelocBlockEntryBase(PIMAGE_BASE_RELOCATION RelocBlock) {
	return (PWORD)((ULONG_PTR)RelocBlock + sizeof(IMAGE_BASE_RELOCATION));
}

ULONG PEHelper::GetRelocBlockEntryCount(PIMAGE_BASE_RELOCATION RelocBlock) {
	return (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
}

ULONG_PTR PEHelper::GetRelocPointer(PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index) {
	return ImageBase +
		RelocBlock->VirtualAddress +
		(GetRelocBlockEntryBase(RelocBlock)[Index] & 0xFFF);
}

ULONG_PTR PEHelper::GetImportOriginalThunk(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor) {
	return ImageBase + ImportDescriptor->OriginalFirstThunk;
}

ULONG_PTR PEHelper::GetImportThunk(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor) {
	return ImageBase + ImportDescriptor->FirstThunk;
}

LPCSTR PEHelper::GetImportModuleName(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor) {
	return (LPCSTR)(ImageBase + ImportDescriptor->Name);
}

LPCSTR PEHelper::GetImportFuncName(ULONG_PTR ImportThunk) {
	return Is64Mod ?
		((PIMAGE_IMPORT_BY_NAME)(ImageBase + ((PIMAGE_THUNK_DATA64)ImportThunk)->u1.AddressOfData))->Name :
		((PIMAGE_IMPORT_BY_NAME)(ImageBase + ((PIMAGE_THUNK_DATA32)ImportThunk)->u1.AddressOfData))->Name;
}