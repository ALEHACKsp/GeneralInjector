#pragma once

#include <Windows.h>

//
// Helper class for PE file access, currently only support image mapping (not file mapping)
//
class PEHelper {
private:
	ULONG_PTR ImageBase;
	PIMAGE_DOS_HEADER DosHeader;
	ULONG_PTR NtHeader;
	PIMAGE_SECTION_HEADER SecHeader;
	ULONG_PTR EntryPoint;
	ULONG_PTR DefaultBase;
	ULONG_PTR RelocBase;
	ULONG_PTR ImportBase;
	PIMAGE_EXPORT_DIRECTORY ExportBase;
	PUSHORT AddressOfOrds;
	PULONG AddressOfNames;
	PULONG AddressOfFuncs;
	ULONG_PTR ImageSize;
	LONG_PTR RelocDelta;
	BOOLEAN Is64Mod;
public:
	PEHelper(PVOID imageBase);
	BOOLEAN inline IsValidPE();
	ULONG_PTR inline GetDirectoryEntryVa(ULONG Index);
	ULONG_PTR inline GetDirectoryEntryRva(ULONG Index);
	ULONG_PTR GetEntryPoint() { return EntryPoint; }
	ULONG_PTR GetRelocBase() { return RelocBase; }
	ULONG_PTR GetImportBase() { return ImportBase; }
	PIMAGE_EXPORT_DIRECTORY GetExportBase() { return ExportBase; }
	ULONG_PTR GetImageBase() { return ImageBase; }
	ULONG_PTR GetImageSize() { return ImageSize; }

	// Relocation
	PIMAGE_BASE_RELOCATION inline GetNextRelocBlock(PIMAGE_BASE_RELOCATION RelocBlock);
	ULONG inline GetRelocBlockEntryCount(PIMAGE_BASE_RELOCATION RelocBlock);
	PWORD inline GetRelocBlockEntryBase(PIMAGE_BASE_RELOCATION RelocBlock);
	ULONG_PTR inline GetRelocPointer(PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index);

	// Import
	ULONG_PTR inline GetImportFirstOriginalThunk(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
	ULONG_PTR inline GetImportNextOriginalThunk( ULONG_PTR OriginalThunk);
	ULONG_PTR inline GetImportFirstThunk(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
	ULONG_PTR inline GetImportNextThunk( ULONG_PTR Thunk);
	LPCSTR inline  GetImportModuleName(PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor);
	LPCSTR inline GetImportFuncName(ULONG_PTR OriginalThunk );

	// Export
	ULONG_PTR  inline GetExportFuncByIndex( ULONG Index );
	ULONG_PTR  GetExportFuncByName( LPCSTR FuncName );
	LPCSTR  inline GetExportFuncNameByIndex( ULONG Index );
	VOID PrintExport();
	VOID PrintImport();


};