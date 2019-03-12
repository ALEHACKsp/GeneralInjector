#include "TestPEHelper.h"
#include <strsafe.h>
#include <iostream>
using std::cout;
using std::endl;

BOOLEAN PEHelper::Analyze( BOOLEAN Force ) {
	BOOLEAN isOk = TRUE;
	__try {
		DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
		NtHeader = ImageBase + DosHeader->e_lfanew;
		PIMAGE_NT_HEADERS64 NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader;
		PIMAGE_NT_HEADERS32 NtHeader32 = (PIMAGE_NT_HEADERS32)NtHeader;
		if ( !IsValidPE() && !Force ) {
			isOk = FALSE;
			__leave;
		}

		Is64Mod = NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		if ( Is64Mod ) {
			SectionHeader = (PIMAGE_SECTION_HEADER)( (ULONG_PTR)NtHeader64 + sizeof( IMAGE_NT_HEADERS64 ) );
			SectionCount = NtHeader64->FileHeader.NumberOfSections;
			ImageSize = NtHeader64->OptionalHeader.SizeOfImage;
			DefaultBase = NtHeader64->OptionalHeader.ImageBase;

		}
		else {
			SectionHeader = (PIMAGE_SECTION_HEADER)( (ULONG_PTR)NtHeader32 + sizeof( IMAGE_NT_HEADERS32 ) );
			SectionCount = NtHeader32->FileHeader.NumberOfSections;
			ImageSize = NtHeader32->OptionalHeader.SizeOfImage;
			DefaultBase = NtHeader32->OptionalHeader.ImageBase;
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER ) {
		isOk = FALSE;
	}

	return isOk;
}

ULONG_PTR PEHelper::GetExportFuncByName( LPCSTR FuncName ) {
	ULONG_PTR address = 0;
	LPCSTR currentName = NULL;

	__try {
		for ( ULONG i = 0; i < ExportBase->NumberOfNames; i++ ) {
			currentName = GetExportFuncNameByIndex( i );
			if ( strncmp( FuncName, currentName, MAX_PATH ) == 0 ) {
				address = GetExportFuncByIndex( i );

				// Forward export not supported yet
				// ...

				break;
			}
		}
	}
	__except ( EXCEPTION_EXECUTE_HANDLER ) {
		address = 0;
	}

	return address;
}

//
// PEMapHelper class definition
//
BOOLEAN PEMapHelper::Analyze( BOOLEAN Force ) {
	if ( !PEHelper::Analyze( Force ) )	return FALSE;

	BOOLEAN isOk = TRUE;
	__try {
		PIMAGE_NT_HEADERS64 NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader;
		PIMAGE_NT_HEADERS32 NtHeader32 = (PIMAGE_NT_HEADERS32)NtHeader;
		if ( Is64Mod ) {
			EntryPoint = NtHeader64->OptionalHeader.AddressOfEntryPoint != 0 ?
				ImageBase + NtHeader64->OptionalHeader.AddressOfEntryPoint : 0;
		}
		else {
			EntryPoint = ImageBase + NtHeader32->OptionalHeader.AddressOfEntryPoint;
		}

		RelocBase = GetDirectoryEntryVa( IMAGE_DIRECTORY_ENTRY_BASERELOC );
		ImportBase = GetDirectoryEntryVa( IMAGE_DIRECTORY_ENTRY_IMPORT );
		ExportBase = (PIMAGE_EXPORT_DIRECTORY)GetDirectoryEntryVa( IMAGE_DIRECTORY_ENTRY_EXPORT );
		AddressOfOrds = (PUSHORT)( ImageBase + ExportBase->AddressOfNameOrdinals );
		AddressOfNames = (PULONG)( ImageBase + ExportBase->AddressOfNames );
		AddressOfFuncs = (PULONG)( ImageBase + ExportBase->AddressOfFunctions );
		RelocDelta = ImageBase - DefaultBase;
	}
	__except ( EXCEPTION_EXECUTE_HANDLER ) {
		isOk = FALSE;
	}

	return isOk;
}

VOID PEMapHelper::PrintExport() {
	if ( !ExportBase )	cout << "No export section!" << endl;

	for ( ULONG i = 0; i < ExportBase->NumberOfNames; i++ ) {
		cout << AddressOfOrds[i] << " : " << GetExportFuncNameByIndex( i ) << endl;
	}
}

VOID PEMapHelper::PrintImport() {   
	if ( !ImportBase ) cout << "No import section!" << endl;

	PIMAGE_IMPORT_DESCRIPTOR currentID = (PIMAGE_IMPORT_DESCRIPTOR)ImportBase;

	while ( currentID->Characteristics ) {
		cout << GetImportModuleName( currentID ) << ":" << endl;

		ULONG_PTR ft = GetImportFirstThunk( currentID );
		ULONG_PTR oft = GetImportFirstOriginalThunk( currentID );

		while ( ( (PIMAGE_THUNK_DATA32)oft )->u1.AddressOfData )
		{
			cout << "\t" << GetImportFuncName( oft ) << endl;

			ft = GetImportNextThunk( ft );
			oft = GetImportNextOriginalThunk( oft );

		}
		currentID++;

		cout << endl;
	}

}