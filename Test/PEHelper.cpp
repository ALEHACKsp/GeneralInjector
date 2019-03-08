#include "PEHelper.h"
#include <strsafe.h>
#include <iostream>
using std::cout;
using std::endl;

PEHelper::PEHelper( PVOID imageBase ) {
	ImageBase = (ULONG_PTR)imageBase;
	DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	NtHeader = ImageBase + DosHeader->e_lfanew;
	PIMAGE_NT_HEADERS64 NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader;
	PIMAGE_NT_HEADERS32 NtHeader32 = (PIMAGE_NT_HEADERS32)NtHeader;
	Is64Mod = NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	if ( Is64Mod ) {
		SecHeader = (PIMAGE_SECTION_HEADER)( (ULONG_PTR)NtHeader64 + NtHeader64->OptionalHeader.SizeOfHeaders );
		ImageSize = NtHeader64->OptionalHeader.SizeOfImage;
		DefaultBase = NtHeader64->OptionalHeader.ImageBase;
		EntryPoint = NtHeader64->OptionalHeader.AddressOfEntryPoint != 0 ?
			ImageBase + NtHeader64->OptionalHeader.AddressOfEntryPoint : 0;
	}
	else {
		SecHeader = (PIMAGE_SECTION_HEADER)( (ULONG_PTR)NtHeader32 + NtHeader32->OptionalHeader.SizeOfHeaders );
		ImageSize = NtHeader32->OptionalHeader.SizeOfImage;
		DefaultBase = NtHeader32->OptionalHeader.ImageBase;
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

BOOLEAN PEHelper::IsValidPE() {
	return DosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
		( (PIMAGE_NT_HEADERS64)NtHeader )->Signature == IMAGE_NT_SIGNATURE;
}

ULONG_PTR PEHelper::GetDirectoryEntryVa( ULONG Index ) {
	return GetDirectoryEntryRva( Index ) != 0 ?
		ImageBase + GetDirectoryEntryRva( Index ) : 0;
}

ULONG_PTR PEHelper::GetDirectoryEntryRva( ULONG Index ) {
	return Is64Mod ?
		( (PIMAGE_NT_HEADERS64)NtHeader )->OptionalHeader.DataDirectory[Index].VirtualAddress :
		( (PIMAGE_NT_HEADERS32)NtHeader )->OptionalHeader.DataDirectory[Index].VirtualAddress;
}

PIMAGE_BASE_RELOCATION PEHelper::GetNextRelocBlock( PIMAGE_BASE_RELOCATION RelocBlock ) {
	return (PIMAGE_BASE_RELOCATION)( (ULONG_PTR)RelocBlock + RelocBlock->SizeOfBlock );
}

PWORD PEHelper::GetRelocBlockEntryBase( PIMAGE_BASE_RELOCATION RelocBlock ) {
	return (PWORD)( (ULONG_PTR)RelocBlock + sizeof( IMAGE_BASE_RELOCATION ) );
}

ULONG PEHelper::GetRelocBlockEntryCount( PIMAGE_BASE_RELOCATION RelocBlock ) {
	return ( RelocBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
}

ULONG_PTR PEHelper::GetRelocPointer( PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index ) {
	return ImageBase +
		RelocBlock->VirtualAddress +
		( GetRelocBlockEntryBase( RelocBlock )[Index] & 0xFFF );
}

ULONG_PTR PEHelper::GetImportFirstOriginalThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
	return ImageBase + ImportDescriptor->OriginalFirstThunk;
}

ULONG_PTR PEHelper::GetImportNextOriginalThunk( ULONG_PTR OriginalThunk ) {
	return Is64Mod ?
		OriginalThunk + sizeof( IMAGE_THUNK_DATA64 ) :
		OriginalThunk + sizeof( IMAGE_THUNK_DATA32 );
}

ULONG_PTR PEHelper::GetImportFirstThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
	return ImageBase + ImportDescriptor->FirstThunk;
}

ULONG_PTR PEHelper::GetImportNextThunk( ULONG_PTR Thunk ) {
	return Is64Mod ?
		Thunk + sizeof( IMAGE_THUNK_DATA64 ) :
		Thunk + sizeof( IMAGE_THUNK_DATA32 );
}

LPCSTR PEHelper::GetImportModuleName( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
	return (LPCSTR)( ImageBase + ImportDescriptor->Name );
}

LPCSTR PEHelper::GetImportFuncName( ULONG_PTR OriginalThunk ) {
	return Is64Mod ?
		( (PIMAGE_IMPORT_BY_NAME)( ImageBase + ( (PIMAGE_THUNK_DATA64)OriginalThunk )->u1.AddressOfData ) )->Name :
		( (PIMAGE_IMPORT_BY_NAME)( ImageBase + ( (PIMAGE_THUNK_DATA32)OriginalThunk )->u1.AddressOfData ) )->Name;
}

ULONG_PTR PEHelper::GetExportFuncByIndex( ULONG Index ) {

	if ( Index >= ExportBase->NumberOfFunctions )	return NULL;

	return AddressOfFuncs[AddressOfOrds[Index]] + ImageBase;
}

ULONG_PTR PEHelper::GetExportFuncByName( LPCSTR FuncName ) {
	ULONG_PTR address = 0;
	LPCSTR currentName = NULL;

	for ( ULONG i = 0; i < ExportBase->NumberOfNames; i++ ) {
		currentName = GetExportFuncNameByIndex( i );
		if ( strncmp( FuncName, currentName, MAX_PATH ) == 0 ) {
			address = GetExportFuncByIndex( i );

			// Forward export not supported yet
			// ...

			break;
		}
	}

	return address;
}

LPCSTR PEHelper::GetExportFuncNameByIndex( ULONG Index ) {
	if ( Index >= ExportBase->NumberOfNames ) return NULL;

	return (LPCSTR)( ImageBase + AddressOfNames[Index] );
}

VOID PEHelper::PrintExport() {
	if ( !ExportBase )	cout << "No export section!" << endl;

	for ( ULONG i = 0; i < ExportBase->NumberOfNames; i++ ) {
		cout << AddressOfOrds[i] << " : " << GetExportFuncNameByIndex( i ) << endl;
	}
}

VOID PEHelper::PrintImport() {   
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