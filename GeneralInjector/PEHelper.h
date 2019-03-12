#pragma once

#include "stdafx.h"

//
// Helper class for PE file access, currently only support image mapping (not file mapping)
//

class PEHelper {
protected:
	ULONG_PTR ImageBase;
	ULONG_PTR DefaultBase;
	PIMAGE_DOS_HEADER DosHeader;
	ULONG_PTR NtHeader;
	PIMAGE_SECTION_HEADER SectionHeader;
	ULONG_PTR EntryPoint;
	ULONG_PTR RelocBase;
	ULONG_PTR ImportBase;
	PIMAGE_EXPORT_DIRECTORY ExportBase;
	PUSHORT AddressOfOrds;
	PULONG AddressOfNames;
	PULONG AddressOfFuncs;
	ULONG_PTR ImageSize;
	ULONG SectionCount;
	BOOLEAN Is64Mod;
public:
	PEHelper( PVOID imageBase ) { 
		ImageBase = (ULONG_PTR)imageBase; 
		Analyze(FALSE);
	}
	// Analyze
	BOOLEAN Analyze( BOOLEAN Force );
	BOOLEAN  IsValidPE() {
		__try {
			return DosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
				( (PIMAGE_NT_HEADERS64)NtHeader )->Signature == IMAGE_NT_SIGNATURE;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return FALSE;
		}
	}

	// Header information
	virtual ULONG_PTR  GetDirectoryEntryVa( ULONG Index ) = 0;
	ULONG_PTR  GetDirectoryEntryRva( ULONG Index ) {
		__try {
			return Is64Mod ?
				( (PIMAGE_NT_HEADERS64)NtHeader )->OptionalHeader.DataDirectory[Index].VirtualAddress :
				( (PIMAGE_NT_HEADERS32)NtHeader )->OptionalHeader.DataDirectory[Index].VirtualAddress;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	ULONG_PTR GetNtHeader() { return NtHeader; }
	PIMAGE_SECTION_HEADER GetSectionHeader() { return SectionHeader; }
	ULONG_PTR GetEntryPoint() { return EntryPoint; }
	ULONG_PTR GetRelocBase() { return RelocBase; }
	ULONG_PTR GetImportBase() { return ImportBase; }
	PIMAGE_EXPORT_DIRECTORY GetExportBase() { return ExportBase; }
	ULONG_PTR GetImageBase() { return ImageBase; }
	ULONG_PTR GetImageSize() { return ImageSize; }
	BOOLEAN IsImage64() { return Is64Mod; }

	ULONG_PTR GetSectionDeltaByIndex( ULONG Index ) {
		return ( SectionHeader[Index] ).VirtualAddress - ( SectionHeader[Index].PointerToRawData );
	}
	ULONG_PTR GetSectionDeltaByRva( ULONG_PTR Rva ) { return GetSectionDeltaByIndex( GetSectionIndexByRva( Rva ) ); }
	LONG GetSectionIndexByRva( ULONG_PTR Rva ) {
		ULONG i = 0;
		for ( ; i < SectionCount; i++ ) {
			if ( Rva >= SectionHeader[i].VirtualAddress &&
				Rva <= SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) {
				break;
			}
		}

		return i < SectionCount ? i : -1;
	}
	LONG GetSectionIndexByVa( ULONG_PTR Va ) {
		return GetSectionIndexByRva( Va - ImageBase );
	}

	// Relocation
	PIMAGE_BASE_RELOCATION GetNextRelocBlock( PIMAGE_BASE_RELOCATION RelocBlock ) {
		__try {
			return (PIMAGE_BASE_RELOCATION)( (ULONG_PTR)RelocBlock + RelocBlock->SizeOfBlock );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return NULL;
		}
	}
	ULONG  GetRelocBlockEntryCount( PIMAGE_BASE_RELOCATION RelocBlock ) {
		__try {
			return ( RelocBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
	PWORD GetRelocBlockEntryBase( PIMAGE_BASE_RELOCATION RelocBlock ) {
		__try {
			return (PWORD)( (ULONG_PTR)RelocBlock + sizeof( IMAGE_BASE_RELOCATION ) );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return NULL;
		}
	}
	virtual ULONG_PTR  GetRelocPointer( PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index ) = 0;

	// Import
	virtual ULONG_PTR  GetImportFirstOriginalThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) = 0;
	ULONG_PTR  GetImportNextOriginalThunk( ULONG_PTR OriginalThunk ) {
		__try {
			return Is64Mod ?
				OriginalThunk + sizeof( IMAGE_THUNK_DATA64 ) :
				OriginalThunk + sizeof( IMAGE_THUNK_DATA32 );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	virtual ULONG_PTR  GetImportFirstThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) = 0;
	ULONG_PTR  GetImportNextThunk( ULONG_PTR Thunk ) {
		__try {
			return Is64Mod ?
				Thunk + sizeof( IMAGE_THUNK_DATA64 ) :
				Thunk + sizeof( IMAGE_THUNK_DATA32 );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	virtual LPCSTR   GetImportModuleName( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) = 0;
	virtual LPCSTR  GetImportFuncName( ULONG_PTR ImportThunk ) = 0;

	// Export
	virtual ULONG_PTR   GetExportFuncByIndex( ULONG Index ) = 0;
	virtual LPCSTR   GetExportFuncNameByIndex( ULONG Index ) = 0;
	ULONG_PTR GetExportFuncByName( LPCSTR FuncName );

	//VOID PrintExport();
	//VOID PrintImport();


};

class PEMapHelper : public PEHelper {
private:
	LONG_PTR RelocDelta;

public:
	PEMapHelper( PVOID imageBase ) :PEHelper( imageBase ) {}
	// Analyze
	virtual BOOLEAN Analyze( BOOLEAN Force );

	// Get information
	virtual ULONG_PTR  GetDirectoryEntryVa( ULONG Index ) {
		return GetDirectoryEntryRva( Index ) != 0 ?
			ImageBase + GetDirectoryEntryRva( Index ) : 0;
	}

	// Relocation
	virtual ULONG_PTR  GetRelocPointer( PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index ) {
		__try {
			return ImageBase +
				RelocBlock->VirtualAddress +
				( GetRelocBlockEntryBase( RelocBlock )[Index] & 0xFFF );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	// Import
	virtual ULONG_PTR  GetImportFirstOriginalThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
		__try {
			return ImageBase + ImportDescriptor->OriginalFirstThunk;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
	virtual ULONG_PTR  GetImportFirstThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
		__try {
			return ImageBase + ImportDescriptor->FirstThunk;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	virtual LPCSTR   GetImportModuleName( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
		__try {
			return (LPCSTR)( ImageBase + ImportDescriptor->Name );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return NULL;
		}
	}
	virtual LPCSTR  GetImportFuncName( ULONG_PTR ImportThunk ) {
		__try {
			return Is64Mod ?
				( (PIMAGE_IMPORT_BY_NAME)( ImageBase + ( (PIMAGE_THUNK_DATA64)ImportThunk )->u1.AddressOfData ) )->Name :
				( (PIMAGE_IMPORT_BY_NAME)( ImageBase + ( (PIMAGE_THUNK_DATA32)ImportThunk )->u1.AddressOfData ) )->Name;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return NULL;
		}
	}

	// Export
	virtual ULONG_PTR   GetExportFuncByIndex( ULONG Index ) {
		__try {
			if ( Index >= ExportBase->NumberOfFunctions )	return NULL;

			return AddressOfFuncs[AddressOfOrds[Index]] + ImageBase;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
	virtual LPCSTR   GetExportFuncNameByIndex( ULONG Index ) {
		__try {
			if ( Index >= ExportBase->NumberOfNames ) return NULL;

			return (LPCSTR)( ImageBase + AddressOfNames[Index] );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	//VOID PrintExport();
	//VOID PrintImport();


};

class PEFileHelper : public PEHelper {
private:
	PEFileHelper( PVOID imageBase ) : PEHelper( imageBase ) {}

	virtual BOOLEAN Analyze( BOOLEAN Force );
	ULONG_PTR GetFileOffsetByRva( ULONG_PTR Rva ) {
		return Rva - GetSectionDeltaByRva( Rva );
	}

	// Header information
	virtual ULONG_PTR GetDirectoryEntryVa( ULONG Index ) {
		ULONG_PTR rva = GetDirectoryEntryRva( Index );
		return rva != 0 ?
			ImageBase + GetFileOffsetByRva( rva ) :
			0;
	}

	// Relocation
	virtual ULONG_PTR GetRelocPointer( PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index ) {
		__try {
			ULONG_PTR rva = RelocBlock->VirtualAddress +
				( GetRelocBlockEntryBase( RelocBlock )[Index] & 0xFFF );
			return ImageBase + GetFileOffsetByRva( rva );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}

	// Import 
	virtual ULONG_PTR GetImportFirstOriginalThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
		__try {
			return ImageBase + GetFileOffsetByRva( ImportDescriptor->OriginalFirstThunk );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
	virtual ULONG_PTR GetImportFirstThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
		__try {
			return ImageBase + GetFileOffsetByRva( ImportDescriptor->FirstThunk );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
	virtual LPCSTR   GetImportModuleName( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
		__try {
			return (LPCSTR)( ImageBase + GetFileOffsetByRva( ImportDescriptor->Name ) );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return NULL;
		}
	}
	virtual LPCSTR  GetImportFuncName( ULONG_PTR ImportThunk ) {
		__try {
			return Is64Mod ?
				( (PIMAGE_IMPORT_BY_NAME)( ImageBase + GetFileOffsetByRva( ( (PIMAGE_THUNK_DATA64)ImportThunk )->u1.AddressOfData ) ) )->Name :
				( (PIMAGE_IMPORT_BY_NAME)( ImageBase + GetFileOffsetByRva( ( (PIMAGE_THUNK_DATA32)ImportThunk )->u1.AddressOfData ) ) )->Name;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return NULL;
		}
	}

	// Export
	virtual ULONG_PTR   GetExportFuncByIndex( ULONG Index ) {
		__try {
			if ( Index >= ExportBase->NumberOfFunctions )	return NULL;

			return GetFileOffsetByRva( AddressOfFuncs[AddressOfOrds[Index]] ) + ImageBase;
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
	virtual LPCSTR   GetExportFuncNameByIndex( ULONG Index ) {
		__try {
			if ( Index >= ExportBase->NumberOfNames ) return NULL;

			return (LPCSTR)( ImageBase + GetFileOffsetByRva( AddressOfNames[Index] ) );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return 0;
		}
	}
};

//class PEMapHelper {
//private:
//	ULONG_PTR ImageBase;
//	PIMAGE_DOS_HEADER DosHeader;
//	ULONG_PTR NtHeader;
//	PIMAGE_SECTION_HEADER SectionHeader;
//	ULONG_PTR EntryPoint;
//	ULONG_PTR DefaultBase;
//	ULONG_PTR RelocBase;
//	ULONG_PTR ImportBase;
//	PIMAGE_EXPORT_DIRECTORY ExportBase;
//	PUSHORT AddressOfOrds;
//	PULONG AddressOfNames;
//	PULONG AddressOfFuncs;
//	ULONG_PTR ImageSize;
//	LONG_PTR RelocDelta;
//	ULONG SectionCount;
//	BOOLEAN Is64Mod;
//public:
//	PEMapHelper( PVOID imageBase );
//	// Analyze
//	BOOLEAN Analyze( BOOLEAN Force );
//	BOOLEAN  IsValidPE() {
//		__try {
//			return DosHeader->e_magic == IMAGE_DOS_SIGNATURE &&
//				( (PIMAGE_NT_HEADERS64)NtHeader )->Signature == IMAGE_NT_SIGNATURE;
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return FALSE;
//		}
//	}
//
//	// Get information
//	ULONG_PTR  GetDirectoryEntryVa( ULONG Index ) {
//		return GetDirectoryEntryRva( Index ) != 0 ?
//			ImageBase + GetDirectoryEntryRva( Index ) : 0;
//	}
//	ULONG_PTR  GetDirectoryEntryRva( ULONG Index ) {
//		__try {
//			return Is64Mod ?
//				( (PIMAGE_NT_HEADERS64)NtHeader )->OptionalHeader.DataDirectory[Index].VirtualAddress :
//				( (PIMAGE_NT_HEADERS32)NtHeader )->OptionalHeader.DataDirectory[Index].VirtualAddress;
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	ULONG_PTR GetNtHeader() { return NtHeader; }
//	PIMAGE_SECTION_HEADER GetSectionHeader() { return SectionHeader; }
//	ULONG_PTR GetEntryPoint() { return EntryPoint; }
//	ULONG_PTR GetRelocBase() { return RelocBase; }
//	ULONG_PTR GetImportBase() { return ImportBase; }
//	PIMAGE_EXPORT_DIRECTORY GetExportBase() { return ExportBase; }
//	ULONG_PTR GetImageBase() { return ImageBase; }
//	ULONG_PTR GetImageSize() { return ImageSize; }
//
//	// Section
//	ULONG_PTR GetSectionDeltaByIndex( ULONG Index ) {
//		return ( SectionHeader[Index] ).VirtualAddress - ( SectionHeader[Index].PointerToRawData );
//	}
//	LONG GetSectionIndexByRva( ULONG_PTR Rva ) {
//		int i = 0;
//		for ( ; i < SectionCount; i++ ) {
//			if ( Rva >= SectionHeader[i].VirtualAddress &&
//				Rva <= SectionHeader[i].VirtualAddress + SectionHeader[i].SizeOfRawData ) {
//				break;
//			}
//		}
//
//		return i < SectionCount ? i : -1;
//	}
//	LONG GetSectionIndexByVa( ULONG_PTR Va ) {
//		return GetSectionIndexByRva( Va - ImageBase );
//	}
//
//	// Relocation
//	PIMAGE_BASE_RELOCATION GetNextRelocBlock( PIMAGE_BASE_RELOCATION RelocBlock ) {
//		__try {
//			return (PIMAGE_BASE_RELOCATION)( (ULONG_PTR)RelocBlock + RelocBlock->SizeOfBlock );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return NULL;
//		}
//	}
//	ULONG  GetRelocBlockEntryCount( PIMAGE_BASE_RELOCATION RelocBlock ) {
//		__try {
//			return ( RelocBlock->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	PWORD GetRelocBlockEntryBase( PIMAGE_BASE_RELOCATION RelocBlock ) {
//		__try {
//			return (PWORD)( (ULONG_PTR)RelocBlock + sizeof( IMAGE_BASE_RELOCATION ) );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return NULL;
//		}
//	}
//	ULONG_PTR  GetRelocPointer( PIMAGE_BASE_RELOCATION RelocBlock, ULONG Index ) {
//		__try {
//			return ImageBase +
//				RelocBlock->VirtualAddress +
//				( GetRelocBlockEntryBase( RelocBlock )[Index] & 0xFFF );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//
//	// Import
//	ULONG_PTR  GetImportFirstOriginalThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
//		__try {
//			return ImageBase + ImportDescriptor->OriginalFirstThunk;
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	ULONG_PTR  GetImportNextOriginalThunk( ULONG_PTR OriginalThunk ) {
//		__try {
//			return Is64Mod ?
//				OriginalThunk + sizeof( IMAGE_THUNK_DATA64 ) :
//				OriginalThunk + sizeof( IMAGE_THUNK_DATA32 );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//
//	ULONG_PTR  GetImportFirstThunk( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
//		__try {
//			return ImageBase + ImportDescriptor->FirstThunk;
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	ULONG_PTR  GetImportNextThunk( ULONG_PTR Thunk ) {
//		__try {
//			return Is64Mod ?
//				Thunk + sizeof( IMAGE_THUNK_DATA64 ) :
//				Thunk + sizeof( IMAGE_THUNK_DATA32 );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	LPCSTR   GetImportModuleName( PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor ) {
//		__try {
//			return (LPCSTR)( ImageBase + ImportDescriptor->Name );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return NULL;
//		}
//	}
//	LPCSTR  GetImportFuncName( ULONG_PTR ImportThunk ) {
//		__try {
//			return Is64Mod ?
//				( (PIMAGE_IMPORT_BY_NAME)( ImageBase + ( (PIMAGE_THUNK_DATA64)ImportThunk )->u1.AddressOfData ) )->Name :
//				( (PIMAGE_IMPORT_BY_NAME)( ImageBase + ( (PIMAGE_THUNK_DATA32)ImportThunk )->u1.AddressOfData ) )->Name;
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return NULL;
//		}
//	}
//
//	// Export
//	ULONG_PTR   GetExportFuncByIndex( ULONG Index ) {
//		__try {
//			if ( Index >= ExportBase->NumberOfFunctions )	return NULL;
//
//			return AddressOfFuncs[AddressOfOrds[Index]] + ImageBase;
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	LPCSTR   GetExportFuncNameByIndex( ULONG Index ) {
//		__try {
//			if ( Index >= ExportBase->NumberOfNames ) return NULL;
//
//			return (LPCSTR)( ImageBase + AddressOfNames[Index] );
//		}
//		__except ( EXCEPTION_EXECUTE_HANDLER ) {
//			return 0;
//		}
//	}
//	ULONG_PTR GetExportFuncByName( LPCSTR FuncName );
//
//	//VOID PrintExport();
//	//VOID PrintImport();
//
//
//};

//VOID PEMapHelper::PrintExport() {
//	if ( !ExportBase )	cout << "No export section!" << endl;
//
//	for ( ULONG i = 0; i < ExportBase->NumberOfNames; i++ ) {
//		cout << AddressOfOrds[i] << " : " << GetExportFuncNameByIndex( i ) << endl;
//	}
//}
//
//VOID PEMapHelper::PrintImport() {
//	if ( !ImportBase ) cout << "No import section!" << endl;
//
//	PIMAGE_IMPORT_DESCRIPTOR currentID = (PIMAGE_IMPORT_DESCRIPTOR)ImportBase;
//
//	while ( currentID->Characteristics ) {
//		cout << GetImportModuleName( currentID ) << ":" << endl;
//
//		ULONG_PTR ft = GetImportFirstThunk( currentID );
//		ULONG_PTR oft = GetImportFirstOriginalThunk( currentID );
//
//		while ( ( (PIMAGE_THUNK_DATA32)oft )->u1.AddressOfData )
//		{
//			cout << "\t" << GetImportFuncName( oft ) << endl;
//
//			ft = GetImportNextThunk( ft );
//			oft = GetImportNextOriginalThunk( oft );
//
//		}
//		currentID++;
//
//		cout << endl;
//	}
//
//}