#include <Windows.h>
#include <iostream>
#include "TestPEHelper.h"

using std::cout;
using std::endl;

int main() {
	/*PVOID ntdllBase = LoadLibraryA( "NTDLL.DLL" );
	if ( !ntdllBase )	cout << "Load ntdll.dll failed. " << endl;*/
	//PVOID k32Base = LoadLibraryA( "Kernel32.dll" );
	//if ( !k32Base )	cout << "Load kernel32.dll failed. " << endl;
	//PEMapHelper test( k32Base );
	//test.Analyze( FALSE );
	//cout << "RelocBase: " << test.GetRelocBase() << endl
	//	<< "ImportBase: " << test.GetImportBase() << endl
	//	<< "ExportBase: " << test.GetExportBase() << endl;
	////test.PrintExport();
	//test.PrintImport();
	//cout << "Address of lstrlenW: " << (PVOID)( test.GetExportFuncByName( "lstrlenW" ) ) << endl;

	PVOID hK32 = CreateFileA("C:\\windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hK32) {
		cout << "Cannot open kerner32.dll" << endl;
		return 1;
	}

	ULONG fileSize;
	ULONG bytesRead;
	fileSize = GetFileSize(hK32, NULL);

	PVOID k32FileBase = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, fileSize + 1);
	SetFilePointer(hK32, 0, NULL, FILE_BEGIN);

	ReadFile(hK32, (PUCHAR)k32FileBase, fileSize, &bytesRead, NULL);

	PEFileHelper test(k32FileBase);
	test.GetExportFuncByName("lstrlenW");
	return 0;
}