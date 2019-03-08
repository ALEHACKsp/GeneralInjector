#include <Windows.h>
#include <iostream>
#include "PEHelper.h"

using std::cout;
using std::endl;

int main() {
	/*PVOID ntdllBase = LoadLibraryA( "NTDLL.DLL" );
	if ( !ntdllBase )	cout << "Load ntdll.dll failed. " << endl;*/
	PVOID k32Base = LoadLibraryA( "Kernel32.dll" );
	if ( !k32Base )	cout << "Load kernel32.dll failed. " << endl;
	PEHelper test( k32Base );
	cout << "RelocBase: " << test.GetRelocBase() << endl
		<< "ImportBase: " << test.GetImportBase() << endl
		<< "ExportBase: " << test.GetExportBase() << endl;
	//test.PrintExport();
	//test.PrintImport();
	cout << "Address of lstrlenW: " << (PVOID)( test.GetExportFuncByName( "lstrlenW" ) ) << endl;
	return 0;
}