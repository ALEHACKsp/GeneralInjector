#pragma once

#include "stdafx.h"

#define GetModuleFuncAddress(ModuleName, FuncName)	(LPVOID)(GetProcAddress(LoadLibrary(_T(ModuleName)), FuncName))

#define INVALID_HANDLE(handle)	(handle == INVALID_HANDLE_VALUE)
#define OffsetToVA(address, offset)	((ULONG_PTR)(address) + (offset))

#define DEREF( name )		*(PULONG_PTR)(name)
#define DEREF_64( name )	*(PDWORD64)(name)
#define DEREF_32( name )	*(PDWORD)(name)
#define DEREF_16( name )	*(PWORD )(name)
#define DEREF_8( name )		*(PBYTE)(name)

// PE Field Macros
#define DOS_HEADER(pImageBase)	((PIMAGE_DOS_HEADER)pImageBase)
#define NT_HEADERS(pImageBase)	((PIMAGE_NT_HEADERS)(OffsetToVA(pImageBase, DOS_HEADER(pImageBase)->e_lfanew)))
#define SEC_HEADER(pImageBase)	((PIMAGE_SECTION_HEADER)(OffsetToVA(NT_HEADERS(pImageBase), sizeof(IMAGE_NT_HEADERS))))
#define IMAGE_SIZE(pImageBase)	(NT_HEADERS(pImageBase)->OptionalHeader.SizeOfImage)
#define IMAGE_BASE(pImageBase)	(NT_HEADERS(pImageBase)->OptionalHeader.ImageBase)
#define IMAGE_ENTRYPOINT(pImageBase)	((PVOID)(OffsetToVA(pImageBase, NT_HEADERS(pImageBase)->OptionalHeader.AddressOfEntryPoint )))

#define	RVA_DATA_DIRECTORY(pImageBase, Index)	((NT_HEADERS(pImageBase)->OptionalHeader.DataDirectory[Index].VirtualAddress))
#define VA_DATA_DIRECTORY(pImageBase, Index)	((PVOID)(OffsetToVA(pImageBase, RVA_DATA_DIRECTORY(pImageBase, Index))))
#define REMOTE_DATA_DIRECTORY(pRemote, pImageBase, Index)	((PVOID)(OffsetToVA(pRemote, RVA_DATA_DIRECTORY(pImageBase, Index))))

#define RELOC_BLOCKS_COUNT(pBR)	(( (pBR)->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD ))
#define RELOC_BLOCKS(pBR)	(PWORD(OffsetToVA(pBR, sizeof(IMAGE_BASE_RELOCATION))))
#define	RELOC_DELTA(pImageBase)	((ULONG_PTR)pImageBase - IMAGE_BASE(pImageBase))
#define RELOC_POINTER(pImageBase, pBR, BlockIndex)	((PULONG_PTR)(OffsetToVA(pImageBase, (pBR)->VirtualAddress + (RELOC_BLOCKS(pBR)[BlockIndex] & 0xFFF ))))
#define RELOC_NEXT_BASERELOC(pBR)	((PIMAGE_BASE_RELOCATION)OffsetToVA(pBR, (pBR)->SizeOfBlock))

#define IMPORT_OFT(pImageBase, pID)	((PIMAGE_THUNK_DATA)(OffsetToVA(pImageBase, (pID)->OriginalFirstThunk)))
#define IMPORT_FT(pImageBase, pID)	((PIMAGE_THUNK_DATA)(OffsetToVA(pImageBase, (pID)->FirstThunk)))
#define IMPORT_NAME(pImageBase, pID)	((LPCSTR)(OffsetToVA(pImageBase, (pID)->Name)))
#define IMPORT_FUNC_ORDINAL(pID)		((pID)->u1.Ordinal)
#define IMPORT_FUNC_NAME(pImageBase, pOFT)	((LPCSTR)((PIMAGE_IMPORT_BY_NAME)OffsetToVA(pImageBase, (pOFT)->u1.AddressOfData))->Name)
#define IMPORT_NEXT_THUNK(pThunk)	((PIMAGE_THUNK_DATA)(OffsetToVA(pThunk, sizeof(IMAGE_THUNK_DATA))))
#define IMPORT_NEXT_DESCRIPTOR(pID)	((PIMAGE_IMPORT_DESCRIPTOR)(OffsetToVA(pID, sizeof(IMAGE_IMPORT_DESCRIPTOR))))


typedef struct _GUI_INFO
{
	HWND	hWindow;
	DWORD	ThreadId;
	DWORD	ProcessId;
}GUI_INFO, *PGUI_INFO;

class Helper
{
public:
	static BOOLEAN GetProcessFullpath(DWORD Pid, CString& ImagePath);
	static BOOLEAN GetProcessFullpath(DWORD Pid, LPTSTR ImagePath);
	static BOOLEAN GetProcessFilename(DWORD Pid, LPTSTR Filename);
	static BOOLEAN GetProcessFilename(DWORD Pid, CString& Filename);
	static BOOLEAN IsProcessWow64(DWORD Pid, PBOOL IsWow64);
	static BOOLEAN FileExists(LPCTSTR szPath);
	static DWORD GetMainThreadId(DWORD dwOwnerPID);
	static void ErrorPop(LPCTSTR ErrorMsg);
	static BOOLEAN GetProcessGUIThreadInfo(PGUI_INFO pGUIInfo);
	static DWORD GetProcessGUIThreadInfo(DWORD Pid, HWND* FoundWnd);
#ifndef _AMD64_
	static BOOLEAN IsWow64Emulator();
#endif
};