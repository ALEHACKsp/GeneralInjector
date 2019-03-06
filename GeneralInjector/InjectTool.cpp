#include "stdafx.h"

#include <imm.h>
#include <strsafe.h>
#include "InjectTool.h"
#include "Helper.h"

#ifdef _UNICODE
#define LOAD_LIBRARY	"LoadLibraryW"
#else
#define LOAD_LIBRARY	"LoadLibraryA"
#endif

BOOLEAN InjectTool::Inject()
{
	if (!m_TargetPid ||
		m_TargetDll.IsEmpty() ||
		!Helper::FileExists(m_TargetDll))
	{
		Helper::ErrorPop(_T("Inject info is invalid"));
		return FALSE;
	}

	BOOLEAN ret;
	switch (m_InjectType)
	{
	case INJECT_CREATE_REMOTE_THREAD:
		ret = InjectCreateRemoteThread();
		break;
	case INJECT_THREAD_HIJACK:
		ret = InjectThreadHijack();
		break;
	case INJECT_QUEUE_USER_APC:
		ret = InjectQueueUserApc();
		break;
	case INJECT_SET_WINDOW_HOOK:
		ret = InjectSetWndHook();
		break;
	case INJECT_IME:
		ret = InjectIME();
		break;
	case INJECT_MANUAL:
		ret = InjectManual();
	default:
		return FALSE;

	}

	return ret;
}

BOOLEAN InjectTool::InjectCreateRemoteThread()
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID llAddr = NULL;
	LPVOID remotePath = NULL;

	LPCTSTR dllBuffer = m_TargetDll.GetBuffer();
	DWORD dllBufferSize = (m_TargetDll.GetLength() + 1) * sizeof(TCHAR);
	SIZE_T bytesRet;
	DWORD exitCode = 0;
	DWORD error = ERROR_INJECT_SUCCESS;

	__try {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid);
		if (!hProcess)	ERROR_LEAVE(error, ERROR_OPEN_PROCESS);

		// Get address of the function LoadLibraryA 
		llAddr = (LPVOID)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), LOAD_LIBRARY);
		if (!llAddr)	ERROR_LEAVE(error, ERROR_GET_PROC_ADDRESS);

		// Allocate new memory region inside the injected process's memory space
		// remotePath is the start address of the allocated memory
		remotePath = VirtualAllocEx(hProcess, NULL, dllBufferSize, MEM_COMMIT, PAGE_READWRITE);
		if (!remotePath)	ERROR_LEAVE(error, ERROR_ALLOC_REMOTE_MEM);

		//// Write the remotePath of LoadLibrary to the process's newly allocated memory
		if (!WriteProcessMemory(hProcess, remotePath, (LPVOID)dllBuffer, dllBufferSize, &bytesRet) ||
			dllBufferSize > bytesRet)
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);

		//// Inject dll into the tremotePathet process using CreateRemoteThread
		hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)llAddr, remotePath, NULL, NULL);
		if (!hThread)	ERROR_LEAVE(error, ERROR_CREATE_REMOTE_THREAD);

		WaitForSingleObject(hThread, INFINITE);

		// Check if LoadLibrary executed correctly
		GetExitCodeThread(hThread, &exitCode);
		if (!exitCode)	error = ERROR_INJECT_FAILED;
	}
	__finally {
		if (remotePath)	VirtualFreeEx(hProcess, remotePath, dllBufferSize, MEM_RELEASE);
		if (hThread)	CloseHandle(hThread);
		if (hProcess)	CloseHandle(hProcess);

		ErrorFormat(error);
	}

	return (error == ERROR_INJECT_SUCCESS) ? TRUE : FALSE;
}

BYTE codeCave32[] = {
	0x60,                         // PUSHAD
	0x9C,                         // PUSHFD
	0x68, 0x00, 0x00, 0x00, 0x00, // PUSH remoteDllPath (3)	  remoteDllPath
	0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, LoadLibraryAddress (8) LoadLibraryAddress
	0xFF, 0xD0,                   // CALL EAX
	//0x83, 0xC4, 0x04,             // ADD ESP, 0x04
	0x9D,                         // POPFD
	0x61,                         // POPAD
	0x68, 0x00, 0x00, 0x00, 0x00, // PUSH originalEip (20)	originalEip
	0xC3                          // RETN
};

BYTE codeCave64[] = {
	0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 0x28
	0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0,0, // mov rcx, remoteDllPath (6)
	0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0,0, // mov rax, LoadLibraryAddress (16)
	0xFF, 0xD0,                             // call rax
	0x48, 0x83, 0xC4, 0x28,                 // add rsp, 0x28
	0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0,0, // mov rax, originalRip (32)
	0x50,				// push rax
	0xc3

};

#ifdef _AMD64_
#define codeCave codeCave64
#else
#define codeCave codeCave32
#endif

BOOLEAN InjectTool::InjectThreadHijack()
{
	DWORD error = ERROR_INJECT_SUCCESS;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID remoteWrapper = NULL;
	LPVOID remoteDllPath = NULL;
	LPVOID loadLibraryAddress = NULL;
	LPCTSTR dllBuffer = m_TargetDll.GetBuffer();
	DWORD	dllBufferSize = (m_TargetDll.GetLength() + 1) * sizeof(TCHAR);
	CONTEXT context = { 0 };

	__try {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid);
		if (!hProcess)	ERROR_LEAVE(error, ERROR_OPEN_PROCESS);

		remoteWrapper = VirtualAllocEx(hProcess, NULL,
			sizeof(codeCave), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!remoteWrapper)	ERROR_LEAVE(error, ERROR_ALLOC_REMOTE_MEM);

		remoteDllPath = VirtualAllocEx(hProcess, NULL, dllBufferSize, MEM_COMMIT, PAGE_READWRITE);
		if (!remoteDllPath)	ERROR_LEAVE(error, ERROR_ALLOC_REMOTE_MEM);

		if (!WriteProcessMemory(hProcess, remoteDllPath, dllBuffer, dllBufferSize, NULL))
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);

		loadLibraryAddress = (LPVOID)GetProcAddress(LoadLibrary(_T("KERNEL32.DLL")), LOAD_LIBRARY);
		if (!loadLibraryAddress)	ERROR_LEAVE(error, ERROR_GET_PROC_ADDRESS);

		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_TargetTid);
		if (!hThread)	ERROR_LEAVE(error, ERROR_OPEN_THREAD);

		if (SuspendThread(hThread) == -1)	ERROR_LEAVE(error, ERROR_SUSPEND_REMOTE_THREAD);

		context.ContextFlags = CONTEXT_CONTROL;

		if (!GetThreadContext(hThread, &context))	ERROR_LEAVE(error, ERROR_GET_THREAD_CONTEXT);

		// COnstruct shellcode
#ifndef _AMD64_
		*(ULONG_PTR*)(codeCave + 3) = (ULONG_PTR)remoteDllPath;
		*(ULONG_PTR*)(codeCave + 8) = (ULONG_PTR)loadLibraryAddress;
		*(ULONG_PTR*)(codeCave + 17) = (ULONG_PTR)context.Eip;

		context.Eip = (DWORD)remoteWrapper;
#else	
		*(ULONG_PTR*)(codeCave + 6) = (ULONG_PTR)remoteDllPath;
		*(ULONG_PTR*)(codeCave + 16) = (ULONG_PTR)loadLibraryAddress;
		*(ULONG_PTR*)(codeCave + 32) = (ULONG_PTR)context.Rip;

		context.Rip = (ULONG_PTR)remoteWrapper;
#endif
		if (!WriteProcessMemory(hProcess, remoteWrapper, (LPVOID)codeCave, sizeof(codeCave), NULL))
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);

		if (!SetThreadContext(hThread, &context))
			ERROR_LEAVE(error, ERROR_SET_THREAD_CONTEXT);
	}
	__finally {
		if (context.ContextFlags)	ResumeThread(hThread);
		if (hThread)	CloseHandle(hThread);
		if (remoteDllPath)	VirtualFreeEx(hProcess, remoteDllPath, dllBufferSize, MEM_RELEASE);
		if (remoteWrapper)	VirtualFreeEx(hProcess, remoteWrapper, sizeof(codeCave), MEM_RELEASE);
		if (hProcess)	CloseHandle(hProcess);

		ErrorFormat(error);
	}

	return (error == ERROR_INJECT_SUCCESS);
}

BOOLEAN InjectTool::InjectQueueUserApc()
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID loadLibraryAddress = NULL;
	LPVOID remoteDllPath = NULL;
	LPTSTR dllBuffer = m_TargetDll.GetBuffer();
	DWORD dllBufferSize = (m_TargetDll.GetLength() + 1) * sizeof(TCHAR);
	DWORD error = ERROR_INJECT_SUCCESS;

	__try {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid);
		if (!hProcess)	ERROR_LEAVE(error, ERROR_OPEN_PROCESS);

		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_TargetTid);
		if (!hThread)	ERROR_LEAVE(error, ERROR_OPEN_THREAD);

		loadLibraryAddress = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), LOAD_LIBRARY);
		if (!loadLibraryAddress)	ERROR_LEAVE(error, ERROR_GET_PROC_ADDRESS);

		remoteDllPath = VirtualAllocEx(hProcess, NULL, dllBufferSize, MEM_COMMIT, PAGE_READWRITE);
		if (!remoteDllPath)	ERROR_LEAVE(error, ERROR_ALLOC_REMOTE_MEM);

		if (!WriteProcessMemory(hProcess, remoteDllPath, dllBuffer, dllBufferSize, NULL))
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);

		if (!QueueUserAPC((PAPCFUNC)loadLibraryAddress, hThread, (ULONG_PTR)remoteDllPath))
			ERROR_LEAVE(error, ERROR_QUEUE_APC);

		AfxMessageBox(_T("Note that target dll will be injected only after target thread entered ALERTABLE state!!"));
	}
	__finally {
		if (remoteDllPath)	VirtualFreeEx(hProcess, remoteDllPath, dllBufferSize, MEM_RELEASE);
		if (hThread)	CloseHandle(hThread);
		if (hProcess)	CloseHandle(hProcess);

		ErrorFormat(error);
	}

	return (error == ERROR_INJECT_SUCCESS);
}

//	Yon don't have to define a hook function in your DLL
//	just a address which will not cause a access violation
//	But better use a dummy hook for compatibility
BOOLEAN InjectTool::InjectSetWndHook()
{
	HMODULE hTargetDll = NULL;
	DWORD error = ERROR_INJECT_SUCCESS;

	__try {
		hTargetDll = LoadLibrary(m_TargetDll);
		if (!hTargetDll)	ERROR_LEAVE(error, ERROR_LOAD_MODULE);

		HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)CallNextHookEx, hTargetDll, m_TargetTid);
		if (!hHook)		ERROR_LEAVE(error, ERROR_INSTALL_WINDOWS_HOOK);

		PostMessage(m_TargetWindow, WM_KEYDOWN, 'A', NULL);
		PostMessage(m_TargetWindow, WM_KEYUP, 'A', NULL);
	}
	__finally {
		if (hTargetDll)	FreeLibrary(hTargetDll);

		ErrorFormat(error);
	}

	return error == ERROR_INJECT_SUCCESS;
}

/*
IME Injection:
ime file can be any dll
* "ime" extension not matter,
* no need to implement any ime function

*** need version resource which specify it's a input method
eg:
FILETYPE 0x3L		(VFT_DRV)
FILESUBTYPE 0xbL	(VFT2_DRV_INPUTMETHOD)
*/
#define IME_NAME	_T("HookIme.ime")

#define REG_CURRENT_USER_KBDLAYOUT	_T("Keyboard Layout\\Preload")
#define REG_LOCAL_MACHINE_KBDLAYOUT	_T("SYSTEM\\ControlSet001\\Control\\Keyboard Layouts")

#pragma comment(lib, "imm32.lib")
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
static void RemoveImeRegistry(HKL hIme)
{
	HKEY hKey = 0;
	DWORD valuesCount = 0;
	TCHAR valueName[MAX_PATH] = { 0 };
	DWORD valueNameSize = MAX_PATH;
	TCHAR subKeyName[MAX_PATH] = { 0 };

	if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_CURRENT_USER, REG_CURRENT_USER_KBDLAYOUT, 0, KEY_ALL_ACCESS, &hKey)) {
		if (ERROR_SUCCESS == RegQueryInfoKey(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &valuesCount, NULL, NULL, NULL, NULL)) {
			if (ERROR_SUCCESS == RegEnumValue(hKey, valuesCount - 1, valueName, &valueNameSize, NULL, NULL, NULL, NULL))
				RegDeleteValue(hKey, valueName);

		}

		RegCloseKey(hKey);
	}

	DWORD ret = ERROR_SUCCESS;
	DWORD idx = 0;
	DWORD keyIme = 0;

	if (ERROR_SUCCESS == RegOpenKeyEx(HKEY_LOCAL_MACHINE, REG_LOCAL_MACHINE_KBDLAYOUT, 0, KEY_ALL_ACCESS, &hKey)) {
		while (RegEnumKey(hKey, idx++, subKeyName, MAX_PATH) == ERROR_SUCCESS) {
			keyIme = _tcstoul(subKeyName, NULL, 16);

			if (keyIme == (DWORD)hIme) {
				if (ERROR_SUCCESS == RegDeleteKey(hKey, subKeyName)) {
					RegCloseKey(hKey);
					break;
				}
			}
		}
	}
}
#pragma warning(default: 4302)
#pragma warning(default: 4311)


BOOLEAN InjectTool::InjectIME()
{
	DWORD error = ERROR_INJECT_SUCCESS;
	TCHAR	sysDir[MAX_PATH] = { 0 };
	TCHAR	imePath[MAX_PATH] = { 0 };
	HKL hIME = NULL;
	HKL	oldIme = 0;
	BOOLEAN isFileCopy = FALSE;

	SHGetSpecialFolderPath(0, sysDir, CSIDL_SYSTEM, FALSE);

	__try {
		StringCbPrintf(imePath, MAX_PATH, _T("%s\\%s"), sysDir, IME_NAME);
		if (!CopyFile(m_TargetDll, imePath, FALSE))	ERROR_LEAVE(error, ERROR_COPY_IME);
		isFileCopy = TRUE;

		hIME = ImmInstallIME(imePath, IME_NAME);
		if (!hIME)	ERROR_LEAVE(error, ERROR_INSTALL_IME);

		// Backup default ime
		SystemParametersInfo(SPI_GETDEFAULTINPUTLANG, 0, &oldIme, 0);

		PostMessage(m_TargetWindow, WM_INPUTLANGCHANGEREQUEST, INPUTLANGCHANGE_SYSCHARSET, (LPARAM)hIME);
		PostMessage(m_TargetWindow, WM_INPUTLANGCHANGE, 0, (LPARAM)hIME);

	}
	__finally {
		// Remove inject ime from system after injection
		if (hIME) {
			if (!UnloadKeyboardLayout(hIME))
				AfxMessageBox(_T("Unload keyboard layout of inject IME failed."), MB_OK | MB_ICONWARNING);

			RemoveImeRegistry(hIME);
		}

		if (isFileCopy)
			if (!DeleteFile(imePath))
				AfxMessageBox(_T("Delete temp ime file failed. Please delete it manually."), MB_OK | MB_ICONWARNING);
	}

	return error == ERROR_INJECT_SUCCESS;
}

/*
Manually Dll Inject:
*****************************************

MAKE SURE YOUR DLL ARE RELEASE BUILDED

MAKE SURE YOUR INJECTOR ARE RELEASE BUILDED

******************************************
1. Load target dll into injector,
2. Create memory-mapped file of it and write to target process
3. Write loader to target process
4. Create remote thread to execute loader
*/
typedef
HMODULE
(WINAPI
	*pLoadLibraryA)(
		_In_ LPCSTR lpLibFileName
		);

typedef
FARPROC
(WINAPI
	*pGetProcAddress)(
		_In_ HMODULE hModule,
		_In_ LPCSTR lpProcName
		);

typedef BOOL(WINAPI *pDllMain)(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	);

typedef struct _LOADER_PARAMS
{
	PVOID						ImageBase;
	PIMAGE_NT_HEADERS			pNtHeaders;

	PIMAGE_BASE_RELOCATION		pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDirectory;

	pLoadLibraryA				fnLoadLibraryA;
	pGetProcAddress				fnGetProcAddress;
}LOADER_PARAMS, *PLOADER_PARAMS;

DWORD WINAPI LibLoader(PVOID	Params) {
	PLOADER_PARAMS LoaderParams = (PLOADER_PARAMS)Params;
	PVOID pImageBase = LoaderParams->ImageBase;

	PIMAGE_BASE_RELOCATION pBaseRelocation = LoaderParams->pBaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = LoaderParams->pImportDirectory;

	ULONG_PTR delta = RELOC_DELTA(pImageBase); // Calculate the delta
	while (pBaseRelocation->VirtualAddress &&
		pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
		DWORD blockCount = RELOC_BLOCKS_COUNT(pBaseRelocation);
		PWORD blockList = RELOC_BLOCKS(pBaseRelocation);
		for (DWORD i = 0; i < blockCount; i++) {
			if (blockList[i]) {
				/*PULONG_PTR ptr = (PULONG_PTR)( (LPBYTE)pImageBase + ( pBaseRelocation->VirtualAddress + ( blockList[i] & 0xFFF ) ) );*/
				PULONG_PTR ptr = RELOC_POINTER(pImageBase, pBaseRelocation, i);
				*ptr += delta;
			}
		}

		// Go to next base-allocation block
		pBaseRelocation = RELOC_NEXT_BASERELOC(pBaseRelocation);
	}

	// Resolve DLL imports
	while (pImportDescriptor->Characteristics) {
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)IMPORT_OFT(pImageBase, pImportDescriptor);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)IMPORT_FT(pImageBase, pImportDescriptor);

		HMODULE hModule = LoaderParams->fnLoadLibraryA(IMPORT_NAME(pImageBase, pImportDescriptor));
		if (!hModule)
			return 5;

		while (OrigFirstThunk->u1.AddressOfData) {
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				// Import by ordinal
				ULONG_PTR Function = (ULONG_PTR)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
				if (!Function)
					return 1;

				FirstThunk->u1.Function = Function;
			}
			else {
				// Import by name
				ULONG_PTR Function = (ULONG_PTR)LoaderParams->fnGetProcAddress(hModule, IMPORT_FUNC_NAME(pImageBase, OrigFirstThunk));
				if (!Function)
					return 2;

				FirstThunk->u1.Function = Function;
			}
			// Move to next import function
			OrigFirstThunk = IMPORT_NEXT_THUNK(OrigFirstThunk);
			FirstThunk = IMPORT_NEXT_THUNK(FirstThunk);
		}
		// Move to next import dll
		pImportDescriptor = IMPORT_NEXT_DESCRIPTOR(pImportDescriptor);
	}

	if (LoaderParams->pNtHeaders->OptionalHeader.AddressOfEntryPoint) {
		pDllMain EntryPoint = (pDllMain)IMAGE_ENTRYPOINT(pImageBase);

		if (EntryPoint((HMODULE)pImageBase, DLL_PROCESS_ATTACH, NULL)) // Call the entry point
			return ERROR_SUCCESS;
		else
			return 3;
	}

	return 4;
}

// Stub function used to calculate loader's size
DWORD WINAPI stubFunc()
{
	return 0;
}

BOOLEAN InjectTool::InjectManual() {
	HANDLE hFile = NULL;
	HANDLE hFileMap = NULL;
	PVOID pMapAddress = NULL;
	HANDLE hProcess = NULL;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectHeader;
	DWORD	imageSize;
	ULONG_PTR	loaderSize;

	LPVOID fnLoadLibraryA;
	LPVOID fnGetProcAddress;

	SIZE_T bytesWrite = 0;
	PVOID remoteImageBase = NULL;
	LOADER_PARAMS loaderParams = { 0 };

	PVOID remoteLoaderAddress = NULL;
	PVOID remoteParams = NULL;
	HANDLE hRemoteThread = NULL;
	DWORD exitCode = 0;
	DWORD error = ERROR_INJECT_SUCCESS;


	__try {
		hFile = CreateFile(m_TargetDll, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (INVALID_HANDLE(hFile))	ERROR_LEAVE(error, ERROR_OPEN_DLL_FILE);

		hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		if (!hFileMap)	ERROR_LEAVE(error, ERROR_CREATE_FILE_MAPPING);

		pMapAddress = MapViewOfFileEx(hFileMap, FILE_MAP_READ, 0, 0, 0, (LPVOID)NULL);
		if (!pMapAddress)	ERROR_LEAVE(error, ERROR_MAP_DLL);

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid);
		if (!hProcess)	ERROR_LEAVE(error, ERROR_OPEN_PROCESS);

		//
		// Prepare injection parameters
		//

		pDosHeader = DOS_HEADER(pMapAddress);
		pNtHeaders = NT_HEADERS(pMapAddress);
		pSectHeader = SEC_HEADER(pMapAddress);
		imageSize = IMAGE_SIZE(pMapAddress);
		loaderSize =/* (ULONG_PTR)stubFunc - (ULONG_PTR)LibLoader*/1024;

		fnLoadLibraryA = GetModuleFuncAddress("KERNEL32.DLL", "LoadLibraryA");
		fnGetProcAddress = GetModuleFuncAddress("KERNEL32.DLL", "GetProcAddress");
		if (!fnLoadLibraryA || !fnGetProcAddress)	ERROR_LEAVE(error, ERROR_GET_PROC_ADDRESS);

		//
		// Allocate memory for dll and loader in target process and write into it
		//

		remoteImageBase = VirtualAllocEx(hProcess, NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!remoteImageBase)	ERROR_LEAVE(error, ERROR_ALLOC_REMOTE_MEM);

		if (!WriteProcessMemory(hProcess, remoteImageBase, pMapAddress, imageSize, &bytesWrite) ||
			bytesWrite < imageSize)
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);

		loaderParams.fnGetProcAddress = (pGetProcAddress)fnGetProcAddress;
		loaderParams.fnLoadLibraryA = (pLoadLibraryA)fnLoadLibraryA;
		loaderParams.pBaseRelocation = (PIMAGE_BASE_RELOCATION)REMOTE_DATA_DIRECTORY(remoteImageBase, pMapAddress, IMAGE_DIRECTORY_ENTRY_BASERELOC);
		loaderParams.pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)REMOTE_DATA_DIRECTORY(remoteImageBase, pMapAddress, IMAGE_DIRECTORY_ENTRY_IMPORT);
		loaderParams.pNtHeaders = (PIMAGE_NT_HEADERS)OffsetToVA(remoteImageBase, pDosHeader->e_lfanew);
		loaderParams.ImageBase = remoteImageBase;

		// Allocate loader and its params together
		remoteLoaderAddress = VirtualAllocEx(hProcess, NULL, loaderSize + sizeof(LOADER_PARAMS), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!remoteLoaderAddress)	ERROR_LEAVE(error, ERROR_ALLOC_REMOTE_MEM);

		remoteParams = (PVOID)((ULONG_PTR)remoteLoaderAddress + loaderSize);

		if (!WriteProcessMemory(hProcess, remoteLoaderAddress, LibLoader, loaderSize, &bytesWrite) ||
			bytesWrite < loaderSize)
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);
		if (!WriteProcessMemory(hProcess, remoteParams, &loaderParams, sizeof(LOADER_PARAMS), &bytesWrite) ||
			bytesWrite < sizeof(LOADER_PARAMS))
			ERROR_LEAVE(error, ERROR_WRITE_REMOTE_MEM);

		hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
			(LPTHREAD_START_ROUTINE)remoteLoaderAddress,
			(LPVOID)remoteParams,
			0, NULL);
		if (!hRemoteThread)	ERROR_LEAVE(error, ERROR_CREATE_REMOTE_THREAD);

		WaitForSingleObject(hRemoteThread, INFINITE);

		if (!GetExitCodeThread(hRemoteThread, &exitCode) && GetLastError() != STILL_ACTIVE)
			error = ERROR_INJECT_FAILED;

	}
	__finally {
		if (hRemoteThread)	CloseHandle(hRemoteThread);
		if (remoteLoaderAddress)	VirtualFreeEx(hProcess, remoteLoaderAddress, loaderSize + sizeof(LOADER_PARAMS), MEM_RELEASE);
		if (remoteImageBase)	VirtualFreeEx(hProcess, remoteImageBase, imageSize, MEM_RELEASE);
		if (hProcess)		CloseHandle(hProcess);
		if (pMapAddress)	UnmapViewOfFile(pMapAddress);
		if (hFileMap)		CloseHandle(hFileMap);
		if (hFile)			CloseHandle(hFile);

		ErrorFormat(error);
	}
	
	return error == ERROR_INJECT_SUCCESS;
}

void InjectTool::ErrorFormat(DWORD ErrorCode)
{
	switch (ErrorCode)
	{
	case ERROR_OPEN_PROCESS:
		Helper::ErrorPop(_T("Error: Open injected process failed!"));
		break;
	case ERROR_OPEN_THREAD:
		Helper::ErrorPop(TEXT("Open main thread of the remote process failed!"));
		break;
	case ERROR_LOAD_MODULE:
		Helper::ErrorPop(_T("Load target dll into injector failed."));
		break;
	case ERROR_INSTALL_WINDOWS_HOOK:
		Helper::ErrorPop(_T("Install windows hook failed.\n"));
		break;
	case ERROR_GET_PROC_ADDRESS:
		Helper::ErrorPop(_T("Error: Get address of the LoadLibrary failed!"));
		break;
	case ERROR_ALLOC_REMOTE_MEM:
		Helper::ErrorPop(_T("Error: Cannot allocate memory region in the injected process!\n"));
		break;
	case ERROR_WRITE_REMOTE_MEM:
		Helper::ErrorPop(_T("Error: Cannot write the dllpath into the process's memory\n"));
		break;
	case ERROR_CREATE_REMOTE_THREAD:
		Helper::ErrorPop(_T("Error: Cannot create remote thread!\n"));
		break;
	case ERROR_SUSPEND_REMOTE_THREAD:
		Helper::ErrorPop(TEXT("Cannot suspend target thread"));
		break;
	case ERROR_GET_THREAD_CONTEXT:
		Helper::ErrorPop(TEXT("Get target thread context failed!"));
		break;
	case ERROR_SET_THREAD_CONTEXT:
		Helper::ErrorPop(TEXT("Set target thread context failed"));
		break;
	case ERROR_QUEUE_APC:
		Helper::ErrorPop(_T("Queue Apc to target thread failed."));
		break;
	case ERROR_COPY_IME:
		Helper::ErrorPop(_T("Copy target dll to system folder failed."));
		break;
	case ERROR_INSTALL_IME:
		Helper::ErrorPop(_T("Install inject ime failed."));
		break;
	case ERROR_OPEN_DLL_FILE:
		Helper::ErrorPop(_T("Open target dll failed."));
		break;
	case ERROR_CREATE_FILE_MAPPING:
		Helper::ErrorPop(_T("Create dll file mapping oject failed."));
		break;
	case ERROR_MAP_DLL:
		Helper::ErrorPop(_T("Map dll file failed."));
		break;

	default:
		break;
	}
}