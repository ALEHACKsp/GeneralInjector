#include "stdafx.h"

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
	default:
		return FALSE;

	}

	return ret;
}

BOOLEAN InjectTool::InjectCreateRemoteThread()
{
	HANDLE hProcess;
	HANDLE hThread;
	LPVOID llAddr;
	LPVOID remotePath;

	LPCTSTR dllBuffer = m_TargetDll.GetBuffer();
	DWORD dllBufferSize = (m_TargetDll.GetLength() + 1) * sizeof(TCHAR);
	SIZE_T bytesRet;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid);
	if (!hProcess)
	{
		Helper::ErrorPop(_T("Error: Open injected process failed!"));
		return FALSE;
	}

	// Get address of the function LoadLibraryA 
	llAddr = (LPVOID)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), LOAD_LIBRARY);
	if (!llAddr)
	{
		Helper::ErrorPop(_T("Error: Get address of the LoadLibrary failed!"));
		return FALSE;
	}

	//// Allocate new memory region inside the injected process's memory space
	//// remotePath is the start address of the allocated memory
	remotePath = VirtualAllocEx(hProcess, NULL, dllBufferSize, MEM_COMMIT, PAGE_READWRITE);
	if (!remotePath)
	{
		Helper::ErrorPop(_T("Error: Cannot allocate memory region in the injected process!\n"));
		return FALSE;
	}

	//// Write the remotePath of LoadLibrary to the process's newly allocated memory
	if (!WriteProcessMemory(hProcess, remotePath, (LPVOID)dllBuffer, dllBufferSize, &bytesRet) ||
		dllBufferSize > bytesRet)
	{
		Helper::ErrorPop(_T("Error: Cannot write the dllpath into the process's memory\n"));
		return FALSE;
	}

	//// Inject dll into the tremotePathet process using CreateRemoteThread
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)llAddr, remotePath, NULL, NULL);
	if (!hThread)
	{
		Helper::ErrorPop(_T("Error: Cannot create remote thread!\n"));
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);

	// Check if LoadLibrary executed correctly
	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	return (exitCode) ? TRUE : FALSE;
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
	HANDLE hProcess;
	HANDLE hThread;
	LPVOID remoteWrapper;
	LPVOID remoteDllPath;
	LPVOID loadLibraryAddress = NULL;
	LPCTSTR dllBuffer = m_TargetDll.GetBuffer();
	DWORD	dllBufferSize = (m_TargetDll.GetLength() + 1) * sizeof(TCHAR);

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid)))
	{
		Helper::ErrorPop(TEXT("Open injected process failed!\nExited."));
		return FALSE;

	}

	if (!(remoteWrapper = VirtualAllocEx(hProcess, NULL,
		sizeof(codeCave), MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		Helper::ErrorPop(TEXT("Cannot allocate memory for remote wrapper!"));
		return FALSE;
	}

	remoteDllPath = VirtualAllocEx(hProcess, NULL, dllBufferSize, MEM_COMMIT, PAGE_READWRITE);
	if (!remoteDllPath)
	{
		Helper::ErrorPop(TEXT("Cannot allocate memory for output text!"));
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, remoteDllPath, dllBuffer, dllBufferSize, NULL))
	{
		Helper::ErrorPop(TEXT("Cannot write  text to process memory!"));
		return FALSE;
	}

	loadLibraryAddress = (LPVOID)GetProcAddress(LoadLibrary(_T("KERNEL32.DLL")), LOAD_LIBRARY);
	if (!loadLibraryAddress)
	{
		Helper::ErrorPop(TEXT("Cannot find the address of function LoadLibraryA! "));
		return FALSE;
	}

	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_TargetTid);
	if (!hThread)
	{
		Helper::ErrorPop(TEXT("Open main thread of the remote process failed!"));
		return FALSE;
	}
	if (SuspendThread(hThread) == -1)
	{
		Helper::ErrorPop(TEXT("Cannot suspend target thread"));
		return FALSE;
	}

	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_CONTROL;

	if (!GetThreadContext(hThread, &context))
	{
		Helper::ErrorPop(TEXT("Get thread context failed!"));
		return FALSE;
	}

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
	if (!WriteProcessMemory(hProcess, remoteWrapper,
		(LPVOID)codeCave, sizeof(codeCave), NULL))
	{
		Helper::ErrorPop(TEXT("Cannot write wrapper to process memory!"));
		return FALSE;
	}

	if (!SetThreadContext(hThread, &context))
	{
		Helper::ErrorPop(TEXT("Set thread context failed"));
		return FALSE;

	}
	ResumeThread(hThread);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}

BOOLEAN InjectTool::InjectQueueUserApc()
{
	LPTSTR dllBuffer = m_TargetDll.GetBuffer();
	DWORD dllBufferSize = (m_TargetDll.GetLength() + 1) * sizeof(TCHAR);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_TargetPid);
	if (!hProcess)
	{
		Helper::ErrorPop(_T("Get target process handle failed."));
		return FALSE;
	}

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, m_TargetTid);
	if (!hThread)
	{
		Helper::ErrorPop(_T("Get target thread handle failed."));
		return FALSE;
	}

	LPVOID loadLibraryAddress = GetProcAddress(GetModuleHandle(_T("kernel32.dll")), LOAD_LIBRARY);
	if (!loadLibraryAddress)
	{
		Helper::ErrorPop(_T("Get LoadLibrary address failed."));
		return FALSE;
	}

	LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, dllBufferSize, MEM_COMMIT, PAGE_READWRITE);
	if (!remoteDllPath)
	{
		Helper::ErrorPop(_T("Alloc remote dll path failed."));
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, remoteDllPath, dllBuffer, dllBufferSize, NULL))
	{
		Helper::ErrorPop(_T("Cannot write dll path to target process."));
		return FALSE;
	}

	if (!QueueUserAPC((PAPCFUNC)loadLibraryAddress, hThread, (ULONG_PTR)remoteDllPath))
	{
		Helper::ErrorPop(_T("QueueUserApc failed."));
		return FALSE;
	}
	
	AfxMessageBox(_T("Note that target dll will be injected only after target thread entered ALERTABLE state!!"));
	return TRUE;
}

BOOLEAN InjectTool::InjectSetWndHook()
{
	HMODULE hTargetDll = LoadLibrary(m_TargetDll);
	if (!hTargetDll)
	{
		Helper::ErrorPop(_T("Load target dll into injector failed.\n"));
		return FALSE;
	}

	HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)CallNextHookEx, hTargetDll, m_TargetTid);
	if (!hHook)
	{
		Helper::ErrorPop(_T("Install windows hook failed.\n"));
		return FALSE;
	}

	PostMessage(m_TargetWindow, WM_KEYDOWN, 'A', NULL);
	PostMessage(m_TargetWindow, WM_KEYUP, 'A', NULL);


	return TRUE;

}
