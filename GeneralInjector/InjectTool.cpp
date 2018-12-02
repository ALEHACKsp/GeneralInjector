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

BOOLEAN InjectTool::InjectThreadHijack()
{
	return BOOLEAN();
}

BOOLEAN InjectTool::InjectQueueUserApc()
{
	return BOOLEAN();
}
