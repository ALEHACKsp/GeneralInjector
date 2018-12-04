#pragma once

#include "stdafx.h"

typedef enum _INJECT_TYPE
{
	INJECT_CREATE_REMOTE_THREAD = 0,
	INJECT_THREAD_HIJACK,
	INJECT_QUEUE_USER_APC,
	INJECT_SET_WINDOW_HOOK,
	INJECT_IME,
	INJECT_MANUAL
}INJECT_TYPE;

class InjectTool
{
	DWORD m_InjectType;
	DWORD m_TargetPid;
	DWORD m_TargetTid;
	CString m_TargetDll;
	HWND m_TargetWindow;

public:
	// Constructor
	InjectTool() : 
		m_InjectType(INJECT_CREATE_REMOTE_THREAD), 
		m_TargetPid(0), 
		m_TargetTid(0),
		m_TargetDll(""),
		m_TargetWindow(NULL){}

	CString GetTargetDll() { return m_TargetDll; }
	DWORD GetTargetProcess() { return m_TargetPid; }
	DWORD GetInjectType() { return m_InjectType; }
	DWORD GetTargetThread() { return m_TargetTid; }
	HWND GetTargetWindow() { return m_TargetWindow; }

	void SetInjectType(DWORD InjectType) { m_InjectType = InjectType; }
	void SetTargetProcess(DWORD Pid) { m_TargetPid = Pid; }
	void SetTargetDll(CString TargetDll) { m_TargetDll = TargetDll; }
	void SetTargetThread(DWORD Tid) { m_TargetTid = Tid; }
	void SetTargetWindow(HWND hWnd) { m_TargetWindow = hWnd; }

	BOOLEAN Inject();
	BOOLEAN InjectCreateRemoteThread();
	BOOLEAN InjectThreadHijack();
	BOOLEAN InjectQueueUserApc();
	BOOLEAN InjectSetWndHook();
	BOOLEAN InjectIME();
};