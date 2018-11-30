#pragma once

#include "stdafx.h"

typedef enum _INJECT_TYPE
{
	INJECT_CREATE_REMOTE_THREAD = 0,
	INJECT_QUEUE_USER_APC,
	INJECT_THREAD_HIJACK,
	INJECT_SET_WINDOW_HOOK,
	INJECT_IME,
	INJECT_MANUAL
}INJECT_TYPE;

class InjectTool
{
	DWORD m_InjectType;
	DWORD m_TargetPid;
	CString m_TargetDll;

public:
	// Constructor
	InjectTool() : m_InjectType(INJECT_CREATE_REMOTE_THREAD), m_TargetPid(0), m_TargetDll("") {}

	CString GetTargetDll() { return m_TargetDll; }
	DWORD GetTargetProcess() { return m_TargetPid; }
	DWORD GetInjectType() { return m_InjectType; }
	void SetInjectType(DWORD InjectType) { m_InjectType = InjectType; }
	void SetTargetProcess(DWORD Pid) { m_TargetPid = Pid; }
	void SetTargetDll(CString TargetDll) { m_TargetDll = TargetDll; }

	BOOLEAN Inject();
	BOOLEAN InjectCreateRemoteThread();
	BOOLEAN InjectThreadHijack();
	BOOLEAN InjectQueueUserApc();
};