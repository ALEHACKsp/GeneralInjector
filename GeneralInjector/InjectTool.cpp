#include "stdafx.h"

#include "InjectTool.h"

BOOLEAN InjectTool::Inject()
{
	if (!m_InjectType ||
		!m_TargetPid ||
		m_TargetDll.IsEmpty())
		return FALSE;

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
	return BOOLEAN();
}

BOOLEAN InjectTool::InjectThreadHijack()
{
	return BOOLEAN();
}

BOOLEAN InjectTool::InjectQueueUserApc()
{
	return BOOLEAN();
}
