// CProcessListDlg.cpp : implementation file
//

#include "stdafx.h"
#include <TlHelp32.h>

#include "GeneralInjector.h"
#include "CProcessListDlg.h"
#include "afxdialogex.h"
#include "Helper.h"

typedef enum {
	SORT_NONE = 0,
	SORT_AZ = 1,
	SORT_ZA = -1,
} SortOrder;

typedef struct _PROCESS_INFO
{
	LPTSTR ProcessName;
	LPTSTR Pid;
	LPTSTR ImagePath;
	LPTSTR ImageType;
}PROCESS_INFO, *PPROCESS_INFO;

SortOrder gOrderType = SORT_NONE;
// CProcessListDlg dialog

IMPLEMENT_DYNAMIC(CProcessListDlg, CDialogEx)

CProcessListDlg::CProcessListDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_PROCESS_LIST, pParent)
{

}

CProcessListDlg::~CProcessListDlg()
{
}

void CProcessListDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_ProcessListCtrl);
}


BEGIN_MESSAGE_MAP(CProcessListDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CProcessListDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON_REFRESH, &CProcessListDlg::OnBnClickedButtonRefresh)
END_MESSAGE_MAP()

void CProcessListDlg::EnumProcess()
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	DWORD result = NULL;
	BOOL isWow64;

	CString ProcessName;
	CString Pid;
	CString ImagePath;
	CString ImageType;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
	}

#ifndef _AMD64_
	BOOLEAN isWow64Emul = Helper::IsWow64Emulator();
#endif

	do
	{
#ifdef _AMD64_
		if (!Helper::IsProcessWow64(pe32.th32ProcessID, &isWow64) ||
			isWow64)
			// 64 bit process only
			continue;
		ImageType = CString(IMAGE_64);
#else
		if (isWow64Emul)    // 32 bit injector in x64 platform
		{
			if (!Helper::IsProcessWow64(pe32.th32ProcessID, &isWow64) ||
				!isWow64)
				// 32 bit process only
				continue;
		}
		ImageType = CString(IMAGE_32);
#endif
		ProcessName = CString(pe32.szExeFile);
		Pid.Format(_T("%d"), pe32.th32ProcessID);
		Helper::GetProcessFullpath(pe32.th32ProcessID, ImagePath);

		m_ProcessListCtrl.AddItem(ProcessName, Pid,ImagePath, ImageType);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

}

void CProcessListDlg::UpdataProcessList()
{
	m_ProcessListCtrl.SetRedraw(FALSE);
	m_ProcessListCtrl.DeleteAllItems();
	EnumProcess();
	m_ProcessListCtrl.SetRedraw(TRUE);
}


// CProcessListDlg message handlers

BOOL CProcessListDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	m_SelectedPid = _T("0");

	m_ProcessListCtrl.SetHeadings(_T("Process Name,150;PID,100;Image Path,200;Image Type,100"));
	m_ProcessListCtrl.SetExtendedStyle(LVS_EX_HEADERDRAGDROP);
	m_ProcessListCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	UpdataProcessList();

	return TRUE;
}


void CProcessListDlg::OnBnClickedOk()
{
	m_SelectedPid = m_ProcessListCtrl.GetItemText(
		m_ProcessListCtrl.GetSelectionMark(),
		COL_PID);
	m_SelectedProcessName = m_ProcessListCtrl.GetItemText(
		m_ProcessListCtrl.GetSelectionMark(),
		COL_PROC_NAME);

	CDialogEx::OnOK();
}


void CProcessListDlg::OnBnClickedButtonRefresh()
{
	UpdataProcessList();
	UpdateData(FALSE);
}
