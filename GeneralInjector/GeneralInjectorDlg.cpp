
// GeneralInjectorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "GeneralInjector.h"
#include "GeneralInjectorDlg.h"
#include "CProcessListDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CGeneralInjectorDlg dialog



CGeneralInjectorDlg::CGeneralInjectorDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_GENERALINJECTOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGeneralInjectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_INJECT_METHODS, m_CtrlInjectMethod);
	DDX_Control(pDX, IDC_EDIT_PROCESS, m_CtrlProcess);
	DDX_Control(pDX, IDC_MFCEDITBROWSE_DLLPATH, m_CtrlDllPath);
}

BEGIN_MESSAGE_MAP(CGeneralInjectorDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_DROPFILES, OnDropFiles)
	ON_BN_CLICKED(IDC_BUTTON_SELECT_PROC, &CGeneralInjectorDlg::OnBnClickedButtonSelectProc)
	ON_BN_CLICKED(IDC_BUTTON_INJECT, &CGeneralInjectorDlg::OnBnClickedButtonInject)
END_MESSAGE_MAP()

// CGeneralInjectorDlg message handlers

BOOL CGeneralInjectorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	m_CtrlInjectMethod.AddString(_T("CreateRemoteThread"));
	m_CtrlInjectMethod.AddString(_T("ThreadHijack"));
	m_CtrlInjectMethod.AddString(_T("QueueUserApc"));
	m_CtrlInjectMethod.SetCurSel(INJECT_CREATE_REMOTE_THREAD);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CGeneralInjectorDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CGeneralInjectorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CGeneralInjectorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

LRESULT CGeneralInjectorDlg::OnDropFiles(WPARAM wParam, LPARAM lParam)
{
	TCHAR szFilePath[MAX_PATH] = { 0 };
	HDROP hDrop = (HDROP)wParam;

	UpdateData(TRUE);

	DragQueryFile(hDrop, 0, szFilePath, MAX_PATH);
	GetDlgItem(IDC_MFCEDITBROWSE_DLLPATH)->SetWindowTextW(szFilePath);
	return 0;
}


#include <tchar.h>
void CGeneralInjectorDlg::OnBnClickedButtonSelectProc()
{
	// TODO: Add your control notification handler code here
	INT_PTR ret = m_processListDlg.DoModal();
	if (ret == IDOK)
	{
		//AfxMessageBox(m_processListDlg.m_SelectedPid);
		m_CtrlProcess.SetWindowText(m_processListDlg.m_SelectedPid);
	}
	else
		AfxMessageBox(_T("No process selected"));
}


void CGeneralInjectorDlg::OnBnClickedButtonInject()
{
	// TODO: Add your control notification handler code here
	TCHAR path[MAX_PATH] = { 0 };
	TCHAR text[MAX_PATH] = { 0 };
	TCHAR buffer[MAX_PATH] = { 0 };
	DWORD type = m_CtrlInjectMethod.GetCurSel();
	m_CtrlDllPath.GetWindowText(path, _countof(path));
	_ultot_s(type, text, _countof(text), 10);

	_stprintf_s(buffer, _countof(buffer),_T("Inject dll %s to process %d with method %d"), path, _tcstoul(m_processListDlg.m_SelectedPid, NULL,10), type);
	AfxMessageBox(buffer);
	m_InjectTool.SetTargetProcess(_tcstoul(m_processListDlg.m_SelectedPid, NULL, 10));
	m_InjectTool.SetInjectType(type);
	m_InjectTool.SetTargetDll(path);
}
