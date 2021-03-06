
// GeneralInjectorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "GeneralInjector.h"
#include "GeneralInjectorDlg.h"
#include "CProcessListDlg.h"
#include "Helper.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#ifdef _AMD64_
#define DIALOG_ARCH	"[64 bit]"
#else
#define DIALOG_ARCH	"[32 bit]"
#endif

#define COPYRIGHT	"-- By Mouka"
#define DIALOG_TITLE _T("General Injector ")DIALOG_ARCH COPYRIGHT

static void FrameWindow(HWND hWnd)
{

	if (!IsWindow(hWnd))	return;

	RECT rc;
	if (::GetWindowRect(hWnd, &rc))
	{
		int w = rc.right - rc.left - 1;
		int h = rc.bottom - rc.top - 1;
		HDC hDC = ::GetWindowDC(hWnd);
		::SetROP2(hDC, R2_XORPEN);
		HPEN hNewPen = CreatePen(PS_SOLID, /*GetSystemMetrics(SM_CXSIZEFRAME)*/10, RGB(255, 255, 255));
		HBRUSH hOldBrush = (HBRUSH)SelectObject(hDC, GetStockObject(HOLLOW_BRUSH));
		HPEN hOldPen = (HPEN)::SelectObject(hDC, hNewPen);

		Rectangle(hDC, 10, 10, rc.right - rc.left - 10, rc.bottom - rc.top - 10);

		::SelectObject(hDC, hOldPen);
		::SelectObject(hDC, hOldBrush);
		::DeleteObject(hNewPen);
		::ReleaseDC(hWnd, hDC);
	}

}

void SetWindowTop(HWND hWnd, bool Value)
{
	if (Value)
	{
		SetWindowPos(hWnd,
			HWND_TOPMOST,
			0, 0, 0, 0,
			SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
	}
	else
	{
		SetWindowPos(hWnd,
			HWND_NOTOPMOST,
			0, 0, 0, 0,
			SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
	}
}

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
	, m_sEditWindow(_T(""))
	, m_sEditProcess(_T(""))
	, m_sEditThread(_T(""))
	, m_sEditDllpath(_T(""))
	, m_SelectedProcessName(_T(""))
	, m_SelectedWnd(NULL)
	, m_StartFinder(FALSE)
	, m_SelectedPid(0)
	, m_SelectedTid(0)
	, m_InjectTool()
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_hIconFinderDock = AfxGetApp()->LoadIcon(IDI_ICON_FINDER_DOCK);
	m_hIconFinderFloat = AfxGetApp()->LoadIcon(IDI_ICON_FINDER_FLOAT);

	m_hCursorFinder = AfxGetApp()->LoadCursor(IDC_CURSOR_WND_FINDER);
}

void CGeneralInjectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO_INJECT_METHODS, m_CtrlCBInjectMethod);
	DDX_Control(pDX, IDC_EDIT_PROCESS, m_CtrlEditProcess);
	DDX_Control(pDX, IDC_MFCEDITBROWSE_DLLPATH, m_CtrlEditDllPath);
	DDX_Control(pDX, IDC_STATIC_FINDER, m_CtrlStaticFinder);
	DDX_Control(pDX, IDC_EDIT_WINDOW, m_CtrlEditWindow);
	DDX_Control(pDX, IDC_EDIT_THREAD, m_CtrlEditThread);
}

void CGeneralInjectorDlg::SetFinderIcon(BOOL IsDock)
{
	HDC hIconDc = ::GetWindowDC(m_CtrlStaticFinder);
	if (IsDock)
	{
		DrawIcon(hIconDc, 0, 0, m_hIconFinderDock);
	}
	else
	{
		DrawIcon(hIconDc, 0, 0, m_hIconFinderFloat);
	}
}

BEGIN_MESSAGE_MAP(CGeneralInjectorDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_MESSAGE(WM_DROPFILES, OnDropFiles)
	ON_MESSAGE(WM_MOUSEMOVE, OnMouseMove)
	ON_MESSAGE(WM_LBUTTONUP, OnMouseUp)
	ON_BN_CLICKED(IDC_BUTTON_SELECT_PROC, &CGeneralInjectorDlg::OnBnClickedButtonSelectProc)
	ON_BN_CLICKED(IDC_BUTTON_INJECT, &CGeneralInjectorDlg::OnBnClickedButtonInject)
	ON_STN_CLICKED(IDC_STATIC_FINDER, &CGeneralInjectorDlg::OnStnClickedStaticFinder)
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

	// Set main dlg title 
	SetWindowText(DIALOG_TITLE);

	m_CtrlCBInjectMethod.AddString(_T("CreateRemoteThread"));
	m_CtrlCBInjectMethod.AddString(_T("ThreadHijack"));
	m_CtrlCBInjectMethod.AddString(_T("QueueUserApc"));
	m_CtrlCBInjectMethod.AddString(_T("SetWindowsHook"));
	m_CtrlCBInjectMethod.AddString(_T("InputMethod"));
	m_CtrlCBInjectMethod.AddString(_T("ManualMap"));
	m_CtrlCBInjectMethod.SetCurSel(INJECT_CREATE_REMOTE_THREAD);

	m_CtrlEditDllPath.EnableFileBrowseButton(_T(".dll"), _T("DLL files|*.dll|All files|*.*||"), OFN_FILEMUSTEXIST);
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
	m_sEditDllpath = szFilePath;
	m_CtrlEditDllPath.SetWindowText(m_sEditDllpath);
	return 0;
}

LRESULT CGeneralInjectorDlg::OnMouseMove(WPARAM wParam, LPARAM lParam)
{
	if (m_StartFinder)
	{
		CWnd* windowUnderCursor;
		POINT currentPos = { 0 };

		if (GetCursorPos(&currentPos))
		{
			windowUnderCursor = WindowFromPoint(currentPos);
			if (windowUnderCursor == this ||
				windowUnderCursor->GetParent() == this)	// Skip current window
			{
				FrameWindow(m_SelectedWnd);
				m_SelectedWnd = NULL;
				m_sEditWindow = _T("");
				m_CtrlEditWindow.SetWindowText(m_sEditWindow);
				return 0;
			}

			// todo: retrieve the class window of target window
			// ...

			else if (windowUnderCursor->m_hWnd != m_SelectedWnd)	// Move to a new window
			{
				FrameWindow(m_SelectedWnd);
				m_SelectedWnd = windowUnderCursor->m_hWnd;
				FrameWindow(m_SelectedWnd);

				// Output selected window handle to dlg
				m_sEditWindow.Format(_T("0x%p"), m_SelectedWnd);
				m_CtrlEditWindow.SetWindowText(m_sEditWindow);
			}


		}

	}

	return 0;
}

LRESULT CGeneralInjectorDlg::OnMouseUp(WPARAM wParam, LPARAM lParam)
{
	if (m_StartFinder)
	{
		m_StartFinder = FALSE;

		FrameWindow(m_SelectedWnd);
		SetFinderIcon(TRUE);
		SetWindowTop(HWND(this), FALSE);

		ReleaseCapture();

		// Get process/thread id of the selected window 
		m_SelectedTid = GetWindowThreadProcessId(m_SelectedWnd, &m_SelectedPid);
		if (m_SelectedPid)
		{
			Helper::GetProcessFilename(m_SelectedPid, m_SelectedProcessName);

			m_sEditProcess.Format(_T("<%d> -- %s"), m_SelectedPid, m_SelectedProcessName);
			m_sEditThread.Format(_T("%d"), m_SelectedTid);
			m_CtrlEditProcess.SetWindowText(m_sEditProcess);
			m_CtrlEditThread.SetWindowText(m_sEditThread);
		}

	}

	return 0;
}

void CGeneralInjectorDlg::OnBnClickedButtonSelectProc()
{
	CProcessListDlg processListDlg;
	INT_PTR ret = processListDlg.DoModal();
	if (ret == IDOK)
	{
		m_SelectedPid = _tcstoul(processListDlg.m_SelectedPid, NULL, 10);
		m_SelectedProcessName = processListDlg.m_SelectedProcessName;

		m_sEditProcess.Format(_T("%s (%d)"), m_SelectedProcessName, m_SelectedPid);
		m_CtrlEditProcess.SetWindowText(m_sEditProcess);

		// Clear previous selected thread and window
		m_SelectedTid = 0;
		m_SelectedWnd = NULL;
		m_sEditThread.Empty();
		m_sEditWindow.Empty();
		m_CtrlEditThread.SetWindowText(m_sEditThread);
		m_CtrlEditWindow.SetWindowText(m_sEditWindow);

	}

}


void CGeneralInjectorDlg::OnBnClickedButtonInject()
{
	CString injectInfo;
	CString injectRet;
	CString typeText;
	m_CtrlEditDllPath.GetWindowText(m_sEditDllpath);
	DWORD type = m_CtrlCBInjectMethod.GetCurSel();
	m_CtrlCBInjectMethod.GetLBText(type, typeText);
	typeText = _T("<") + typeText + _T(">");

	// Validate inject infos
	if (m_sEditDllpath.IsEmpty())
	{
		AfxMessageBox(_T("Target dll path cannot be empty"));
		return;
	}
	else if (!m_SelectedPid)
	{
		AfxMessageBox(_T("Please select process from list, or capture a windows"));
		return;
	}

	// When inejct type is QueueUserApc/ThreadHijack which needs a thread 
	// And target process is selected from list
	// Then try to find a thread of the process
	if ((type == INJECT_QUEUE_USER_APC ||
		type == INJECT_THREAD_HIJACK) && !m_SelectedTid)
	{
		m_SelectedTid = Helper::GetMainThreadId(m_SelectedPid);
		if (!m_SelectedTid)
		{
			AfxMessageBox(_T("Cannot get a thread of the target process"));
			return;
		}
	}

	// When inejct type is IME_inject/SetWindowsHookEx which needs a window
	// And process is selected from list
	// Then try to find a window of the process
	if ((type == INJECT_SET_WINDOW_HOOK ||
		type == INJECT_IME) && !m_SelectedWnd)
	{
		GUI_INFO guiInfo = { 0 };
		guiInfo.ProcessId = m_SelectedPid;
		if (!Helper::GetProcessGUIThreadInfo(&guiInfo))
		{
			AfxMessageBox(_T("Cannot get a window of the target process"));
			return;
		}
		m_SelectedTid = guiInfo.ThreadId;
		m_SelectedWnd = guiInfo.hWindow;
	}

	injectInfo.Format(_T(
		"Injected process : %s\n"
		"Injected dll : \"%s\"\n"
		"Method : %s\n\n"
		"Sure to inject?\n"), m_sEditProcess, m_sEditDllpath, typeText);
	if (AfxMessageBox(injectInfo, MB_OKCANCEL | MB_ICONASTERISK) == IDOK)
	{
		m_InjectTool.SetTargetProcess(m_SelectedPid);
		m_InjectTool.SetTargetThread(m_SelectedTid);
		m_InjectTool.SetTargetWindow(m_SelectedWnd);
		m_InjectTool.SetInjectType(type);
		m_InjectTool.SetTargetDll(m_sEditDllpath);

		if (m_InjectTool.Inject())
		{
			injectRet.Format(_T("Inject to process %s successfully."), m_sEditProcess);
			AfxMessageBox(injectRet, MB_OK | MB_ICONINFORMATION);
		}
		else
		{
			injectRet.Format(_T("Inject to process %s failed."), m_sEditProcess);
			AfxMessageBox(injectRet, MB_OK | MB_ICONWARNING);
		}
	}

}


void CGeneralInjectorDlg::OnStnClickedStaticFinder()
{
	// Clean last found first
	m_SelectedWnd = NULL;
	m_SelectedPid = 0;
	m_SelectedTid = 0;

	m_sEditProcess = _T("");
	m_sEditThread = _T("");
	m_sEditWindow = _T("");
	m_CtrlEditProcess.SetWindowText(m_sEditProcess);
	m_CtrlEditThread.SetWindowText(m_sEditWindow);
	m_CtrlEditWindow.SetWindowText(m_sEditWindow);

	// Begin finder
	m_StartFinder = TRUE;

	SetWindowTop(HWND(this), TRUE);
	SetCursor(m_hCursorFinder);	// Change cursor when finding 
	SetFinderIcon(FALSE);			// Change Finder icon when finding window

	SetCapture();
}


