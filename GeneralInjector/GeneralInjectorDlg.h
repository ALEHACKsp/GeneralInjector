
// GeneralInjectorDlg.h : header file
//

#pragma once

#include "InjectTool.h"
#include "CProcessListDlg.h"

// CGeneralInjectorDlg dialog
class CGeneralInjectorDlg : public CDialogEx
{
	// Construction
public:
	CGeneralInjectorDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_GENERALINJECTOR_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;
	HICON m_hIconFinderDock;
	HICON m_hIconFinderFloat;
	HCURSOR m_hCursorFinder;

	// Generated message map functions
	void SetFinderIcon(BOOL IsDock);
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnDropFiles(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnMouseMove(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnMouseUp(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonSelectProc();
	afx_msg void OnBnClickedButtonInject();
	afx_msg void OnStnClickedStaticFinder();
	CComboBox m_CtrlCBInjectMethod;
	CEdit m_CtrlEditProcess;
	CEdit m_CtrlEditWindow;
	CEdit m_CtrlEditThread;
	CMFCEditBrowseCtrl m_CtrlEditDllPath;
	CStatic m_CtrlStaticFinder;
	CString m_sEditProcess;
	CString m_sEditThread;
	CString m_sEditWindow;
	CString m_sEditDllpath;

	BOOLEAN m_StartFinder;
	HWND m_SelectedWnd;
	DWORD m_SelectedPid;
	DWORD m_SelectedTid;
	CString m_SelectedProcessName;

	InjectTool m_InjectTool;
};
