#pragma once

class CjwttestDlg : public CDialogEx
{
public:
	CjwttestDlg(CWnd* pParent = nullptr);	

#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_JWT_TEST_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.

protected:
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	DECLARE_MESSAGE_MAP()

public:
	afx_msg void OnDestroy();
	virtual BOOL PreTranslateMessage(MSG* pMsg);

	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();	

private:
	void HS256_test();
	void RSA_test();
	void read_key(const std::string& key_path, std::string& key);
};
