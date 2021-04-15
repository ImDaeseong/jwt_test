#include "pch.h"
#include "framework.h"
#include "jwt_test.h"
#include "jwt_testDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CjwttestDlg::CjwttestDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_JWT_TEST_DIALOG, pParent)
{
}

void CjwttestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CjwttestDlg, CDialogEx)
	ON_WM_PAINT()
	ON_BN_CLICKED(IDC_BUTTON1, &CjwttestDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CjwttestDlg::OnBnClickedButton2)
	ON_WM_DESTROY()
END_MESSAGE_MAP()

BOOL CjwttestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	return TRUE;  
}

void CjwttestDlg::OnPaint()
{
	CPaintDC dc(this);
}

BOOL CjwttestDlg::PreTranslateMessage(MSG* pMsg)
{
	return CDialogEx::PreTranslateMessage(pMsg);
}

void CjwttestDlg::OnDestroy()
{
	CDialogEx::OnDestroy();
}

//hs256
void CjwttestDlg::OnBnClickedButton1()
{
	HS256_test();	
}

//RS256
void CjwttestDlg::OnBnClickedButton2()
{
	RSA_test();
}

void CjwttestDlg::HS256_test()
{
	CString sPassword = _T("password1234567890");

	//ssign
	jwt::jwt_object obj{ algorithm("HS256"), secret(std::string(CT2CA(sPassword))) };

	obj.add_claim("iss", "daeseong.com")
		.add_claim("exp", 1485270000000)
		.add_claim("https://daeseong.com/jwt", true)
		.add_claim("userId", "userId1234567890")
		.add_claim("username", "daeseong");


	jwt::jwt_header jheader = obj.header();
	std::string header = jwt::to_json_str(jheader).c_str();

	std::string payload = jwt::to_json_str(obj.payload()).c_str();

	std::string sign = obj.signature();

	CString shead(header.c_str());
	//OutputDebugString(shead);

	CString spayload(payload.c_str());
	//OutputDebugString(spayload);

	CString ssign(sign.c_str());
	//OutputDebugString(ssign);


	//decode
	jwt::jwt_object decobj = jwt::decode(sign, algorithms({ "hs256" }), false, secret(std::string(CT2CA(sPassword))));

	std::string decheader = jwt::to_json_str(decobj.header()).c_str();

	std::string decpayload = jwt::to_json_str(decobj.payload()).c_str();

	CString sdechead(decheader.c_str());
	//OutputDebugString(sdechead);

	CString sdecpayload(decpayload.c_str());
	//OutputDebugString(sdecpayload);


	CString sResult;
	sResult.Format(_T("sign:%s\r\ndec:%s"), ssign, sdecpayload);
	OutputDebugString(sResult);

	if (decobj.has_claim("iss")) {
		std::string iss = decobj.payload().get_claim_value<std::string>("iss");
	}
}

void CjwttestDlg::RSA_test()
{
	/*
	std::string pub_key =
		R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Oz81UGSi+VBrvdIDnFL
2UVSLUVyjBXXH9Ar2tZoaOy/JVevK63yoiLpbRHjAMy9nVViq/OrQHkT7BJ6HzSU
9NwiaqZPMb16eacX+RUIYnVVMgICsxyFG2xLS/GtD4w9GvYdvHqa5Y8wg1Y03MtZ
vXNmCapWZryBibKV4aRTnfM/ditz7uLl3DwTzka3hGvqw+zWgf2L6cQZDWWAifYA
S59h0q2mciVeqiksPzcgJVS15RtNujxxryo+B2vbjV/FmKGTtByOL8eCkExeMDOp
do67gKqBrarz1bEloZEzlyeEjcGrbeueLeHBLE86N+ts9jJ5ew7/GzW6u7ldzjZe
QQIDAQAB
-----END PUBLIC KEY-----)";

	std::string priv_key =
		R"(-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDU7PzVQZKL5UGu
90gOcUvZRVItRXKMFdcf0Cva1mho7L8lV68rrfKiIultEeMAzL2dVWKr86tAeRPs
EnofNJT03CJqpk8xvXp5pxf5FQhidVUyAgKzHIUbbEtL8a0PjD0a9h28eprljzCD
VjTcy1m9c2YJqlZmvIGJspXhpFOd8z92K3Pu4uXcPBPORreEa+rD7NaB/YvpxBkN
ZYCJ9gBLn2HSraZyJV6qKSw/NyAlVLXlG026PHGvKj4Ha9uNX8WYoZO0HI4vx4KQ
TF4wM6l2jruAqoGtqvPVsSWhkTOXJ4SNwatt654t4cEsTzo362z2Mnl7Dv8bNbq7
uV3ONl5BAgMBAAECggEAQbkI7bZ4yo+wL5aKelLES8NW8zxdeBoBtgMmljzaK5Dw
C1G+cygVHbDTBmSgAg4wdRD3DQaAlL0KxjKJ2Xn8hHwyb2L4TO0kkcpe3vZ8CRAY
hQAT3z9tYqKRt1ZYydTKw7i2QwhBKZyCJ/gDBygJgi3NkCww0TNcdKlYFDcJzFXJ
0OaZ9JMfRwsr/umLjD1HEP+zRoqtcrVH3sAwQeWuTvfEz5GRSCxhf3XZlq99tZX0
4dbyOoH0CO1Gn3z1NKb6f3hA3P4PsipYH9j/mug9MYJgUv1nhMUmb8oG6Taxs+DO
c8z+2XbGfKV70OHftTLJweYP5beIcEQFL9ZMIAkhJQKBgQDv2Gd49TGHauMqK277
aMxZpdWgxz3KfA2rrbAK2xUB9lVSnmCpBUBAtyDbMpX4lYl+vyxRR+rBnoaNxuzE
/0Kvr4xhsOJc7zNECujjTuKeleAPmwxyzt5TsxDhoKnqBKC+tluBBZfp1sStadD/
rWrEVc90I6JhnfVvMZv1Q307ywKBgQDjRGpO45vU8WlGcpG/C+7l1wXHxCo/lRYH
eX/KEPTo9pCdR2E9cCoNsIaJtkugWohgv4Fd5dHjwzlnbMGyHdXSpJi3MRchCcgw
kpyS9sgWddP+U99AL12puoTyc3ZhMTPKBcY8JOfFDWXjhspNvObMbocqmdUx6SsE
IOtolppkowKBgHcDYxTaVmFj4KUkOEX4kq5JY+AL/dVkCUSPQzOf0qTOnzgH7t7w
BBoYxO0ABPr8+OUz58HNdeftycbAVuzJ3UVgTsCLDUggScgRwc5JbppStIQJ4/t0
O049JLtRBf9hnIIF6xHyvJcEQ0PpphO48anLCs4OgJz/zLIIY+MoQhRRAoGAAad0
0qAreTBMoNuine5bTcbz3tFZsV7Ha0SCHpli/vMUeGCVn5naZIEdaZEvGbqu9W1P
ZryOe4bnOw56lm5LKR5TkjnEPlRQ5bGbfCJZsHgpE9fObywpFVwrLYyTlv+Brf2+
xJ9MJI4FaNOJU2mFkIVZbID0IUneK0iGDhvSgdsCgYBGEYAQR8+z2eCEOqidFe+K
L99xhfUacXeKkKZ7Jadb2ZpPf4axpxz1URtZN8aacYdCMvBm4dNvGxuVcWkMF3pl
Gbg/8SduROAR3/4QewBvZrBriC0BvVeg/xVhn1GnCHEZR1ILM9UnKbef5+Xd/8pC
cv7W+fQP4Art0BtezXCmWg==
-----END PRIVATE KEY-----)";
	*/

	std::string pub_key;
	std::string priv_key;
	read_key("E:/VS2019/public.key", pub_key);
	read_key("E:/VS2019/private.key", priv_key);

	//ssign
	jwt::jwt_object obj;
	obj.secret(priv_key);
	obj.header().algo(jwt::algorithm::RS256);

	obj.add_claim("iss", "daeseong.com")
		.add_claim("exp", 1485270000000)
		.add_claim("https://daeseong.com/jwt", true)
		.add_claim("userId", "userId1234567890")
		.add_claim("username", "daeseong");

	jwt::jwt_header jheader = obj.header();
	std::string header = jwt::to_json_str(jheader).c_str();

	std::string payload = jwt::to_json_str(obj.payload()).c_str();

	std::string sign = obj.signature();

	CString shead(header.c_str());
	//OutputDebugString(shead);

	CString spayload(payload.c_str());
	//OutputDebugString(spayload);

	CString ssign(sign.c_str());
	//OutputDebugString(ssign);


	//decode
	jwt::jwt_object decobj = jwt::decode(sign, algorithms({ "RS256" }), false, secret(pub_key), verify(true));

	std::string decheader = jwt::to_json_str(decobj.header()).c_str();

	std::string decpayload = jwt::to_json_str(decobj.payload()).c_str();

	CString sdechead(decheader.c_str());
	//OutputDebugString(sdechead);

	CString sdecpayload(decpayload.c_str());
	//OutputDebugString(sdecpayload);

	CString sResult;
	sResult.Format(_T("sign:%s\r\ndec:%s"), ssign, sdecpayload);
	OutputDebugString(sResult);

	if (decobj.has_claim("iss")) {
		std::string iss = decobj.payload().get_claim_value<std::string>("iss");
	}
}

void CjwttestDlg::read_key(const std::string& key_path, std::string& key)
{
	std::ifstream in(key_path);

	if (!in.good())
	{
		throw std::runtime_error("could not load key");
	}

	const std::string result{ std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };

	if (result.empty())
	{
		throw std::runtime_error("key was empty");
	}

	key.assign(result);
}