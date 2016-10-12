#include "StdAfx.h"
#include "SignHelp.h"
#include <Wintrust.h>
//#pragma comment (lib, "Version.lib")
#pragma comment (lib, "Wintrust.lib")
//#pragma comment (lib, "Shell32.lib")


#define WINTRUST_ACTION_GENERIC_VERIFY_V2                       \
			{ 0xaac56b,                                         \
			  0xcd44,                                           \
			  0x11d0,                                           \
			  { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } \
			}


SignHelp* SignHelp::m_instance = NULL;
//=================================================================================================================================
SignHelp* SignHelp::Instance()
{
	if (m_instance == NULL){
		m_instance = new SignHelp(); 
	}
	return m_instance;
}


SignHelp::SignHelp(void)
{
}

SignHelp::~SignHelp(void)
{
}

bool SignHelp::IsSigned(wchar_t* path)
{
	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO sWintrustFileInfo;
	WINTRUST_DATA      sWintrustData;
	HRESULT            hr;

	memset((void*)&sWintrustFileInfo, 0x00, sizeof(WINTRUST_FILE_INFO));
	memset((void*)&sWintrustData, 0x00, sizeof(WINTRUST_DATA));

	sWintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);

	wchar_t* pResult = path;
	sWintrustFileInfo.pcwszFilePath = pResult;

	sWintrustFileInfo.hFile = NULL;

	sWintrustData.cbStruct            = sizeof(WINTRUST_DATA);
	sWintrustData.dwUIChoice          = WTD_UI_NONE;
	sWintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	sWintrustData.dwUnionChoice       = WTD_CHOICE_FILE;
	sWintrustData.pFile               = &sWintrustFileInfo;
	sWintrustData.dwStateAction       = WTD_STATEACTION_VERIFY;

	hr = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);

	bool bVerify = false;
	if (TRUST_E_NOSIGNATURE == hr)
	{
		OutputDebugString(L"No signature found on the file.\n");
	}

	else if (TRUST_E_BAD_DIGEST == hr)
	{
		OutputDebugString(L"The signature of the file is invalid\n");
	}

	else if (TRUST_E_PROVIDER_UNKNOWN == hr)
	{
		OutputDebugString(L"No trust provider on this machine can verify this type of files.\n");

	}

	else if (S_OK != hr)
	{
		wchar_t wszBuf[64];
		memset(wszBuf, 0, sizeof(wszBuf));
		wsprintf(wszBuf, L"WinVerifyTrust failed with error 0x%.8X\n", hr);
		OutputDebugString(wszBuf);
	}

	else
	{
		bVerify = true;
	}

	sWintrustData.dwUIChoice = WTD_UI_NONE;
	sWintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guidAction, &sWintrustData);
	return bVerify;
}