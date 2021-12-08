#include "workthread.h"


//白名单目录
//CHAR *WhiteDirList[] = {
//	"C:\\Program Files\\",
//	"C:\\Windows\\",
//	"C:\\Windows\\Debug\\",
//	"C:\\Windows\\PCHealth\\",
//	"C:\\Windows\\Registration\\",
//	"C:\\Windows\\System32\com\\",
//	"C:\\Windows\\System32\FxsTmp\\",
//	"C:\\Windows\\System32\Microsoft\\",
//	"C:\\Windows\\System32\Spool\\",
//	"C:\\Windows\\System32\Tasks\\",
//	"C:\\Windows\\Tasks\\",
//	"C:\\Windows\\Temp\\",
//	"C:\\Windows\\Tracing\\",
//	"C:\\Windows\\System32",
//	"C:\\Windows\\ehome",
//	"C:\\Program Files\\Windows Defender",
//	"C:\\Program Files\\Windows Journal",
//	"C:\\Program Files\\Windows Media Player"
//};

CHAR *AutoApproveEXEList[] = {
	"C:\\Windows\\System32\\cttunesvr.exe",
	"C:\\Windows\\SysWOW64\\cttunesvr.exe",
	"inetmgr.exe",
	"C:\\Windows\\System32\\infdefaultinstall.exe",
	"C:\\Windows\\SysWOW64\\infdefaultinstall.exe",
	"C:\\Windows\\System32\\migwiz\\migsetup.exe",
	"C:\\Windows\\SysWOW64\\migwiz\\migsetup.exe",
	"C:\\Windows\\System32\\migwiz\\migwiz.exe",
	"C:\\Windows\\SysWOW64\\migwiz\\migwiz.exe"
	"C:\\Windows\\System32\\mmc.exe",
	"C:\\Windows\\SysWOW64\\mmc.exe",
	"C:\\Windows\\System32\\oobe\\oobe.exe",
	"C:\\Windows\\System32\\pkgmgr.exe",
	"C:\\Windows\\SysWOW64\\pkgmgr.exe",
	"provisionshare.exe",
	"provisionstorage.exe",
	"C:\\Windows\\System32\\spinstall.exe",
	"C:\\Windows\\System32\\winsat.exe",

};

BOOL GetProcessEleation(DWORD dwPid ,TOKEN_ELEVATION_TYPE* pElevationType, BOOL* pIsadmin)
{
	HANDLE hToken = NULL;
	BOOL bResult = FALSE;
	DWORD dwSize = 0;

	if (!OpenProcessToken(OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid), TOKEN_QUERY, &hToken))
	{
		//printf("[!]OpenProcessToken:%d \t\n", GetLastError()); 
		return FALSE;
	}
		
	if (GetTokenInformation(hToken, TokenElevationType, pElevationType, sizeof(TokenElevationType), &dwSize)) {
		BYTE adminSID[SECURITY_MAX_SID_SIZE];
		dwSize = sizeof(adminSID);
		if (FALSE == CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, &dwSize))
		{
			printf("[!] CreateWellKnownSid:%d \t\n", GetLastError());
			return FALSE;
		}
		if (*pElevationType == TokenElevationTypeLimited) {
			HANDLE hUnfilteredToken = NULL;
			GetTokenInformation(hToken, TokenLinkedToken, (VOID*)&hUnfilteredToken, sizeof(HANDLE), &dwSize);
			if (CheckTokenMembership(hUnfilteredToken, &adminSID, pIsadmin))
				bResult = TRUE;
			CloseHandle(hUnfilteredToken);
		}
		else
		{
			*pIsadmin = IsUserAnAdmin();
			bResult = TRUE;
		}
	}
	CloseHandle(hToken);
	return bResult;
}

BOOL GetParentProcessId(DWORD dwPid, DWORD* pdwParentId)
{
	BOOL bResult = FALSE;
	//获取pfnNtQueryInformationProcess函数地址
	pfnNtQueryInformationProcess pNtQueryInformationProcess;

	pNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, dwPid);
	if (!hProcess)
	{
		printf("[!]OpenProcess:%d \t\n", GetLastError());
		*pdwParentId = -1;
		return bResult;
	}

	PROCESS_BASIC_INFORMATION  pbi;
	if (!pNtQueryInformationProcess(hProcess, ProcessBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) && pbi.InheritedFromUniqueProcessId >= 4)
	{
		*pdwParentId = pbi.InheritedFromUniqueProcessId;
		bResult = TRUE;
	}
	return bResult;
}

//https://blog.csdn.net/zuishikonghuan/article/details/47746621
//https://cloud.tencent.com/developer/ask/83272

//提升权限函数  
BOOL EnablePrivilege(HANDLE hToken, LPCSTR szPrivName)
{

	TOKEN_PRIVILEGES tkp;

	LookupPrivilegeValue(NULL, szPrivName, &tkp.Privileges[0].Luid);//修改进程权限  
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL);//通知系统修改进程权限  

	return((GetLastError() == ERROR_SUCCESS));

}
BOOL GetProcessPath(DWORD dwProcessId, TCHAR* lpFilePath)
{
	BOOL bResult = FALSE;
	TCHAR FileName[MAX_PATH] = {0};
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		return bResult;
	}
	HMODULE hModule = NULL;
	DWORD dwSize = MAX_PATH;
	if (EnumProcessModules(hProcess,&hModule, sizeof(hModule), &dwSize) && dwSize != 0)
	{
		if (GetModuleFileNameEx(hProcess, hModule, FileName, MAX_PATH))
		{
			RtlMoveMemory((void*)lpFilePath, FileName, sizeof(TCHAR)*MAX_PATH);
			bResult = TRUE;
		}
	}
	else
	{
		if (QueryFullProcessImageNameA(hProcess, 0, FileName, &dwSize))
		{
			RtlMoveMemory((void*)lpFilePath, FileName, sizeof(TCHAR)*MAX_PATH);
			bResult = TRUE;
		}
		else
		{
				HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				if (hSnapshot) 
				{
					PROCESSENTRY32 pe32;
					pe32.dwSize = sizeof(PROCESSENTRY32);
					if (Process32First(hSnapshot, &pe32)) 
					{
						do 
						{
							if (pe32.th32ProcessID == dwProcessId)
							{
								RtlMoveMemory((void*)lpFilePath, pe32.szExeFile, sizeof(TCHAR)*MAX_PATH);
								break;
							}
						} while (Process32Next(hSnapshot, &pe32));
					}
					CloseHandle(hSnapshot);
				}
		}
	}
	return bResult;
}

//检查可疑的文件名
BOOL IsAutoApprovalEXE(TCHAR* lpFilePath)
{
	BOOL bResult = FALSE;
	DWORD dwIndex = 0;
	while (AutoApproveEXEList[dwIndex] != NULL)
	{
		if (strcmp(lpFilePath, AutoApproveEXEList[dwIndex]) == 0)
		{
			bResult = TRUE;
			break;
		}
		dwIndex++;
	}
	return bResult;
}

//检查是否具有autoElevate标志
BOOL  CheckFusion(TCHAR* lpFilePath)
{
	BOOL bResult = FALSE;
	HANDLE hFile = CreateFile(lpFilePath, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == NULL)
	{
		return FALSE;
	}

	ACTCTXW pActCtx;
	WCHAR lpwFilePath[MAX_PATH] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, lpFilePath, strlen(lpFilePath) + 1, lpwFilePath, sizeof(lpwFilePath) / sizeof(lpwFilePath[0]));


	memset(&pActCtx, 0, sizeof(ACTCTXW));
	pActCtx.cbSize = 32;
	pActCtx.lpSource = lpwFilePath;
	pActCtx.lpResourceName = MAKEINTRESOURCEW(1);
	pActCtx.dwFlags = 8;


	HANDLE hMapping = NULL;
	
	LPVOID lpStartAddress = NULL;
	hMapping  = CreateFileMappingW(hFile, 0, 0x1000002u, 0, 0, 0);
	if (hMapping)
	{
		lpStartAddress = MapViewOfFile(hMapping, 4u, 0, 0, 0);
		if (lpStartAddress)
		{
			pActCtx.dwFlags |= 0x80u;
			pActCtx.hModule = (HMODULE)lpStartAddress;
		}
	}
	else
	{
		hMapping = 0;
	}
	HANDLE hActCtx = CreateActCtxW(&pActCtx);
	WCHAR pvBuffer[MAX_PATH] = {0};
	if (hActCtx != INVALID_HANDLE_VALUE)
	{
		if (QueryActCtxSettingsW(0, hActCtx, 0, L"autoElevate", pvBuffer, 8u, 0) && (pvBuffer[0] == 't' || pvBuffer[0] == 'T'))
			bResult = TRUE;
		ReleaseActCtx(hActCtx);
	}
	if (lpStartAddress)
		UnmapViewOfFile(lpStartAddress);
	if (hMapping)
		CloseHandle(hMapping);
	return bResult;
}


/////////////////////////////////////////////////////
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	GUID DriverActionGuid = DRIVER_ACTION_VERIFY;

	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };

	////set up structs to verify files with cert signatures
	memset(&wfi, 0, sizeof(wfi));
	wfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
	wfi.pcwszFilePath = pwszSourceFile;
	wfi.hFile = NULL;
	wfi.pgKnownSubject = NULL;

	memset(&wd, 0, sizeof(wd));
	wd.cbStruct = sizeof(WINTRUST_DATA);
	wd.dwUnionChoice = WTD_CHOICE_FILE;
	wd.pFile = &wfi;
	wd.dwUIChoice = WTD_UI_NONE;
	wd.fdwRevocationChecks = WTD_REVOKE_NONE;
	wd.dwStateAction = 0;
	wd.dwProvFlags = WTD_SAFER_FLAG;
	wd.hWVTStateData = NULL;
	wd.pwszURLReference = NULL;
	wd.pPolicyCallbackData = NULL;
	wd.pSIPClientData = NULL;
	wd.dwUIContext = 0;

	return WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
}

DWORD getSignerInfo(
	std::wstring aFileName,
	std::shared_ptr<CMSG_SIGNER_INFO> &aSignerInfo,
	HCERTSTORE &aCertStore)
{
	BOOL lRetVal = TRUE;
	DWORD lEncoding = 0;
	DWORD lContentType = 0;
	DWORD lFormatType = 0;
	HCERTSTORE lStoreHandle = NULL;
	HCRYPTMSG lCryptMsgHandle = NULL;

	CERT_INFO CertInfo = { 0 };

	DWORD lSignerInfoSize = 0;

	lRetVal = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		aFileName.data(),
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&lEncoding,
		&lContentType,
		&lFormatType,
		&lStoreHandle,
		&lCryptMsgHandle,
		NULL);

	if (!lRetVal)
	{
		return GetLastError();
	}

	lRetVal = CryptMsgGetParam(lCryptMsgHandle,
		CMSG_SIGNER_INFO_PARAM,
		0,
		NULL,
		&lSignerInfoSize);

	if (!lRetVal)
	{
		return GetLastError();
	}

	PCMSG_SIGNER_INFO lSignerInfoPtr = (PCMSG_SIGNER_INFO) new BYTE[lSignerInfoSize];

	// Get Signer Information.
	lRetVal = CryptMsgGetParam(lCryptMsgHandle,
		CMSG_SIGNER_INFO_PARAM,
		0,
		(PVOID)lSignerInfoPtr,
		&lSignerInfoSize);

	if (!lRetVal)
	{
		delete lSignerInfoPtr;
		return GetLastError();
	}

	aSignerInfo = std::shared_ptr<CMSG_SIGNER_INFO>(lSignerInfoPtr);
	aCertStore = lStoreHandle;
	return ERROR_SUCCESS;
}

DWORD getCertificateContext(
	std::shared_ptr<CMSG_SIGNER_INFO> aSignerInfo,
	HCERTSTORE aCertStore,
	PCCERT_CONTEXT &aCertContextPtr)
{

	PCCERT_CONTEXT pCertContext = NULL;
	CERT_INFO CertInfo = { 0 };

	CertInfo.Issuer = aSignerInfo->Issuer;
	CertInfo.SerialNumber = aSignerInfo->SerialNumber;

	pCertContext = CertFindCertificateInStore(
		aCertStore,
		(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
		0,
		CERT_FIND_SUBJECT_CERT,
		(PVOID)&CertInfo,
		NULL);

	if (!pCertContext)
	{
		return GetLastError();
	}

	aCertContextPtr = pCertContext;

	return ERROR_SUCCESS;
}

DWORD queryCertificateInfo(
	PCCERT_CONTEXT aCertContext,
	DWORD aType,
	std::wstring &aOutputName)
{

	DWORD lNameLength;

	lNameLength = CertGetNameString(aCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		aType,
		NULL,
		NULL,
		0);

	if (!lNameLength)
	{
		return GetLastError();
	}

	std::vector<wchar_t> lNameVector;
	lNameVector.reserve(lNameLength);

	// Get Issuer name.
	lNameLength = CertGetNameStringW(aCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		aType,
		NULL,
		lNameVector.data(),
		lNameLength);

	if (!lNameLength)
	{
		return GetLastError();
	}

	aOutputName.assign(lNameVector.data(), lNameLength);

	return ERROR_SUCCESS;
}

BOOL CheckMiscrosoftSignature(LPCWSTR pwszSourceFile)
{
	BOOL bResult = FALSE;
	WCHAR* SubjectName;
	HCERTSTORE lCertStore;
	std::shared_ptr<CMSG_SIGNER_INFO> lSignerInfo;
	DWORD lRetVal = ERROR_SUCCESS;
	PCCERT_CONTEXT lCertContexPtr = NULL;
	lRetVal = getSignerInfo(pwszSourceFile, lSignerInfo, lCertStore);
	if (lRetVal != ERROR_SUCCESS)
	{
		return bResult;
	}

	lRetVal = getCertificateContext(lSignerInfo, lCertStore, lCertContexPtr);
	if (lRetVal != ERROR_SUCCESS)
	{
		return bResult;
	}

	std::wstring lSubjectName;
	lRetVal = queryCertificateInfo(lCertContexPtr, 0, lSubjectName);
	if (lRetVal == ERROR_SUCCESS)
	{
		SubjectName = &lSubjectName[0];
		if (wcsicmp(SubjectName, L"Microsoft Windows") == 0)
		{
			bResult = TRUE;
		}

	}
	return bResult;
}
////////////////////////////////////////

BOOL CheckExeSignature(DWORD dwPid)
{
	BOOL bResult = FALSE;
	//LPWSTR pwszSourceFile = NULL;
	WCHAR pwszSourceFile[MAX_PATH] = { 0 };
	TCHAR lpFilePath[MAX_PATH] = {0};
	GetProcessPath(dwPid, lpFilePath);
	MultiByteToWideChar(CP_ACP, 0, lpFilePath, strlen(lpFilePath) + 1, pwszSourceFile, sizeof(pwszSourceFile) / sizeof(pwszSourceFile[0]));
	if (VerifyEmbeddedSignature(pwszSourceFile) == ERROR_SUCCESS)
	{
		bResult = CheckMiscrosoftSignature(pwszSourceFile);
	}
	return bResult;
}
//判断父进程的合法性
BOOL IsParentProcessLegitimacy(DWORD dwPid,DWORD *dwParentPid)
{
	BOOL bResult = FALSE;
	DWORD dwParentId = -1;

	//获取父进程Pid
	if (GetParentProcessId(dwPid, &dwParentId) == TRUE && (dwParentId == -1))
	{
		return bResult;
	}

	//获取父进程的文件路径
	TCHAR lpFilePath[MAX_PATH] = {0};
	if (GetProcessPath(dwParentId, lpFilePath) == FALSE && lpFilePath == NULL)
	{
		return bResult;
	}
	BOOL bIsAdmin = FALSE;
	TOKEN_ELEVATION_TYPE  ElevationType;
	if (IsAutoApprovalEXE(lpFilePath) == TRUE || CheckFusion(lpFilePath) == TRUE || (GetProcessEleation(dwParentId, &ElevationType, &bIsAdmin) == TRUE && (ElevationType == TokenElevationTypeFull)))
	{
		bResult = TRUE;
	}
	*dwParentPid = dwParentId;
	return bResult;
}




PCHAR GetProcessNameByPid(DWORD dwPid)
{
	TCHAR lpFilePath[MAX_PATH] = { 0 };
	if (GetProcessPath(dwPid, lpFilePath) != TRUE)
	{
		strcpy(lpFilePath, "GetProcessNameError");
		return lpFilePath;
	}
	PathStripPath(lpFilePath);
	return lpFilePath;

}
BOOL WorkThread(PVOID _ProcessInfo)
{
	PROCESS_LONNK_READDATA *ProcessInfo = (PROCESS_LONNK_READDATA*)_ProcessInfo;
	TCHAR ProcessName[MAX_PATH] = { 0 };
	TCHAR ParentProcessName[MAX_PATH] = { 0 };

	DWORD dwPid = (DWORD)ProcessInfo->hProcessId;
	DWORD dwParentPid = 0;
	strcpy(ProcessName, &ProcessInfo->szProcessName[4]);
	strcpy(ParentProcessName, ProcessInfo->szParentProcessName);
	
	//printf("%s ----> %s \t\n", ParentProcessName, ProcessName);

	BOOL bIsAdmin = FALSE;
	TOKEN_ELEVATION_TYPE  ElevationType;
	
	//第一步:判断是否提升权限
	if (GetProcessEleation(dwPid, &ElevationType, &bIsAdmin) == TRUE && (ElevationType == TokenElevationTypeFull))
	{
		//第二步:进程文件是否存在数字签名
		//第三步:检查父进程合法性
		if (CheckExeSignature(dwPid) == FALSE && IsParentProcessLegitimacy(dwPid, &dwParentPid) == TRUE)
		{
			printf("[*]detect ByPass UAC: %s [%d] =======> %s[%d] \t\n", ParentProcessName, dwParentPid, ProcessName, dwPid);
		}
	}

	return TRUE;
}