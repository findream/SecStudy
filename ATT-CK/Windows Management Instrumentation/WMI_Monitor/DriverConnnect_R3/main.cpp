#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")

#define CODE_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CODE_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DEVICE_LINK_NAME    L"\\\\.\\BufferedIODevcieLinkName"

HRESULT _DetourRemoteCreateInstance(
	ULONG       hRpc,
	ULONG       *ORPCthis,
	ULONG       *ORPCthat,
	IN  ULONG   *pUnk,
	IN  ULONG   *pInActProperties,
	OUT ULONG   ** ppOutActProperties
	);



BOOL GetInjectProcessId(PCHAR pcServiceName, PDWORD dwProcessId)
{
	SC_HANDLE hSCM = NULL;
	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
	if (hSCM == NULL)
	{
		printf("[!] OpenSCManager:%d", GetLastError());
		return FALSE;
	}

	DWORD dwBufSize = 0;                // 传入的缓冲长度
	DWORD dwBufNeed = 0;                // 需要的缓冲长度
	DWORD dwNumberOfService = 0;        // 返回的服务个数
	EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
		NULL, dwBufSize, &dwBufNeed, &dwNumberOfService, NULL, NULL);

	char *pBuf = NULL;
	dwBufSize = dwBufNeed + sizeof(ENUM_SERVICE_STATUS_PROCESS);
	pBuf = (char *)malloc(dwBufSize);
	memset(pBuf, 0, dwBufSize);

	BOOL bRet = FALSE;
	bRet = EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
		(LPBYTE)pBuf, dwBufSize, &dwBufNeed, &dwNumberOfService, NULL, NULL);
	if (bRet == FALSE)
	{
		printf(" EnumServicesStatusEx %d", GetLastError());
		return FALSE;
	}


	LPENUM_SERVICE_STATUS_PROCESS pServiceInfo = (LPENUM_SERVICE_STATUS_PROCESS)pBuf;
	DWORD dwPid = -1;
	for (unsigned int i = 0; i < dwNumberOfService; i++)
	{
		if (strcmp(pServiceInfo[i].lpServiceName, pcServiceName) == 0)
		{
			dwPid = pServiceInfo[i].ServiceStatusProcess.dwProcessId;
			break;
		}
	}
	*dwProcessId = dwPid;
	return TRUE;
}


int main()
{
	//PULONG A = 0;
	//_DetourRemoteCreateInstance(1, A, A, A, A, &A);
	PCHAR pcServiceName = "RpcSs";
	DWORD dwProcessId = -1;
	if (GetInjectProcessId(pcServiceName, &dwProcessId) == FALSE)
	{
		printf("[!]GetInjectProcessId:%x\n", GetLastError());
		return FALSE;
	}
	HANDLE handle = CreateFileW(DEVICE_LINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == handle)
	{
		printf("[!]CreateFileW:%x\n", GetLastError());
		return FALSE;
	}
	DWORD ulReturn = 0;
	BOOL bResult = WriteFile(handle, &dwProcessId, sizeof(DWORD), &ulReturn, NULL);
	if (bResult == FALSE || ulReturn == 0)
	{
		printf("[!]DeviceIoControl:%x\n", GetLastError());
		CloseHandle(handle);
		return FALSE;
	}
	CloseHandle(handle);
	return TRUE;
}



/////////////////////////////////

typedef struct _FUNCADDR
{
	ULONG fnTrampolineFunShellcode_Addr;
	ULONG fnDetourRemoteCreateInstanceShellcode_Addr;
	ULONG JmpBackAddr;
}FUNCADDR, *PFUNCADDR;


typedef struct _PEB_LDR_DATA
{
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR SpareBool;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
}PEB, *PPEB;

typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	DWORD SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD Flags;
	WORD LoadCount;
	WORD TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	DWORD CheckSum;
	DWORD TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef HANDLE (*pfnCreateFileW)(
	LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
	);

typedef BOOL (*pfnWriteFile)(
	HANDLE       hFile,
	LPCVOID      lpBuffer,
	DWORD        nNumberOfBytesToWrite,
	LPDWORD      lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped
	);

typedef BOOL (*pfnCloseHandle)(
	HANDLE hObject
	);

typedef VOID (*pfnRtlMoveMemory)(
	_Out_       VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_        SIZE_T         Length
	);
typedef HMODULE (*pfnLoadLibraryA)(
	LPCSTR lpLibFileName
	);
typedef FARPROC (*pfnGetProcAddress)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);




HRESULT _DetourRemoteCreateInstance(
	ULONG       hRpc,
	ULONG       *ORPCthis,
	ULONG       *ORPCthat,
	IN  ULONG   *pUnk,
	IN  ULONG   *pInActProperties,
	OUT ULONG   ** ppOutActProperties
	)
{
	PLDR_DATA_TABLE_ENTRY pLdrDataOfKernel32 = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrDataOfRpcss = NULL;
	PVOID lpBaseAddrOfKernel32 = NULL;
	PVOID lpBaseAddrOfRpcss = NULL;
	PVOID lpEndAddrOfRpcss = NULL;
	pfnCreateFileW  pCreateFileW = NULL;
	pfnWriteFile pWriteFile = NULL;
	pfnCloseHandle pCloseHandle = NULL;
	ULONG pRemoteCreateInstance = NULL;
	pfnLoadLibraryA pLoadLibraryA = NULL;
	pfnGetProcAddress pGetProcAddress = NULL;
	pfnRtlMoveMemory pRtlMoveMemory = NULL;


	//HMODULE aa = LoadLibraryA("rpcss.dll");
	PPEB pPeb = NULL;
	_asm
	{
		pushad
		mov eax, fs:[0x30]
		mov pPeb, eax
		popad
	}

	//Ldr
	PPEB_LDR_DATA Ldr = NULL;
	Ldr = pPeb->Ldr;

	PLIST_ENTRY pCurrentLdrData = &Ldr->InLoadOrderModuleList;
	PLIST_ENTRY pNextLdrData = pCurrentLdrData->Flink;
	while (pCurrentLdrData != pNextLdrData)
	{
		if (pLdrDataOfKernel32 != NULL &&pLdrDataOfRpcss != NULL)
		{
			break;
		}
		PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pNextLdrData;
		PWSTR usModuleName = pLdrDataEntry->BaseDllName.Buffer;
		if (*usModuleName == 'k'
			&& *(usModuleName + 1) == 'e' 
			&&  *(usModuleName + 2) == 'r'
			&&  *(usModuleName + 3) == 'n'
			&&  *(usModuleName + 4) == 'e'
			&&  *(usModuleName + 5) == 'l'
			&&  *(usModuleName + 6) == '3'
			&&  *(usModuleName + 7) == '2'
			)
		{
			pLdrDataOfKernel32 = pLdrDataEntry;
		}
		else if (usModuleName[0] == 'r' 
			&& usModuleName[1] == 'p' 
			&& usModuleName[2] == 'c' 
			&& usModuleName[3] == 's' 
			&& usModuleName[4] == 's')
		{
			pLdrDataOfRpcss = pLdrDataEntry;
		}
		pNextLdrData = pNextLdrData->Flink;
	}

	//获取基地址
	lpBaseAddrOfKernel32 = pLdrDataOfKernel32->DllBase;
	lpBaseAddrOfRpcss = pLdrDataOfRpcss->DllBase;
	lpEndAddrOfRpcss = (PVOID)((ULONG)lpBaseAddrOfRpcss + pLdrDataOfRpcss->SizeOfImage);


	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddrOfKernel32;//dos头
	PIMAGE_NT_HEADERS NtDllHeader = (PIMAGE_NT_HEADERS)(ULONG_PTR)((ULONG_PTR)pDosHeader + pDosHeader->e_lfanew);//nt头
	IMAGE_OPTIONAL_HEADER opthdr = NtDllHeader->OptionalHeader;//pe可选镜像头
	PIMAGE_EXPORT_DIRECTORY pExportTable = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pDosHeader +
		opthdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD arrayOfFunctionNames = (PDWORD)((BYTE*)pDosHeader + pExportTable->AddressOfNames);//函数名表
	PWORD arrayOfFunctionOrdinals = (PWORD)((BYTE*)pDosHeader + pExportTable->AddressOfNameOrdinals);// 函数索引号RVA
	PDWORD arrayOfFunctionAddresses = (PDWORD)((ULONG_PTR)pDosHeader + pExportTable->AddressOfFunctions);//地址表
	DWORD Base = pExportTable->Base;
	PCHAR functionName = NULL;
	ULONG functionOrdinal = 0;
	for (DWORD dwIndex = 0; dwIndex < pExportTable->NumberOfFunctions; dwIndex++) //在整个导出表里扫描
	{
		functionName = (PCHAR)((BYTE*)pDosHeader + arrayOfFunctionNames[dwIndex]);//函数名字
		if ('C' == *functionName && 'r' == *(functionName + 1) &&
			'e' == *(functionName + 2) && 'a' == *(functionName + 3) &&
			't' == *(functionName + 4) && 'e' == *(functionName + 5) &&
			'F' == *(functionName + 6) && 'i' == *(functionName + 7) &&
			'l' == *(functionName + 8) && 'e' == *(functionName + 9) &&
			'W' == *(functionName + 10) && '\0' == *(functionName + 11))
		{
			functionOrdinal = arrayOfFunctionOrdinals[dwIndex] + Base - 1; //函数索引号RVA[x]
			pCreateFileW = (pfnCreateFileW)((BYTE*)pDosHeader + arrayOfFunctionAddresses[functionOrdinal]);//函数地址
		}
		else if ('W' == *functionName && 'r' == *(functionName + 1) &&
			'i' == *(functionName + 2) && 't' == *(functionName + 3) &&
			'e' == *(functionName + 4) && 'F' == *(functionName + 5) &&
			'i' == *(functionName + 6) && 'l' == *(functionName + 7) &&
			'e' == *(functionName + 8) && '\0' == *(functionName + 9))
		{
			functionOrdinal = arrayOfFunctionOrdinals[dwIndex] + Base - 1; //函数索引号RVA[x]
			pWriteFile = (pfnWriteFile)((BYTE*)pDosHeader + arrayOfFunctionAddresses[functionOrdinal]);//函数地址
		}
		else if ('C' == *functionName && 'l' == *(functionName + 1) &&
			'o' == *(functionName + 2) && 's' == *(functionName + 3) &&
			'e' == *(functionName + 4) && 'H' == *(functionName + 5) &&
			'a' == *(functionName + 6) && 'n' == *(functionName + 7) &&
			'd' == *(functionName + 8) && 'l' == *(functionName + 9) &&
			'e' == *(functionName + 10) && '\0' == *(functionName + 11))
		{
			functionOrdinal = arrayOfFunctionOrdinals[dwIndex] + Base - 1; //函数索引号RVA[x]
			pCloseHandle = (pfnCloseHandle)((BYTE*)pDosHeader + arrayOfFunctionAddresses[functionOrdinal]);//函数地址
		}
		else if ('G' == *functionName && 'e' == *(functionName + 1) &&
			't' == *(functionName + 2) && 'P' == *(functionName + 3) &&
			'r' == *(functionName + 4) && 'o' == *(functionName + 5) &&
			'c' == *(functionName + 6) && 'A' == *(functionName + 7) &&
			'd' == *(functionName + 8) && 'd' == *(functionName + 9) &&
			'r' == *(functionName + 10) && 'e' == *(functionName + 11) &&
			's' == *(functionName + 12) && 's' == *(functionName + 13) && 
			'\0' == *(functionName + 14))
		{
			functionOrdinal = arrayOfFunctionOrdinals[dwIndex] + Base - 1; //函数索引号RVA[x]
			pGetProcAddress = (pfnGetProcAddress)((BYTE*)pDosHeader + arrayOfFunctionAddresses[functionOrdinal]);//函数地址
		}
		else if ('L' == *functionName && 'o' == *(functionName + 1) &&
			'a' == *(functionName + 2) && 'd' == *(functionName + 3) &&
			'L' == *(functionName + 4) && 'i' == *(functionName + 5) &&
			'b' == *(functionName + 6) && 'r' == *(functionName + 7) &&
			'a' == *(functionName + 8) && 'r' == *(functionName + 9) &&
			'y' == *(functionName + 10) && 'A' == *(functionName + 11) && 
			'\0' == *(functionName + 12))
		{
			functionOrdinal = arrayOfFunctionOrdinals[dwIndex] + Base - 1; //函数索引号RVA[x]
			pLoadLibraryA = (pfnLoadLibraryA)((BYTE*)pDosHeader + arrayOfFunctionAddresses[functionOrdinal]);//函数地址
		}
	}
	CHAR ModuleName[] = { 'N', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l','\0' };
	CHAR ProcName[] = { 'R', 't', 'l', 'M', 'o', 'v', 'e', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
	HMODULE hModule = pLoadLibraryA(ModuleName);
	pRtlMoveMemory = (pfnRtlMoveMemory)pGetProcAddress(hModule, ProcName);

	//暴力搜索得到RemoteCreateInstance
	DWORD pCurrentAddr = (DWORD)lpBaseAddrOfRpcss;
	DWORD pEndAddr = (DWORD)lpEndAddrOfRpcss;
	while (pCurrentAddr <pEndAddr)
	{
		//printf("%x", pCurrentAddr);
		if ((*(PBYTE)(pCurrentAddr + 0) == 0xBE &&
			*(PBYTE)(pCurrentAddr + 1) == 0x05 &&
			*(PBYTE)(pCurrentAddr + 2) == 0x00 &&
			*(PBYTE)(pCurrentAddr + 3) == 0x07 &&
			*(PBYTE)(pCurrentAddr + 4) == 0x80) &&
			(*(PBYTE)(pCurrentAddr + 0x29) == 0xBE &&
			*(PBYTE)(pCurrentAddr + 0x29 + 1) == 0x57 &&
			*(PBYTE)(pCurrentAddr + 0x29 + 2) == 0x00 &&
			*(PBYTE)(pCurrentAddr + 0x29 + 3) == 0x07 &&
			*(PBYTE)(pCurrentAddr + 0x29 + 4) == 0x80))
		{
			pRemoteCreateInstance = (ULONG)(pCurrentAddr - 0x12A0B);
			break;
		}
		pCurrentAddr = pCurrentAddr + 1;
	}

	//获取攻击IP地址
	CHAR pIPbuffer[0x1D] = { '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
		'\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0', 
		'\0', '\0', '\0' };
	pRtlMoveMemory(pIPbuffer, (PULONG)((ULONG)pInActProperties + 0x284), 0x1D);
	//建立通信
	//"\\\\.\\BufferedIODevcieLinkName"
	WCHAR FileName[] = { '\\','\\', '.', '\\', 'B', 'u', 'f', 'f', 'e', 'r', 'e',
		'd', 'I', 'O', 'D', 'e', 'v', 'c', 'i', 'e', 'L', 'i', 'n', 'k', 
		'N', 'a', 'm', 'e' ,'\0'};
	HANDLE handle = pCreateFileW(FileName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	DWORD ulReturn = 0;
	BOOL bResult = pWriteFile(handle, pIPbuffer, 0x1D, &ulReturn, NULL);
	pCloseHandle(handle);
	hRpc = NULL;
	ULONG pRemoteCreateInstance_ = ((ULONG)pRemoteCreateInstance + 5);
	_asm
	{
			mov     edi, edi
			push    ebp
			mov     ebp, esp
			jmp _DetourRemoteCreateInstance
	}
}


