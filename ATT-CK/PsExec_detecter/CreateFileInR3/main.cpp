#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <WinIoCtl.h>
#include "GetHandleTable.h"


#define CODE_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CODE_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DEVICE_LINK_NAME    L"\\\\.\\BufferedIODevcieLinkName"

typedef struct tagPROCESS_BASIC_INFORMATION
{
	DWORD ExitStatus;
	DWORD PebBaseAddress;
	DWORD AffinityMask;
	DWORD BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
}PROCESS_BASIC_INFORMATION;
//
//typedef enum enumSYSTEM_INFORMATION_CLASS
//{
//	SystemBasicInformation,
//	SystemProcessorInformation,
//	SystemPerformanceInformation,
//	SystemTimeOfDayInformation,
//}SYSTEM_INFORMATION_CLASS;
//
typedef LONG(WINAPI *PNTQUERYINFORMATIONPROCESS)(HANDLE, UINT, PVOID, ULONG, PULONG);
PNTQUERYINFORMATIONPROCESS  NtQueryInformationProcess = NULL;

DWORD GetParentProcessID(HANDLE hProcess)
{
	LONG                      status;
	DWORD                     dwParentPID = 0;
//	HANDLE                    hProcess;
	PROCESS_BASIC_INFORMATION pbi;

	//hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	if (!hProcess)
		return -1;
	NtQueryInformationProcess = (PNTQUERYINFORMATIONPROCESS)GetProcAddress(GetModuleHandle("ntdll"), "NtQueryInformationProcess");
	if (NtQueryInformationProcess == NULL)
	{
		return -1;
	}
	status = NtQueryInformationProcess(hProcess, SystemBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	if (!status)
		dwParentPID = pbi.InheritedFromUniqueProcessId;

	CloseHandle(hProcess);
	return dwParentPID;
}


BOOL IsServicesByPid(DWORD dwPid)
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
	for (unsigned int i = 0; i < dwNumberOfService; i++)
	{
		if (dwPid == pServiceInfo[i].ServiceStatusProcess.dwProcessId)
		{
			printf("[*]Find Service Name %s Of ProcessId", pServiceInfo[i].lpDisplayName);
			return TRUE;
		}
	}
	return FALSE;

}

BOOL IsPipe(DWORD dwPid)
{
	return GetHanldeTable(dwPid);
}

int main()
{
	HANDLE handle = CreateFileW(DEVICE_LINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == handle)
	{
		printf("CreateFileW", GetLastError());
		return NULL;
	}

	LPBYTE buffer = (LPBYTE)malloc(sizeof(HANDLE));
	DWORD dwRetSize = 0;
	if (ReadFile(handle, (LPVOID)buffer, sizeof(DWORD), &dwRetSize, NULL) == FALSE)
	{
		printf("ReadFile %d\n", GetLastError());
		return -1;
	}
	CloseHandle(handle);


	DWORD dwPid = -1;
	if (buffer != 0)
	{
		memcpy(&dwPid, buffer, sizeof(DWORD));
		printf("[*]PresentPid:%x", dwPid);
		
		//dwPid = GetProcessId(hProcess);
		if (IsServicesByPid(dwPid) == TRUE)
		{
			if (IsPipe(dwPid) == TRUE)
			{
				printf("[*]detected software like PsExec in your system");
			}
		}


	}
	return 0;
}