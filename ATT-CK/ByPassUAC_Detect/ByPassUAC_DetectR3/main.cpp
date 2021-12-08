#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include "workthread.h"




#define EVENT_NAME    L"Global\\ProcLook"


//设备与设备之间通信
#define DEVICE_OBJECT_NAME  L"\\Device\\BufferedIODeviceObjectName"
#define  IBINARY_EVENTNAME  L"\\BaseNamedObjects\\ProcLook"
#define DEVICE_LINK_NAME    L"\\\\.\\BufferedIODevcieLinkName"



#define CTRLCODE_BASE 0x8000
#define MYCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, CTRLCODE_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCESS_LOCK_READ MYCTRL_CODE(1)





int main(int argc, char* argv[])
{

	PROCESS_LONNK_READDATA pmdInfoNow = { 0 };

	// 打开驱动设备对象
	HANDLE hDriver = CreateFileW(
		DEVICE_LINK_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileW:%x\n", GetLastError());
		return -1;
	}
	// 打开内核事件对象
	HANDLE hProcessEvent = OpenEventW(SYNCHRONIZE, FALSE, EVENT_NAME);

	if (NULL == hProcessEvent)
	{
		printf(" OpenEventW:%x\n", GetLastError());
		return -1;
	}
	while (TRUE)
	{
		WaitForSingleObject(hProcessEvent, INFINITE); //等待事件
		DWORD dwRetSize = 0;
		BOOL bResult = FALSE;
		bResult = DeviceIoControl(
			hDriver,
			IOCTL_PROCESS_LOCK_READ,
			NULL,
			0,
			&pmdInfoNow,
			sizeof(pmdInfoNow),
			&dwRetSize,
			NULL);
		if (dwRetSize == 0)
		{
			printf("DeviceIoControl:%x\n", GetLastError());
			return 0;
		}

		if (pmdInfoNow.hProcessId != 0 && strlen(pmdInfoNow.szProcessName) != 0 && pmdInfoNow.hParentId != 0 && strlen(pmdInfoNow.szParentProcessName) != 0)
		{
			DWORD dwThreadId = 0;
			if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, &pmdInfoNow, 0, &dwThreadId) == NULL)
			{
				printf("[!]CreateThread:%d\n", GetLastError());
			}
		}
	}

	CloseHandle(hDriver);
	return 0;
}