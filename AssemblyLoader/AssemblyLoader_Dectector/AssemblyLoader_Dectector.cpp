#include "..\packages\krabsetw_x64-windows\include\krabs.hpp"
#include <iostream>
#include <tlhelp32.h>
#include <locale.h>
#include <windows.h>
#include <stdio.h>
#include <evntrace.h>
#include <evntcons.h>
#include <Tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include <vector>
#pragma warning(disable:4996)
#pragma comment(lib,"Shlwapi.lib")

#define LoaderKeyword 0x8
#define StartEnumerationKeyword 0x40
#define AssemblyDCStart 155

std::vector<DWORD> pids;

BOOL DetectByMemory(HANDLE hProcess);
BOOL SetConsoleColor(WORD wAttributes);

typedef struct _ProcessInfo
{
	DWORD dwPID;				// 进程ID
	WCHAR szExeFile[MAX_PATH];
}ProcessInfo, *PProcessInfo;

BOOL Monitor(DWORD dwPid)
{
	WCHAR szExeFile[MAX_PATH] = { 0 };
	DWORD dwSize = MAX_PATH;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
	QueryFullProcessImageNameW(hProcess, 0, szExeFile, &dwSize);
	BOOL bIsExecuteAssembly = DetectByMemory(hProcess);
	if (bIsExecuteAssembly == TRUE)
	{
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_BLUE);
		printf("[%d] : %s is execute-Assembly(.Net Load Memory)\n", dwPid, szExeFile);
		SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
	return TRUE;
}

void DetectByETW()
{
	auto assembly_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context)
	{

		krabs::schema schema(record, trace_context.schema_locator);
		krabs::parser parser(schema);
		pids.push_back(record.EventHeader.ProcessId);

		//std::wcout << L" ProcessId=" << record.EventHeader.ProcessId;
		//std::wcout << L" EventId=" << schema.event_id();
		//std::wstring image_name = parser.parse<std::wstring>(L"ImageName");
		//std::wcout << L" ImageName=" << image_name;
		//std::wcout << std::endl;
		DWORD dwPid = record.EventHeader.ProcessId;
		WCHAR szExeFile[MAX_PATH] = { 0 };
		DWORD dwSize = MAX_PATH;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
		QueryFullProcessImageNameW(hProcess, 0, szExeFile, &dwSize);
		BOOL bIsExecuteAssembly = DetectByMemory(hProcess);
		if (bIsExecuteAssembly == TRUE)
		{
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_BLUE);
			printf("[%d] : %ls is execute-Assembly(.Net Load Memory)\n", dwPid, szExeFile);
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
		else
		{
			printf("[%d] : %ls\n", dwPid, szExeFile);
		}
		return TRUE;

	};


	krabs::user_trace trace(L"user_trace_008");
	krabs::provider<> dotnet_rundown_provider(L".NET Common Language Runtime");  //L".NET Common Language Runtime"

																				 //dotnet_rundown_provider.any(0x08 | 0x010 | 0x40 | 0x0000000200000000);
	dotnet_rundown_provider.any(0x0000000200000000);

	//krabs::predicates::id_is eventid = krabs::predicates::id_is(155);
	//krabs::predicates::version_is version = krabs::predicates::version_is(0);
	//krabs::event_filter assembly_rundown_filter(
	//	krabs::predicates::any_of({
	//		&eventid,
	//		&version}));

	//krabs::event_filter assembly_rundown_filter(krabs::predicates::version_is(4));
	//assembly_rundown_filter.add_on_event_callback(assembly_callback);
	//dotnet_rundown_provider.add_filter(assembly_rundown_filter);
	dotnet_rundown_provider.add_on_event_callback(assembly_callback);
	trace.enable(dotnet_rundown_provider);
	trace.start();

}


BOOL AdjustPrivileges()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES oldtp;
	DWORD dwSize = sizeof(TOKEN_PRIVILEGES);
	LUID luid;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);


	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		OutputDebugStringA("提升权限失败,LookupPrivilegeValue");
		return FALSE;
	}
	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize)) {
		CloseHandle(hToken);
		OutputDebugStringA("提升权限失败 AdjustTokenPrivileges");
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

DWORD EnumModulesHandle(HANDLE hProcess, HMODULE **lpModule)
{
	DWORD cbBytesNeeded = 0;
	// 备注：EnumProcessModules 函数无法枚举64位进程的模块，除非程序以64位编译
	EnumProcessModulesEx(hProcess, NULL, 0, &cbBytesNeeded, LIST_MODULES_ALL); // 计算数组大小
	*lpModule = (HMODULE *)malloc(cbBytesNeeded + 0x1000);
	EnumProcessModulesEx(hProcess, *lpModule, cbBytesNeeded + 0x1000, &cbBytesNeeded, LIST_MODULES_ALL); // 枚举模块句柄
	return cbBytesNeeded / sizeof(HMODULE);
}

BOOL DetectByMemory(HANDLE hProcess)
{
	UCHAR SignMemory[] = { 0x54,0x68,0x69,0x73,0x20,0x70,0x72,0x6F,0x67,0x72,0x61,0x6D,0x20,0x63,0x61,0x6E,0x6E,0x6F,0x74,0x20,0x62,0x65,0x20,0x72,0x75,0x6E,0x20,0x69,0x6E,0x20,0x44,0x4F,0x53,0x20,0x6D,0x6F,0x64,0x65 };
	BOOL bIsExecuteFile = FALSE;
	if (NULL == hProcess)
		return bIsExecuteFile;
	SYSTEM_INFO sysInfo = { 0 };
	GetSystemInfo(&sysInfo);
	MEMORY_BASIC_INFORMATION pMemInfo = { 0 };
	DWORD dwErrorCode;

	BOOL IsWow64 = FALSE;
	if (IsWow64Process(hProcess, &IsWow64) == FALSE)
		return bIsExecuteFile;
	DWORD64 dwLastAddr = (IsWow64 == TRUE) ? 0x700000 : 0x700000000000;


	for (DWORD64 MemoryAddress = (DWORD64)sysInfo.lpMinimumApplicationAddress; MemoryAddress < (DWORD64)dwLastAddr; MemoryAddress += pMemInfo.RegionSize) //0x7ff4e85d0000   0x70000000
	{
		if (bIsExecuteFile == TRUE)
			break;
		if (VirtualQueryEx(hProcess, (LPVOID)MemoryAddress, &pMemInfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
			break;

		if ((pMemInfo.Type == MEM_COMMIT || pMemInfo.Type == MEM_PRIVATE) && pMemInfo.Protect == PAGE_READWRITE) //
		{
			PVOID pMemoryBuffer = malloc(pMemInfo.RegionSize + 1);
			memset(pMemoryBuffer, 0, pMemInfo.RegionSize + 1);
			SIZE_T dwReturnNumber = 0;
			if (ReadProcessMemory(hProcess, pMemInfo.BaseAddress, pMemoryBuffer, pMemInfo.RegionSize, &dwReturnNumber) == FALSE)
			{
				printf("[!] ReadProcessMemory Failed\n");
				free(pMemoryBuffer);
				pMemoryBuffer = NULL;
				continue;
			}
			for (DWORD64 dwIndex = 0; dwIndex < pMemInfo.RegionSize + 1; dwIndex++)
			{
				if ((memcmp((PVOID)((DWORD64)pMemoryBuffer + dwIndex), SignMemory, sizeof(SignMemory)) == 0) &&
					(memcmp((PVOID)((DWORD64)pMemoryBuffer + dwIndex - 0x4E), "MZ", 2) == 0))
				{
					bIsExecuteFile = TRUE;
					break;
				}
			}
			free(pMemoryBuffer);
			pMemoryBuffer = NULL;
		}
	}

	return bIsExecuteFile;

}

BOOL SetConsoleColor(WORD wAttributes)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE)
		return FALSE;

	return SetConsoleTextAttribute(hConsole, wAttributes);
}


int main()
{
	pids.clear();
	//pids.push_back(7400);


	DWORD dwThreadId = 0;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DetectByETW, NULL, 0, &dwThreadId);
	if (hThread == NULL)
	{
		printf("[!] etw monitor thread start failed \n");
		return 0;
	}

	Sleep(1000 * 5);
	//遍历所有进程的所有模块
	BOOL bIsExecuteAssembly = FALSE;
	ProcessInfo processinfo = { 0 };

	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("[!] CreateToolhelp32Snapshot Failed \n");
		return 0;
	}
	BOOL bNext = Process32FirstW(hProcessSnapshot, &pe32);
	while (bNext)
	{
		bIsExecuteAssembly = FALSE;
		processinfo.dwPID = pe32.th32ProcessID;
		wcscpy(processinfo.szExeFile, pe32.szExeFile);
		DWORD dwSize = MAX_PATH;
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
		if (hProcess != NULL)
		{
			QueryFullProcessImageNameW(hProcess, 0, processinfo.szExeFile, &dwSize);
			HMODULE *lpModuleHandle = NULL;
			DWORD dwNumOfModule = EnumModulesHandle(hProcess, &lpModuleHandle);
			for (DWORD i = 0; i < dwNumOfModule; i++)
			{
				TCHAR ModuleName[MAX_PATH] = { 0 };
				if (GetModuleFileNameExW(hProcess, lpModuleHandle[i], ModuleName, MAX_PATH) != 0 && wcslen(ModuleName) != 0)
				{
					PathStripPathW(ModuleName);
					if (wcscmp(ModuleName, L"clr.dll") == 0)
					{
						//printf("存在CLR.DLL\n");
						for (DWORD index = 0; index < pids.size(); index++)
						{
							if (pids[index] == processinfo.dwPID)
							{
								//printf("processinfo.dwPID \n\n");
								if (DetectByMemory(hProcess) == TRUE)
								{
									bIsExecuteAssembly = TRUE;
									break;
								}

							}
						}

					}
				}
				if (bIsExecuteAssembly == TRUE)
					break;
			}
			CloseHandle(hProcess);
		}
		if (bIsExecuteAssembly == TRUE)
		{
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_BLUE);
			printf("[%d] : %ls is execute-Assembly(.Net Load Memory)\n", processinfo.dwPID, processinfo.szExeFile);
			SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
		}
		else
		{
			printf("[%d] : %ls\n", processinfo.dwPID, processinfo.szExeFile);
		}
		bNext = Process32Next(hProcessSnapshot, &pe32);
	}
	WaitForSingleObject(hThread, INFINITE);
	getchar();
	return 0;
}