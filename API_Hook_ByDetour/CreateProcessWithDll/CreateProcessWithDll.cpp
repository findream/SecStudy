#include "CreateProcessWithDll.h"
#include "detours.h"
#include <shlwapi.h>
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")

BOOL CreateProcessWithDll(CHAR* szFilePathOfProcess, CHAR* szFilePathOfDll)
{
	if (szFilePathOfProcess == NULL && szFilePathOfDll == NULL)
		return FALSE;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	DWORD dwNumberOfDll = 1;
	if (DetourCreateProcessWithDll(
		NULL,
		szFilePathOfProcess,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi,
		szFilePathOfDll,
		NULL) == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

int main(int argc, char **argv)
{
	if (argc != 3)
	{
		printf("[!]argument number error\n");
		return 0;
	}
	CHAR szProcessPath[MAX_PATH] = { 0 };
	CHAR szDllPath[MAX_PATH] = { 0 };
	strcpy_s(szProcessPath, strlen(argv[1]) + 1, argv[1]);
	strcpy_s(szDllPath, strlen(argv[2]) + 1, argv[2]);
	if (strcmp(szProcessPath, "") == 0 && strcmp(szDllPath, "") == 0)
	{
		printf("[!]argument error\n");
		return 0;
	}
	if (CreateProcessWithDll(szProcessPath, szDllPath) == FALSE)
	{
		printf("[!]CreateProcessWithDll error\n");
		return 0;
	}
	return 0;




}