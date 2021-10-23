#include <stdio.h>
#include <windows.h>
#include "detours.h"
#include <shlwapi.h>
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")


BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) 
{
	switch (ul_reason_for_call) 
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL,"test","DLL_PROCESS_ATTACH",MB_OK);
		break;
	case DLL_PROCESS_DETACH:
		MessageBoxA(NULL, "test", "DLL_PROCESS_ATTACH", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}