#include <ntddk.h>
#include <ntimage.h>


// 直接获取 SSDT 
//extern SSDTEntry __declspec(dllimport)KeServiceDescriptorTable;

ULONG GetSSDTFunctionIndex(UNICODE_STRING ustrDllFileName, PCHAR pszFunctionName);
NTSTATUS DllFileMap(UNICODE_STRING ustrDllFileName, HANDLE *phFile, HANDLE *phSection, PVOID *ppBaseAddress);
ULONG GetIndexFromExportTable(PVOID pBaseAddress, PCHAR pszFunctionName);