#include <windows.h>
#include <stdio.h>
#include <winnt.h>
#include <Shlobj.h>
#include <psapi.h>
#include <shlwapi.h>
#include <WinUser.h>

#include <stdlib.h>
#include <tchar.h>
#include <stdlib.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <vector>
#include <atlconv.h>
#include <wchar.h>
#include <memory>
#include <tlhelp32.h>
#pragma comment(lib, "WinTrust.Lib")
#ifdef _WIN64

#pragma comment(lib, "ShLwApi_x64.Lib")

#elif

#pragma comment(lib, "ShLwApi.Lib")

#endif // _WIN64

#pragma comment(lib, "Crypt32.Lib")

#pragma warning(disable:4996)

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessOwnerInformation,
	ProcessWindowInformation,
	ProcessHandleInformation,
	ProcessMitigationPolicy,
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount,
	ProcessRevokeFileHandles,
	ProcessWorkingSetControl,
	ProcessHandleTable,
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation,
	ProcessProtectionInformation,
	MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;


typedef LONG KPRIORITY;
typedef DWORD PPEB;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;


typedef struct _PROCESS_LONNK_READDATA
{
	HANDLE hProcessId;              //쏵넋돨PID
	TCHAR szProcessName[MAX_PATH];   //쏵넋츰
	HANDLE hParentId;                //만쏵넋PID
	TCHAR szParentProcessName[MAX_PATH]; //만쏵넋쏵넋츰
}PROCESS_LONNK_READDATA, *PPROCESS_LONNK_READDATA;


typedef NTSTATUS(WINAPI *pfnNtQueryInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out PULONG ReturnLength
	);

BOOL WorkThread(PVOID ProcessInfo);
BOOL EnablePrivilege(HANDLE hToken, LPCSTR szPrivName);
PCHAR GetProcessNameByPid(DWORD dwPid);