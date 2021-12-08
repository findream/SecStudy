#include <ntddk.h>
#include <ntstrsafe.h>
/*
@ 通讯
*/
//#define CTL_SYS \
//	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
//
//#define CODE_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
//#define CODE_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CTRLCODE_BASE 0x8000
#define MYCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, CTRLCODE_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCESS_LOCK_READ MYCTRL_CODE(1)

//设备与设备之间通信
#define DEVICE_OBJECT_NAME  L"\\Device\\BufferedIODeviceObjectName"
#define DEVICE_LINK_NAME    L"\\DosDevices\\BufferedIODevcieLinkName"
#define  IBINARY_EVENTNAME       L"\\BaseNamedObjects\\ProcLook"


//保存进程相关信息
//自定义设备扩展.以及全局变量指针.进行保存的.
#define MAX_PATH  260

typedef struct _Device_Exten
{
	/*
	仅仅保存进程ID和进程名
	*/
	PKEVENT pkProcessEvent;          //全局事件对象,ring3使用
	HANDLE  hProcessId;              //进程的PID
	TCHAR szProcessName[MAX_PATH];   //进程名
	HANDLE hParentId;                //父进程PID
	TCHAR szParentProcessName[MAX_PATH]; //父进程进程名
}DEVICE_EXTEN, *PDEVICE_EXTEN;

typedef struct _PROCESS_LONNK_READDATA
{
	HANDLE  hProcessId;              //进程的PID
	TCHAR szProcessName[MAX_PATH];   //进程名
	HANDLE hParentId;                //父进程PID
	TCHAR szParentProcessName[MAX_PATH]; //父进程进程名
}PROCESS_LONNK_READDATA, *PPROCESS_LONNK_READDATA;



//函数声明
void pfnCreateProcessRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
	);
NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
