#include <ntifs.h>
#include <ntstrsafe.h>

#define LIST_OFFSET 0xB8
#define PID_OFFSET 0xB4
#define NAME_OFFSET 0x16C
#define PEB_OFFSET 0x1A8
#define LDR_OFFSET 0x0C


typedef struct _PEB_LDR_DATA
{
	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;

} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _FUNCADDR
{
	ULONG fnDetourRemoteCreateInstanceShellcode_Addr;
	ULONG JmpBackAddr;
}FUNCADDR, *PFUNCADDR;

typedef struct _LDR_DATA_TABLE_ENTRY
{

	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	ULONG TimeDateStamp;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;



typedef struct _HookData
{
 //   UCHAR OldFunctionByte[5];               //保存原函数前5个字节
	//UCHAR NewFunctionByte[5];
	PUCHAR OldFunctionByte;
	PUCHAR NewFunctionByte;
	ULONG TargetFunctionAddr;          //原函数地址
	ULONG JmpBackAddr;		           //回跳到原函数中的地址
	ULONG pfnTrampolineFun;	           //调用原始函数的通道
	ULONG pfnDetourFun;		           //HOOK过滤函数
}HOOKDATA,*PHOOKDATA;


#define DEVICE_LINK_NAME    L"\\DosDevices\\BufferedIODevcieLinkName"
#define DEVICE_OBJECT_NAME  L"\\Device\\BufferedIODeviceObjectName"
#define CTL_SYS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define CODE_READ CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define CODE_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)


HRESULT HookRemoteCretaeInstance(ULONG ulPidOfrpcss);
HRESULT InstallHook(PVOID pFunctionAddr_RemoteCreateInstance, PEPROCESS pEprocessOfRpcss);
VOID WPOFF();
VOID WPON(); 
NTSTATUS CreateCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp);
NTSTATUS ReadCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp);
NTSTATUS CloseCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp);
VOID UninstallHook();





HRESULT _DetourRemoteCreateInstance(
	ULONG       hRpc,
	ULONG       *ORPCthis,
	ULONG       *ORPCthat,
	IN  ULONG   *pUnk,
	IN  ULONG   *pInActProperties,
	OUT ULONG   ** ppOutActProperties
	);
