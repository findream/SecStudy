#include <ntddk.h>
#include <ntimage.h>

typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;		  // SSDT基址
	PULONG ServiceCounterTableBase;   // SSDT中服务被调用次数计数器
	ULONG NumberOfService;            // SSDT服务个数
	PUCHAR ParamTableBase;		      // 系统服务参数表基址
}SSDTEntry, *PSSDTEntry;



// 直接获取 SSDT 
extern SSDTEntry __declspec(dllimport) KeServiceDescriptorTable;



PULONG *pOldAttr;

/*
	@函数声明区、
*/
BOOLEAN SSDTFunctionHook(PCHAR FunctionName, PVOID DetourFunction);
NTSTATUS CancelWriteProtect();
NTSTATUS SetWriteProtect();
PVOID GetSSDTFunctionAddress(PCHAR FunctionName, PULONG ulOutSSDTFunctionIndex);

