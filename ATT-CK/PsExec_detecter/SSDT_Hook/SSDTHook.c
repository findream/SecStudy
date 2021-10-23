#include <ntddk.h>
#include "SSDTHook.h"
#include "SSDTHook_Index.h"


//进行SSDTHook
extern PVOID pSSDTFunctionAddress = NULL;   //全局的无类型指针
BOOLEAN SSDTFunctionHook(PCHAR FunctionName,PVOID DetourFunction)
{
	//获取原始SSDT函数地址
	ULONG ulSSDTFunctionIndex = 0;
	pSSDTFunctionAddress = GetSSDTFunctionAddress(FunctionName, &ulSSDTFunctionIndex);
	if (pSSDTFunctionAddress == NULL)
	{
		DbgPrint("GetSSDTFunctionAddress Error");
		return FALSE;
	}

	//取消写保护
	NTSTATUS ntStatusWritringProtect = CancelWriteProtect();
	if (ntStatusWritringProtect != STATUS_SUCCESS)
	{
		DbgPrint("CancelWriteProtect Error");
		return FALSE;
	}

	//修改SSDT
	KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex] = DetourFunction;

	//设置写保护
	ntStatusWritringProtect = SetWriteProtect();
	if (ntStatusWritringProtect != STATUS_SUCCESS)
	{
		DbgPrint("SetWriteProtect Error");
		return FALSE;
	}
}

PVOID GetSSDTFunctionAddress(PCHAR FunctionName, PULONG ulOutSSDTFunctionIndex)
{
	//获取对应函数的SSDT索引号
	UNICODE_STRING ustrDllFileName;
	RtlInitUnicodeString(&ustrDllFileName, L"\\??\\C:\\Windows\\System32\\ntdll.dll");
	ULONG ulSSDTFunctionIndex = 0;
	ulSSDTFunctionIndex = GetSSDTFunctionIndex(ustrDllFileName, FunctionName);
	if (ulSSDTFunctionIndex == 0)
	{
		DbgPrint("SSDTFunctionIndex Error");
		return NULL;
	}
	*ulOutSSDTFunctionIndex = ulSSDTFunctionIndex;
	DbgPrint("SSDTFunctionIndex：%X%x", ulSSDTFunctionIndex);
	

	//获取Function的地址
	PVOID FunctionAddress = NULL;
#ifdef _WIN64
	FunctionAddress = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex]>>4;
	FunctionAddress = (PVOID)(KeServiceDescriptorTable.ServiceTableBase + FunctionAddress);
#else
	FunctionAddress = (PVOID)KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex];
#endif

	if (FunctionAddress == NULL)
	{
		return FunctionAddress;
	}
	DbgPrint("%s:%x", FunctionName, FunctionAddress);
	return FunctionAddress;

}

NTSTATUS CancelWriteProtect()
{

	_asm
	{
		cli;//将处理器标志寄存器的中断标志位清0，不允许中断
		mov eax, cr0
	    and  eax, ~0x10000 // 0x10000 = 10000000000000000
		mov cr0, eax
	};
	//保存原有的 CRO 属性 
	return STATUS_SUCCESS;
}

NTSTATUS SetWriteProtect()
{
	_asm
	{
		mov  eax, cr0
		or   eax, 0x10000
		mov  cr0, eax
		sti
	}
}
