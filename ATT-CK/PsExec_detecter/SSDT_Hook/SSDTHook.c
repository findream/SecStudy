#include <ntddk.h>
#include "SSDTHook.h"
#include "SSDTHook_Index.h"


//����SSDTHook
extern PVOID pSSDTFunctionAddress = NULL;   //ȫ�ֵ�������ָ��
BOOLEAN SSDTFunctionHook(PCHAR FunctionName,PVOID DetourFunction)
{
	//��ȡԭʼSSDT������ַ
	ULONG ulSSDTFunctionIndex = 0;
	pSSDTFunctionAddress = GetSSDTFunctionAddress(FunctionName, &ulSSDTFunctionIndex);
	if (pSSDTFunctionAddress == NULL)
	{
		DbgPrint("GetSSDTFunctionAddress Error");
		return FALSE;
	}

	//ȡ��д����
	NTSTATUS ntStatusWritringProtect = CancelWriteProtect();
	if (ntStatusWritringProtect != STATUS_SUCCESS)
	{
		DbgPrint("CancelWriteProtect Error");
		return FALSE;
	}

	//�޸�SSDT
	KeServiceDescriptorTable.ServiceTableBase[ulSSDTFunctionIndex] = DetourFunction;

	//����д����
	ntStatusWritringProtect = SetWriteProtect();
	if (ntStatusWritringProtect != STATUS_SUCCESS)
	{
		DbgPrint("SetWriteProtect Error");
		return FALSE;
	}
}

PVOID GetSSDTFunctionAddress(PCHAR FunctionName, PULONG ulOutSSDTFunctionIndex)
{
	//��ȡ��Ӧ������SSDT������
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
	DbgPrint("SSDTFunctionIndex��%X%x", ulSSDTFunctionIndex);
	

	//��ȡFunction�ĵ�ַ
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
		cli;//����������־�Ĵ������жϱ�־λ��0���������ж�
		mov eax, cr0
	    and  eax, ~0x10000 // 0x10000 = 10000000000000000
		mov cr0, eax
	};
	//����ԭ�е� CRO ���� 
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
