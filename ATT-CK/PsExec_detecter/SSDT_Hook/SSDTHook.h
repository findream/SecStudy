#include <ntddk.h>
#include <ntimage.h>

typedef struct _SERVICE_DESCIPTOR_TABLE
{
	PULONG ServiceTableBase;		  // SSDT��ַ
	PULONG ServiceCounterTableBase;   // SSDT�з��񱻵��ô���������
	ULONG NumberOfService;            // SSDT�������
	PUCHAR ParamTableBase;		      // ϵͳ����������ַ
}SSDTEntry, *PSSDTEntry;



// ֱ�ӻ�ȡ SSDT 
extern SSDTEntry __declspec(dllimport) KeServiceDescriptorTable;



PULONG *pOldAttr;

/*
	@������������
*/
BOOLEAN SSDTFunctionHook(PCHAR FunctionName, PVOID DetourFunction);
NTSTATUS CancelWriteProtect();
NTSTATUS SetWriteProtect();
PVOID GetSSDTFunctionAddress(PCHAR FunctionName, PULONG ulOutSSDTFunctionIndex);

