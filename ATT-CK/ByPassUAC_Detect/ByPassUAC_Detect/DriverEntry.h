#include <ntddk.h>
#include <ntstrsafe.h>
/*
@ ͨѶ
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

//�豸���豸֮��ͨ��
#define DEVICE_OBJECT_NAME  L"\\Device\\BufferedIODeviceObjectName"
#define DEVICE_LINK_NAME    L"\\DosDevices\\BufferedIODevcieLinkName"
#define  IBINARY_EVENTNAME       L"\\BaseNamedObjects\\ProcLook"


//������������Ϣ
//�Զ����豸��չ.�Լ�ȫ�ֱ���ָ��.���б����.
#define MAX_PATH  260

typedef struct _Device_Exten
{
	/*
	�����������ID�ͽ�����
	*/
	PKEVENT pkProcessEvent;          //ȫ���¼�����,ring3ʹ��
	HANDLE  hProcessId;              //���̵�PID
	TCHAR szProcessName[MAX_PATH];   //������
	HANDLE hParentId;                //������PID
	TCHAR szParentProcessName[MAX_PATH]; //�����̽�����
}DEVICE_EXTEN, *PDEVICE_EXTEN;

typedef struct _PROCESS_LONNK_READDATA
{
	HANDLE  hProcessId;              //���̵�PID
	TCHAR szProcessName[MAX_PATH];   //������
	HANDLE hParentId;                //������PID
	TCHAR szParentProcessName[MAX_PATH]; //�����̽�����
}PROCESS_LONNK_READDATA, *PPROCESS_LONNK_READDATA;



//��������
void pfnCreateProcessRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
	);
NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
