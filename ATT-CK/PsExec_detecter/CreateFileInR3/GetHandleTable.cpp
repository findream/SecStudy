// GetHandleTable.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "GetHandleTable.h"

//ȫ�ֱ���
pfnNtQuerySystemInformation ZwQuerySystemInformation;
pfnNtQueryObject ZwQueryObject;
pfnNtQueryInformationProcess ZwQueryInformationProcess;
HANDLEINFO HandleInfoArray[1024];


// ������Ȩ
bool EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if( !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) )
	{
		return   FALSE;
	}
	if( !LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue) )
	{
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if( !AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL) )
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}

//��ʼ��δ�ĵ�������
BOOL InitUnDocumentProc()
{
	HMODULE hNtdll = GetModuleHandle("Ntdll.dll");
	if( hNtdll == NULL )	return FALSE;

	ZwQuerySystemInformation = 
		(pfnNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	ZwQueryObject = 
		(pfnNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
	ZwQueryInformationProcess = 
		(pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if( (ZwQuerySystemInformation == NULL) || 
		(ZwQueryObject == NULL) || 
		(ZwQueryInformationProcess == NULL) )
		return FALSE;
	return TRUE;
}


DWORD GetHanldeTable(DWORD dwPid)
{
	EnableDebugPrivilege();
	InitUnDocumentProc();
	NTSTATUS Status;
	HANDLE hSource = NULL;
	HANDLE hDuplicate = NULL;
	DWORD HandleCount;
	OBJECT_NAME_INFORMATION *ObjectName;
	OBJECT_TYPE_INFORMATION *ObjectType;
	char BufferForObjectName[1024];
	char BufferForObjectType[1024];
	DWORD HandleArrayCount = 0;


	hSource = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, dwPid);
	if (hSource != NULL)
	{
		DWORD dwHandle;

		Status = ZwQueryInformationProcess(hSource, ProcessHandleCount, &HandleCount, sizeof(HandleCount), NULL);

		for (DWORD i = 1; i <= HandleCount; i++)//��پ��
		{
			dwHandle = i * 4;
			if (DuplicateHandle(hSource, //����һ��������� && �жϴ˾���Ƿ���Ч
				(HANDLE)dwHandle,
				GetCurrentProcess(),
				&hDuplicate,
				0, FALSE, DUPLICATE_SAME_ACCESS))
			{
				ZeroMemory(BufferForObjectName, 1024);
				ZeroMemory(BufferForObjectType, 1024);

				//��ȡ�������
				Status = ZwQueryObject(hDuplicate,
					ObjectTypeInformation,
					BufferForObjectType,
					sizeof(BufferForObjectType),
					NULL);

				ObjectType = (OBJECT_TYPE_INFORMATION*)BufferForObjectType;
				if (Status == STATUS_INFO_LENGTH_MISMATCH || !NT_SUCCESS(Status))
					continue;

				//��ȡ�����
				Status = ZwQueryObject((HANDLE)hDuplicate,
					ObjectNameInformation,
					BufferForObjectName,
					sizeof(BufferForObjectName),
					NULL);


				ObjectName = (POBJECT_NAME_INFORMATION)BufferForObjectName;
				if (Status == STATUS_INFO_LENGTH_MISMATCH || !NT_SUCCESS(Status))
					continue;

				PWCHAR HandleType_File = L"File";
				CHAR cObjectName[MAX_PATH] = { 0 };
				if (wcscmp((PWCHAR)ObjectType->TypeName.Buffer, HandleType_File) == 0)
				{

					wsprintfA(cObjectName, "%S", (PWCHAR)ObjectName->Name.Buffer);
					if (strstr(cObjectName, "\\Device\\NamedPipe"))
					{
						printf("[*]Type:%ls|Name:%ls|Handle:%X\n", ObjectType->TypeName.Buffer, ObjectName->Name.Buffer, (DWORD)dwHandle);
						return TRUE;
					}

				}
				//printf("Type:%ls|Name:%ls|Handle:%X\n", ObjectType->TypeName.Buffer,
				//	ObjectName->Name.Buffer, (DWORD)dwHandle);
				//wcsncpy(HandleInfoArray[HandleArrayCount].usHandleType, (PWCHAR)ObjectType->TypeName.Buffer, ObjectType->TypeName.Length);
				//wcsncpy(HandleInfoArray[HandleArrayCount].usHandleName, (PWCHAR)ObjectName->Name.Buffer, ObjectName->Name.Length);
				//HandleInfoArray[HandleArrayCount].ulHandle = dwHandle;
				HandleArrayCount++;
			}
		}
		CloseHandle(hSource);
	}
	return FALSE;
}

