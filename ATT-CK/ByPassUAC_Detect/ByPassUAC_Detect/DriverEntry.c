#include "DriverEntry.h"

UNICODE_STRING g_uSymbolicLinkName = { 0 };
PDEVICE_OBJECT g_pDeviceObject = NULL;

//卸载驱动.关闭符号链接
void DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS ntStatus;
	UNICODE_STRING SymboLicLinkStr = { 0 };
	ntStatus = RtlUnicodeStringInit(&SymboLicLinkStr, DEVICE_LINK_NAME);
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = IoDeleteSymbolicLink(&SymboLicLinkStr);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("IoDeleteSymbolicLink:%d", ntStatus);
		}
	}

	IoDeleteDevice(pDriverObject->DeviceObject);
	PsSetCreateProcessNotifyRoutineEx(pfnCreateProcessRoutine, TRUE);
}

void pfnCreateProcessRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	if (CreateInfo != NULL)
	{
		PDEVICE_EXTEN pDeviceExten = (PDEVICE_EXTEN)g_pDeviceObject->DeviceExtension;
		pDeviceExten->hProcessId = ProcessId;
		pDeviceExten->hParentId = CreateInfo->ParentProcessId;

		//获取父进程的进程名
		PEPROCESS pParentEprocess = NULL;
		ntStatus = PsLookupProcessByProcessId(pDeviceExten->hParentId, &pParentEprocess);
		if (pParentEprocess != NULL)
		{
			PCHAR tmpParentProcessName = PsGetProcessImageFileName(pParentEprocess);
			if (strlen(tmpParentProcessName) != 0)
			{
				RtlZeroMemory(pDeviceExten->szParentProcessName, MAX_PATH);
				RtlCopyMemory(pDeviceExten->szParentProcessName, tmpParentProcessName, strlen(tmpParentProcessName));
				//pDeviceExten->szParentProcessName[strlen(tmpParentProcessName) + 1] = '\0';
			}	
		}
		
		ANSI_STRING asProcessName;
		if (RtlUnicodeStringToAnsiString(&asProcessName, CreateInfo->ImageFileName, TRUE) == STATUS_SUCCESS)
		{
			RtlZeroMemory(pDeviceExten->szProcessName, MAX_PATH);
			RtlCopyMemory(pDeviceExten->szProcessName, asProcessName.Buffer,asProcessName.Length);
			//pDeviceExten->szProcessName[asProcessName.Length + 1] = '\0';
		}
		KeSetEvent(pDeviceExten->pkProcessEvent, 0, FALSE);
		KeResetEvent(pDeviceExten->pkProcessEvent);
	}
}

NTSTATUS DisPatchComd(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}


NTSTATUS SendToR3(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION pIrpStack;
	PVOID pUserOutPutBuffer;
	PPROCESS_LONNK_READDATA pReadData;
	ULONG uIoControl = 0;
	ULONG uReadLength;
	ULONG uWriteLeng;
	PDEVICE_EXTEN pDeviceExten;

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	pUserOutPutBuffer = pIrp->AssociatedIrp.SystemBuffer; //如果控制码是缓冲区方式.就使用这个.

	//定义读取的数据
	pReadData = (PPROCESS_LONNK_READDATA)pUserOutPutBuffer;
	uIoControl = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	uReadLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uWriteLeng = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	//其实最好应该采用这种通信的方式
	switch (uIoControl)
	{
		case IOCTL_PROCESS_LOCK_READ:
			//拷贝数据
			pDeviceExten = (PDEVICE_EXTEN)g_pDeviceObject->DeviceExtension;
			pReadData->hProcessId = pDeviceExten->hProcessId;
			pReadData->hParentId = pDeviceExten->hParentId;
			RtlZeroMemory(pReadData->szParentProcessName, MAX_PATH);
			RtlCopyMemory(pReadData->szParentProcessName, pDeviceExten->szParentProcessName, strlen(pDeviceExten->szParentProcessName));
			RtlZeroMemory(pReadData->szProcessName, MAX_PATH);
			RtlCopyMemory(pReadData->szProcessName, pDeviceExten->szProcessName, strlen(pDeviceExten->szProcessName));
			break;
		default:
			ntStatus = STATUS_INVALID_PARAMETER;
			uWriteLeng = 0;
			break;
	}

	pIrp->IoStatus.Information = uWriteLeng;
	pIrp->IoStatus.Status = ntStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING RegistryPath)
{
	//推出
	pDriverObject->DriverUnload = DriverUnload;

	// 创建设备对象
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING  DeviceObjectName = { 0 };
	PDEVICE_OBJECT  pDeviceObject = NULL;
	ntStatus = RtlUnicodeStringInit(&DeviceObjectName, DEVICE_OBJECT_NAME);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlUnicodeStringInit DeviceObjectName :%d", ntStatus);
		return ntStatus;
	}
	ntStatus = IoCreateDevice(
		pDriverObject,
		sizeof(DEVICE_EXTEN),//使用设备扩展.指定大小.那么设备对象中成员就会指向这块内存
		&DeviceObjectName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,                //独占设备
		&pDeviceObject);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice:%d",ntStatus);
		return ntStatus;
	}

	pDriverObject->Flags |= DO_BUFFERED_IO;
	g_pDeviceObject = pDeviceObject;

	//创建设备连接
	UNICODE_STRING  DeviceLinkName = { 0 };
	ntStatus = RtlUnicodeStringInit(&DeviceLinkName, DEVICE_LINK_NAME);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlUnicodeStringInit DeviceLinkName :%d", ntStatus);
		return ntStatus;
	}
	ntStatus = IoCreateSymbolicLink(&DeviceLinkName, &DeviceObjectName);
	if (!NT_SUCCESS(ntStatus))
	{
		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink :%d",ntStatus);
		return ntStatus;
	}
	
	//创建事件
	UNICODE_STRING EventName = { 0 };
	ntStatus = RtlUnicodeStringInit(&EventName, IBINARY_EVENTNAME);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("RtlUnicodeStringInit EventName :%d", ntStatus);
		return ntStatus;
	}
	PDEVICE_EXTEN pDeviceExten = (PDEVICE_EXTEN)pDeviceObject->DeviceExtension;
	if (pDeviceExten == NULL)
	{
		DbgPrint("pDeviceExten Failed");
		return ntStatus;
	}
	pDeviceExten->pkProcessEvent = IoCreateNotificationEvent(&EventName, &pDeviceExten->hProcessId);
	KeClearEvent(pDeviceExten->pkProcessEvent);

	//设置进程回调
	ntStatus = PsSetCreateProcessNotifyRoutineEx(pfnCreateProcessRoutine, FALSE); //FASLE为注册
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("PsSetCreateProcessNotifyRoutine :%d", ntStatus);
		IoDeleteDevice(pDeviceObject);
		return ntStatus;
	}



	//初始化派遣函数
	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DisPatchComd;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SendToR3;



	return ntStatus;
}