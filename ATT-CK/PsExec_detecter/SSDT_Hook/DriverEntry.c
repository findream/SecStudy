//#include <ntddk.h>
#include "SSDTHook_Index.h"
#include "SSDTHook.h"
#include "DriverEntry.h"

//https://www.kanxue.com/chm.htm?id=14600&pid=node1000843
//https://www.kanxue.com/chm.htm?id=12050&pid=node1000843
//https://www.kanxue.com/chm.htm?id=13131&pid=node1000843

NTSTATUS NTAPI NewZwCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PVOID Parameter9,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
	);


ULONG upPid = 0;

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess = NULL;


VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING  DeviceLinkName;
	PDEVICE_OBJECT  v1 = NULL;
	PDEVICE_OBJECT  DeleteDeviceObject = NULL;

	RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);
	IoDeleteSymbolicLink(&DeviceLinkName);

	DeleteDeviceObject = DriverObject->DeviceObject;
	while (DeleteDeviceObject != NULL)
	{
		v1 = DeleteDeviceObject->NextDevice;
		IoDeleteDevice(DeleteDeviceObject);
		DeleteDeviceObject = v1;
	}
}

//创建例程
NTSTATUS CreateCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;     //LastError()
	Irp->IoStatus.Information = 0;             //ReturnLength
	IoCompleteRequest(Irp, IO_NO_INCREMENT);   //将Irp返回给Io管理器
	return STATUS_SUCCESS;
}

//R0-->R3
NTSTATUS ReadCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp)
{
	DbgBreakPoint();
	if (upPid != 0)
	{
		
		PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
		ULONG length = stack->Parameters.Read.Length;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = length;
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &upPid, sizeof(HANDLE));
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}
	return STATUS_SUCCESS;

}

//关闭例程
NTSTATUS CloseCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;     //LastError()
	Irp->IoStatus.Information = 0;             //ReturnLength
	IoCompleteRequest(Irp, IO_NO_INCREMENT);   //将Irp返回给Io管理器
	return STATUS_SUCCESS;
}


PVOID pSSDTFunctionAddress;
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	DbgBreakPoint();

	SSDTFunctionHook("ZwCreateUserProcess", NewZwCreateUserProcess);


	// 创建设备对象
	UNICODE_STRING  DeviceObjectName;
	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT  DeviceObject = NULL;

	RtlInitUnicodeString(&DeviceObjectName, DEVICE_OBJECT_NAME);
	Status = IoCreateDevice(pDriverObject,
		0,
		&DeviceObjectName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		TRUE,
		&DeviceObject);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("IoCreateDevice");
		return Status;
	}

	//创建设备连接
	UNICODE_STRING  DeviceLinkName;
	RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);
	Status = IoCreateSymbolicLink(&DeviceLinkName, &DeviceObjectName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(DeviceObject);
		DbgPrint("IoCreateSymbolicLink");
		return Status;
	}

	DeviceObject->Flags |= DO_BUFFERED_IO;

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCallBack;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCallBack;
	pDriverObject->MajorFunction[IRP_MJ_READ] = ReadCallBack;

	pDriverObject->DriverUnload = DriverUnload;
	return Status;


}

NTSTATUS NTAPI NewZwCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG CreateProcessFlags,
	IN ULONG CreateThreadFlags,
	IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
	IN PVOID Parameter9,
	IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
	)
{
	
	NTSTATUS ntStatus = FALSE;
	pFnNtCreateUserProcess OldCreateUserProcess = pSSDTFunctionAddress;
	if (ProcessParameters->StandardInput != NULL && ProcessParameters->StandardOutput != NULL && ProcessParameters->StandardError != NULL)
	{
		DbgBreakPoint();
		ntStatus = OldCreateUserProcess(ProcessHandle,
			ThreadHandle,
			ProcessDesiredAccess,
			ThreadDesiredAccess,
			ProcessObjectAttributes,
			ThreadObjectAttributes,
			CreateProcessFlags,
			CreateThreadFlags,
			ProcessParameters,
			Parameter9,
			AttributeList);
		if (*ProcessHandle != NULL)
		{
			DbgBreakPoint();
			PROCESS_BASIC_INFORMATION pbi;

			UNICODE_STRING routineName;
			RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
			ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
			ntStatus = ZwQueryInformationProcess(*ProcessHandle, 0, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
			if (!ntStatus)
			{
				upPid = pbi.InheritedFromUniqueProcessId;
			}
		}
		
		return ntStatus;

		//将结果返回到R3
	}

	return OldCreateUserProcess(ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		CreateProcessFlags,
		CreateThreadFlags,
		ProcessParameters,
		Parameter9,
		AttributeList);
}