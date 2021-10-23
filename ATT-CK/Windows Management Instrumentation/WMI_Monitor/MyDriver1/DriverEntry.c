#include "DriverEntry.h"



//HOOKDATA HookData;
extern PVOID gpFunctionAddr_RemoteCreateInstance;
extern PEPROCESS gpEprocessOfRpcss;

VOID Unload(PDRIVER_OBJECT pDriverObject)
{
	UninstallHook();
	UNICODE_STRING  DeviceLinkName;
	PDEVICE_OBJECT  v1 = NULL;
	PDEVICE_OBJECT  DeleteDeviceObject = NULL;

	RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);
	IoDeleteSymbolicLink(&DeviceLinkName);

	DeleteDeviceObject = pDriverObject->DeviceObject;
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

//R3-->R0
NTSTATUS WriteCallBack(PDEVICE_OBJECT  DeviceObject, PIRP Irp)
{
	ULONG uPid = -1;
	PCHAR pIpBuffer = NULL;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG length = stack->Parameters.Read.Length;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = length;
	if (length == 4)
	{
		RtlCopyMemory(&uPid, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG));
	}
	else if (length > 4)
	{
		pIpBuffer = ExAllocatePool(NonPagedPool,0x1D);
		RtlZeroMemory(pIpBuffer, 0x1D);
		RtlCopyMemory(pIpBuffer, Irp->AssociatedIrp.SystemBuffer, 0x1D);
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	if (uPid != -1)
	{
		HookRemoteCretaeInstance(uPid);
	}
	else if (pIpBuffer != NULL)
	{
		//解析数据
		DbgPrint("[!]检测到针对%ls的WMI远程访问", pIpBuffer);
		DbgPrint("[!]已自动阻止");
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



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
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
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = WriteCallBack;

	pDriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;

}


