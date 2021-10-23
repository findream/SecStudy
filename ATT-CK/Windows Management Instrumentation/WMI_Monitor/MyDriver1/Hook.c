#include "DriverEntry.h"

HOOKDATA HookData;
ULONG g_uCr0;
PVOID gpFunctionAddr_RemoteCreateInstance;
PEPROCESS gpEprocessOfRpcss;

VOID WPOFF()
{
	ULONG uAttr;
	_asm
	{
		push eax;
		mov eax, cr0;
		mov uAttr, eax;
		and eax, 0FFFEFFFFh; // CR0 16 BIT = 0 
		mov cr0, eax;
		pop eax;
		cli
	};
	g_uCr0 = uAttr; //保存原有的 CRO 屬性 
}
VOID WPON()
{
	_asm
	{
		sti
			push eax;
		mov eax, g_uCr0; //恢復原有 CR0 屬性 
		mov cr0, eax;
		pop eax;
	};
}


// 原理:遍历EPROCESS列表
PEPROCESS GetSpecialProcess(ULONG dwPid)
{
	//获取当前进程的EPROCESS
	PEPROCESS pResultEprocess = NULL;
	PEPROCESS pCurrentProcess = NULL;
	pCurrentProcess = PsGetCurrentProcess();
	if (NULL == pCurrentProcess)
	{
		DbgPrint("[!] PsGetCurrentProcess");
		return NULL;
	}

	PLIST_ENTRY pCurList = (PLIST_ENTRY)((ULONG)pCurrentProcess + LIST_OFFSET);
	PLIST_ENTRY pList = pCurList;
	PEPROCESS pEprocess = NULL;
	while (pList->Flink != pCurList)
	{
		pEprocess = (PEPROCESS)((ULONG)pList - LIST_OFFSET);
		if (pEprocess == NULL)
		{
			DbgPrint("pEprocess Error");
			continue;
		}
		ULONG ProcessId = -1;
		ProcessId = *(ULONG*)((ULONG)pEprocess + PID_OFFSET);
		if (ProcessId == -1)
		{
			DbgPrint("ProcessId Error");
			continue;
		}
		if (ProcessId == dwPid)
		{
			pResultEprocess = pEprocess;
			break;
		}
		pList = pList->Flink;
	}
	return pResultEprocess;
}

//原理:通过遍历PEB的LDR双向链表
PLDR_DATA_TABLE_ENTRY GetSpecialModule(PEPROCESS pEprocess, UNICODE_STRING usSpecialModuleName)
{
	PLDR_DATA_TABLE_ENTRY pResultLdrData = NULL;

	//因为PEB是r3下的,所以在R0必须通过KeStackAttachProcess附加
	KAPC_STATE ks;
	KeStackAttachProcess(pEprocess, &ks);


	PPEB pPeb = *(PULONG)((ULONG)pEprocess + PEB_OFFSET);
	if (!MmIsAddressValid(pPeb))
	{
		DbgPrint("[!]Peb address is notn valid");
		return pResultLdrData;
	}

	__try
	{
		PPEB_LDR_DATA Ldr = *(PULONG)((ULONG)pPeb + LDR_OFFSET);
		if (!MmIsAddressValid(Ldr))
		{
			DbgPrint("[!]Ldr address is notn valid");
			return pResultLdrData;
		}

		PLIST_ENTRY pCurrentLdrData = &Ldr->InLoadOrderModuleList;
		PLIST_ENTRY pNextLdrData = pCurrentLdrData->Flink;
		while (pCurrentLdrData != pNextLdrData)
		{
			PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)pNextLdrData;
			UNICODE_STRING usModuleName = pLdrDataEntry->BaseDllName;
			if (RtlCompareUnicodeString(&usSpecialModuleName, &usModuleName, FALSE) == 0)
			{
				pResultLdrData = pLdrDataEntry;
				break;
			}
			pNextLdrData = pNextLdrData->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[!]get module info error");
	}

	//取消附加进程
	KeUnstackDetachProcess(&ks);
	return pResultLdrData;
}


//原理:通过特征码获取地址
PVOID Get_RemoteCreateInstance_Addr(PVOID pStartAddr, PVOID pEndAddr)
{
	CHAR lpSpecialCode1[5] = { 0xBE, 0x05, 0x00, 0x07, 0x80 };
	CHAR lpSpecialCode2[5] = { 0xBE, 0x57, 0x00, 0x07, 0x80 };
	DWORD pCurrentAddr = (DWORD)pStartAddr;
	DWORD dwResultAddr = 0;
	while (pCurrentAddr < (DWORD)pEndAddr)
	{
		if ((RtlCompareMemory((PVOID)pCurrentAddr, lpSpecialCode1, 5) == 5) && (RtlCompareMemory((PVOID)(pCurrentAddr + 0x29), lpSpecialCode2, 5) == 5))
		{
			//12A0B
			dwResultAddr = (DWORD)pCurrentAddr - 0x12A0B;
			break;
		}
		pCurrentAddr = pCurrentAddr + 1;
	}
	return (PVOID)dwResultAddr;

}



HRESULT InstallHook(PVOID pFunctionAddr_RemoteCreateInstance, PEPROCESS pEprocessOfRpcss)
{
	
	//初始化HookData
	HookData.TargetFunctionAddr = pFunctionAddr_RemoteCreateInstance;
	HookData.JmpBackAddr = (ULONG)pFunctionAddr_RemoteCreateInstance + 5;
	HookData.NewFunctionByte = ExAllocatePool(NonPagedPool, 5);
	HookData.OldFunctionByte = ExAllocatePool(NonPagedPool, 5);
	RtlZeroMemory(HookData.NewFunctionByte, 5);
	RtlZeroMemory(HookData.OldFunctionByte, 5);

	//在进城中开辟空间存储shellcode
	//HookData.pfnDetourFun = _DetourRemoteCreateInstance;
	//HookData.pfnTrampolineFun = _TrampolineRemoteCreateInstance;  
	HANDLE hProcess = NULL;
	NTSTATUS ntStatus = 0;
	ntStatus = ObOpenObjectByPointer((PVOID)pEprocessOfRpcss,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		GENERIC_ALL,
		*PsProcessType,
		KernelMode,
		&hProcess
		);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("[!]ObOpenObjectByPointer hProcess Failed", ntStatus);
		return -1;
	}

	////开辟fnTrampolineFun函数的shellcode空间
	//PVOID fnTrampolineFunShellcode_Addr = NULL;
	//ULONG uSizeOfffnTrampolineFunShellcode = 0xC;
	//DbgPrint("[!]size of TrampolineFun", uSizeOfffnTrampolineFunShellcode);
	//ntStatus = ZwAllocateVirtualMemory(hProcess, &fnTrampolineFunShellcode_Addr, 0, &uSizeOfffnTrampolineFunShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//if (!NT_SUCCESS(ntStatus))
	//{
	//	DbgPrint("[!]Virtual memory for fnTrapolinefun Failed", ntStatus);
	//	return -1;
	//}
	//HookData.pfnTrampolineFun = fnTrampolineFunShellcode_Addr;

	//开辟DetourRemoteCreateInstance的空间
	PVOID fnDetourRemoteCreateInstanceShellcode_Addr = NULL;
	ULONG uSizeOffnDetourRemoteCreateInstanceShellcode = 0x200;
	ntStatus = ZwAllocateVirtualMemory(hProcess, &fnDetourRemoteCreateInstanceShellcode_Addr, 0, &uSizeOffnDetourRemoteCreateInstanceShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("[!]Virtual memory for fnDetourRemoteCreateInstance Failed", ntStatus);
		return -1;
	}
	HookData.pfnDetourFun = fnDetourRemoteCreateInstanceShellcode_Addr;



	//检查是否被Hook
	UCHAR OldFunctionByte[5] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };
	if (RtlCompareMemory((PVOID)HookData.TargetFunctionAddr, (PVOID)OldFunctionByte, 5) != 5)
	{
		DbgPrint("[!]detected target function hooked");
		return -1;
	}
	// 保存Target 函数 Bytes
	RtlCopyMemory(HookData.OldFunctionByte, pFunctionAddr_RemoteCreateInstance, 5);

	////将pfnTrampolineFun函数Shellcode写入内存
	//RtlZeroMemory(fnTrampolineFunShellcode_Addr, uSizeOfffnTrampolineFunShellcode);
	//RtlCopyMemory(fnTrampolineFunShellcode_Addr, _TrampolineRemoteCreateInstance, uSizeOfffnTrampolineFunShellcode);

	//将DetourRemoteCreateInstance函数Shellcode写入内存
	RtlZeroMemory(fnDetourRemoteCreateInstanceShellcode_Addr, uSizeOffnDetourRemoteCreateInstanceShellcode);
	RtlCopyMemory(fnDetourRemoteCreateInstanceShellcode_Addr, _DetourRemoteCreateInstance, uSizeOffnDetourRemoteCreateInstanceShellcode);


	//IRQL
	WPOFF();
	KIRQL oldIrql;
	oldIrql = KeRaiseIrqlToDpcLevel();

	//修改入口点数据
	HookData.NewFunctionByte[0] = 0xE9;
	*(ULONG*)(HookData.NewFunctionByte + 1) = (ULONG)fnDetourRemoteCreateInstanceShellcode_Addr - HookData.TargetFunctionAddr - 5;
	RtlCopyMemory(HookData.TargetFunctionAddr, HookData.NewFunctionByte, 5);

	KeLowerIrql(oldIrql);
	WPON();

	return STATUS_SUCCESS;

}


HRESULT HookRemoteCretaeInstance(ULONG ulPidOfrpcss)
{
	//=====================Hook=======================
	//获取rpcss的EPROCESS
	PEPROCESS pEprocessOfRpcss = GetSpecialProcess(ulPidOfrpcss);
	if (NULL == pEprocessOfRpcss)
	{
		DbgPrint("[!]get rpcss Eprocess Failed");
		return STATUS_SUCCESS;
	}
	gpEprocessOfRpcss = pEprocessOfRpcss;
	DbgPrint("[*]eprocess of rpcss(svchost.exe)is %x", pEprocessOfRpcss);

	//遍历进程的模块
	UNICODE_STRING usModuleNameOfRpcss = RTL_CONSTANT_STRING(L"rpcss.dll");
	PLDR_DATA_TABLE_ENTRY pModuleInfoOfRpcss = NULL;
	pModuleInfoOfRpcss = GetSpecialModule(pEprocessOfRpcss, usModuleNameOfRpcss);

	//附加进程
	KAPC_STATE ks;
	KeStackAttachProcess(pEprocessOfRpcss, &ks);

	if (!MmIsAddressValid(pModuleInfoOfRpcss))
	{
		DbgPrint("[!]Peb address is notn valid");
		return STATUS_SUCCESS;
	}

	PVOID pBaseAddr = pModuleInfoOfRpcss->DllBase;
	PVOID pEndAddr = (PVOID)((ULONG)pBaseAddr + (ULONG)(pModuleInfoOfRpcss->SizeOfImage));
	DbgPrint("[*]find special module:%Z", &pModuleInfoOfRpcss->BaseDllName);
	DbgPrint("[*]baseaddress of rpcss.dll:%x", pBaseAddr);

	//寻找 RemoteCreateInstance
	PVOID pFunctionAddr_RemoteCreateInstance = Get_RemoteCreateInstance_Addr(pBaseAddr, pEndAddr);
	if (!MmIsAddressValid(pFunctionAddr_RemoteCreateInstance))
	{
		DbgPrint("[!]find RemoteCreateInstance address failed");
		return STATUS_SUCCESS;
	}
	DbgPrint("[*]find start address of RemoteCreateInstance:%x", pFunctionAddr_RemoteCreateInstance);

	//开始Hook
	gpFunctionAddr_RemoteCreateInstance = pFunctionAddr_RemoteCreateInstance;
	if (InstallHook(pFunctionAddr_RemoteCreateInstance, pEprocessOfRpcss) != STATUS_SUCCESS)
	{
		DbgPrint("[!]Install hook failed");
		KeUnstackDetachProcess(&ks);
		return STATUS_SUCCESS;
	}

	KeUnstackDetachProcess(&ks);
	return STATUS_SUCCESS;
}


VOID UninstallHook()
{
	DbgPrint("address of _RemoteCreateInstance:%x", gpFunctionAddr_RemoteCreateInstance);

	KAPC_STATE ks;
	KeStackAttachProcess(gpEprocessOfRpcss, &ks);

	//IRQL
	WPOFF();
	KIRQL oldIrql;
	oldIrql = KeRaiseIrqlToDpcLevel();

	UCHAR OldFunctionByte[5] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };
	RtlCopyMemory(gpFunctionAddr_RemoteCreateInstance, OldFunctionByte, 5);
	KeLowerIrql(oldIrql);
	WPON();

	KeUnstackDetachProcess(&ks);
}


//Detour function
//获取Kernel32的基地址
//获取rpcss的基地址
//获取RemoteCreateInstance地址
//裸函数
__declspec(naked)
HRESULT _DetourRemoteCreateInstance(
ULONG       hRpc,
ULONG       *ORPCthis,
ULONG       *ORPCthat,
IN  ULONG   *pUnk,
IN  ULONG   *pInActProperties,
OUT ULONG   ** ppOutActProperties
)
{
	_asm
	{

		push    ebp
			mov     ebp, esp
			sub     esp, 220h
			push    ebx
			push    esi
			push    edi
			mov     dword ptr[ebp - 4], 0
			mov     dword ptr[ebp - 8], 0
			mov     dword ptr[ebp - 0Ch], 0
			mov     dword ptr[ebp - 10h], 0
			mov     dword ptr[ebp - 14h], 0
			mov     dword ptr[ebp - 18h], 0
			mov     dword ptr[ebp - 1Ch], 0
			mov     dword ptr[ebp - 20h], 0
			mov     dword ptr[ebp - 24h], 0
			mov     dword ptr[ebp - 28h], 0
			mov     dword ptr[ebp - 2Ch], 0
			mov     dword ptr[ebp - 30h], 0
			mov     dword ptr[ebp - 34h], 0
			pusha
			mov     eax, fs : [30h]
			mov[ebp - 34h], eax
			popa
			mov     dword ptr[ebp - 38h], 0
			mov     eax, [ebp - 34h]
			mov     ecx, [eax + 0Ch]
			mov[ebp - 38h], ecx
			mov     eax, [ebp - 38h]
			add     eax, 0Ch
			mov[ebp - 3Ch], eax
			mov     eax, [ebp - 3Ch]
			mov     ecx, [eax]
			mov[ebp - 40h], ecx

		loc_431BF3 :
		mov     eax, [ebp - 3Ch]
			cmp     eax, [ebp - 40h]
			jz      loc_431CFC
			cmp     dword ptr[ebp - 4], 0
			jz      short loc_431C10
			cmp     dword ptr[ebp - 8], 0
			jz      short loc_431C10
			jmp     loc_431CFC

		loc_431C10 :
		mov     eax, [ebp - 40h]
			mov[ebp - 44h], eax
			mov     eax, [ebp - 44h]
			mov     ecx, [eax + 30h]
			mov[ebp - 48h], ecx
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax]
			cmp     ecx, 6Bh
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 2]
			cmp     ecx, 65h
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 4]
			cmp     ecx, 72h
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 6]
			cmp     ecx, 6Eh
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 8]
			cmp     ecx, 65h
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 0Ah]
			cmp     ecx, 6Ch
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 0Ch]
			cmp     ecx, 33h
			jnz     short loc_431C86
			mov     eax, [ebp - 48h]
			movzx   ecx, word ptr[eax + 0Eh]
			cmp     ecx, 32h
			jnz     short loc_431C86
			mov     eax, [ebp - 44h]
			mov[ebp - 4], eax
			jmp     short loc_431CEF

		loc_431C86 :
		mov     eax, 2
			imul    ecx, eax, 0
			mov     edx, [ebp - 48h]
			movzx   eax, word ptr[edx + ecx]
			cmp     eax, 72h
			jnz     short loc_431CEF
			mov     eax, 2
			shl     eax, 0
			mov     ecx, [ebp - 48h]
			movzx   edx, word ptr[ecx + eax]
			cmp     edx, 70h
			jnz     short loc_431CEF
			mov     eax, 2
			shl     eax, 1
			mov     ecx, [ebp - 48h]
			movzx   edx, word ptr[ecx + eax]
			cmp     edx, 63h
			jnz     short loc_431CEF
			mov     eax, 2
			imul    ecx, eax, 3
			mov     edx, [ebp - 48h]
			movzx   eax, word ptr[edx + ecx]
			cmp     eax, 73h
			jnz     short loc_431CEF
			mov     eax, 2
			shl     eax, 2
			mov     ecx, [ebp - 48h]
			movzx   edx, word ptr[ecx + eax]
			cmp     edx, 73h
			jnz     short loc_431CEF
			mov     eax, [ebp - 44h]
			mov[ebp - 8], eax

		loc_431CEF :
		mov     eax, [ebp - 40h]
			mov     ecx, [eax]
			mov[ebp - 40h], ecx
			jmp     loc_431BF3

		loc_431CFC :
		mov     eax, [ebp - 4]
			mov     ecx, [eax + 18h]
			mov[ebp - 0Ch], ecx
			mov     eax, [ebp - 8]
			mov     ecx, [eax + 18h]
			mov[ebp - 10h], ecx
			mov     eax, [ebp - 8]
			mov     ecx, [ebp - 10h]
			add     ecx, [eax + 20h]
			mov[ebp - 14h], ecx
			mov     eax, [ebp - 0Ch]
			mov[ebp - 4Ch], eax
			mov     eax, [ebp - 4Ch]
			mov     ecx, [ebp - 4Ch]
			add     ecx, [eax + 3Ch]
			mov[ebp - 50h], ecx
			mov     esi, [ebp - 50h]
			add     esi, 18h
			mov     ecx, 38h
			lea     edi, [ebp - 130h]
			rep movsd
			mov     eax, 8
			imul    ecx, eax, 0
			mov     edx, [ebp - 4Ch]
			add     edx, [ebp + ecx - 0D0h]
			mov[ebp - 134h], edx
			mov     eax, [ebp - 134h]
			mov     ecx, [ebp - 4Ch]
			add     ecx, [eax + 20h]
			mov[ebp - 138h], ecx
			mov     eax, [ebp - 134h]
			mov     ecx, [ebp - 4Ch]
			add     ecx, [eax + 24h]
			mov[ebp - 13Ch], ecx
			mov     eax, [ebp - 134h]
			mov     ecx, [ebp - 4Ch]
			add     ecx, [eax + 1Ch]
			mov[ebp - 140h], ecx
			mov     eax, [ebp - 134h]
			mov     ecx, [eax + 10h]
			mov[ebp - 144h], ecx
			mov     dword ptr[ebp - 148h], 0
			mov     dword ptr[ebp - 14Ch], 0
			mov     dword ptr[ebp - 150h], 0
			jmp     short loc_431DCB

		loc_431DBC :
		mov     eax, [ebp - 150h]
			add     eax, 1
			mov[ebp - 150h], eax

		loc_431DCB :
		mov     eax, [ebp - 134h]
			mov     ecx, [ebp - 150h]
			cmp     ecx, [eax + 14h]
			jnb     loc_432342
			mov     eax, [ebp - 150h]
			mov     ecx, [ebp - 138h]
			mov     edx, [ebp - 4Ch]
			add     edx, [ecx + eax * 4]
			mov[ebp - 148h], edx
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax]
			cmp     ecx, 43h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 1]
			cmp     ecx, 72h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 2]
			cmp     ecx, 65h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 3]
			cmp     ecx, 61h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 4]
			cmp     ecx, 74h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 5]
			cmp     ecx, 65h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 6]
			cmp     ecx, 46h
			jnz     loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 7]
			cmp     ecx, 69h
			jnz     short loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 8]
			cmp     ecx, 6Ch
			jnz     short loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 9]
			cmp     ecx, 65h
			jnz     short loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Ah]
			cmp     ecx, 57h
			jnz     short loc_431F00
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Bh]
			test    ecx, ecx
			jnz     short loc_431F00
			mov     eax, [ebp - 150h]
			mov     ecx, [ebp - 13Ch]
			movzx   edx, word ptr[ecx + eax * 2]
			mov     eax, [ebp - 144h]
			lea     ecx, [edx + eax - 1]
			mov[ebp - 14Ch], ecx
			mov     eax, [ebp - 14Ch]
			mov     ecx, [ebp - 140h]
			mov     edx, [ebp - 4Ch]
			add     edx, [ecx + eax * 4]
			mov[ebp - 18h], edx
			jmp     loc_43233D

		loc_431F00 :
		mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax]
			cmp     ecx, 57h
			jnz     loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 1]
			cmp     ecx, 72h
			jnz     loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 2]
			cmp     ecx, 69h
			jnz     loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 3]
			cmp     ecx, 74h
			jnz     loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 4]
			cmp     ecx, 65h
			jnz     loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 5]
			cmp     ecx, 46h
			jnz     short loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 6]
			cmp     ecx, 69h
			jnz     short loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 7]
			cmp     ecx, 6Ch
			jnz     short loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 8]
			cmp     ecx, 65h
			jnz     short loc_431FE2
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 9]
			test    ecx, ecx
			jnz     short loc_431FE2
			mov     eax, [ebp - 150h]
			mov     ecx, [ebp - 13Ch]
			movzx   edx, word ptr[ecx + eax * 2]
			mov     eax, [ebp - 144h]
			lea     ecx, [edx + eax - 1]
			mov[ebp - 14Ch], ecx
			mov     eax, [ebp - 14Ch]
			mov     ecx, [ebp - 140h]
			mov     edx, [ebp - 4Ch]
			add     edx, [ecx + eax * 4]
			mov[ebp - 1Ch], edx
			jmp     loc_43233D

		loc_431FE2 :

		mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax]
			cmp     ecx, 43h
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 1]
			cmp     ecx, 6Ch
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 2]
			cmp     ecx, 6Fh
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 3]
			cmp     ecx, 73h
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 4]
			cmp     ecx, 65h
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 5]
			cmp     ecx, 48h
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 6]
			cmp     ecx, 61h
			jnz     loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 7]
			cmp     ecx, 6Eh
			jnz     short loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 8]
			cmp     ecx, 64h
			jnz     short loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 9]
			cmp     ecx, 6Ch
			jnz     short loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Ah]
			cmp     ecx, 65h
			jnz     short loc_4320EA
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Bh]
			test    ecx, ecx
			jnz     short loc_4320EA
			mov     eax, [ebp - 150h]
			mov     ecx, [ebp - 13Ch]
			movzx   edx, word ptr[ecx + eax * 2]
			mov     eax, [ebp - 144h]
			lea     ecx, [edx + eax - 1]
			mov[ebp - 14Ch], ecx
			mov     eax, [ebp - 14Ch]
			mov     ecx, [ebp - 140h]
			mov     edx, [ebp - 4Ch]
			add     edx, [ecx + eax * 4]
			mov[ebp - 20h], edx
			jmp     loc_43233D

		loc_4320EA :
		mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax]
			cmp     ecx, 47h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 1]
			cmp     ecx, 65h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 2]
			cmp     ecx, 74h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 3]
			cmp     ecx, 50h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 4]
			cmp     ecx, 72h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 5]
			cmp     ecx, 6Fh
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 6]
			cmp     ecx, 63h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 7]
			cmp     ecx, 41h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 8]
			cmp     ecx, 64h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 9]
			cmp     ecx, 64h
			jnz     loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Ah]
			cmp     ecx, 72h
			jnz     short loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Bh]
			cmp     ecx, 65h
			jnz     short loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Ch]
			cmp     ecx, 73h
			jnz     short loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Dh]
			cmp     ecx, 73h
			jnz     short loc_43222B
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Eh]
			test    ecx, ecx
			jnz     short loc_43222B
			mov     eax, [ebp - 150h]
			mov     ecx, [ebp - 13Ch]
			movzx   edx, word ptr[ecx + eax * 2]
			mov     eax, [ebp - 144h]
			lea     ecx, [edx + eax - 1]
			mov[ebp - 14Ch], ecx
			mov     eax, [ebp - 14Ch]
			mov     ecx, [ebp - 140h]
			mov     edx, [ebp - 4Ch]
			add     edx, [ecx + eax * 4]
			mov[ebp - 2Ch], edx
			jmp     loc_43233D

		loc_43222B :
		mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax]
			cmp     ecx, 4Ch
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 1]
			cmp     ecx, 6Fh
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 2]
			cmp     ecx, 61h
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 3]
			cmp     ecx, 64h
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 4]
			cmp     ecx, 4Ch
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 5]
			cmp     ecx, 69h
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 6]
			cmp     ecx, 62h
			jnz     loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 7]
			cmp     ecx, 72h
			jnz     short loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 8]
			cmp     ecx, 61h
			jnz     short loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 9]
			cmp     ecx, 72h
			jnz     short loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Ah]
			cmp     ecx, 79h
			jnz     short loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Bh]
			cmp     ecx, 41h
			jnz     short loc_43233D
			mov     eax, [ebp - 148h]
			movsx   ecx, byte ptr[eax + 0Ch]
			test    ecx, ecx
			jnz     short loc_43233D
			mov     eax, [ebp - 150h]
			mov     ecx, [ebp - 13Ch]
			movzx   edx, word ptr[ecx + eax * 2]
			mov     eax, [ebp - 144h]
			lea     ecx, [edx + eax - 1]
			mov[ebp - 14Ch], ecx
			mov     eax, [ebp - 14Ch]
			mov     ecx, [ebp - 140h]
			mov     edx, [ebp - 4Ch]
			add     edx, [ecx + eax * 4]
			mov[ebp - 28h], edx

		loc_43233D :
		jmp     loc_431DBC

		loc_432342 :
		mov     byte ptr[ebp - 15Ch], 4Eh
			mov     byte ptr[ebp - 15Bh], 74h
			mov     byte ptr[ebp - 15Ah], 64h
			mov     byte ptr[ebp - 159h], 6Ch
			mov     byte ptr[ebp - 158h], 6Ch
			mov     byte ptr[ebp - 157h], 2Eh
			mov     byte ptr[ebp - 156h], 64h
			mov     byte ptr[ebp - 155h], 6Ch
			mov     byte ptr[ebp - 154h], 6Ch
			mov     byte ptr[ebp - 153h], 0
			mov     byte ptr[ebp - 16Ch], 52h
			mov     byte ptr[ebp - 16Bh], 74h
			mov     byte ptr[ebp - 16Ah], 6Ch
			mov     byte ptr[ebp - 169h], 4Dh
			mov     byte ptr[ebp - 168h], 6Fh
			mov     byte ptr[ebp - 167h], 76h
			mov     byte ptr[ebp - 166h], 65h
			mov     byte ptr[ebp - 165h], 4Dh
			mov     byte ptr[ebp - 164h], 65h
			mov     byte ptr[ebp - 163h], 6Dh
			mov     byte ptr[ebp - 162h], 6Fh
			mov     byte ptr[ebp - 161h], 72h
			mov     byte ptr[ebp - 160h], 79h
			mov     byte ptr[ebp - 15Fh], 0
			lea     eax, [ebp - 15Ch]
			push    eax
			call    dword ptr[ebp - 28h]
			add     esp, 4
			mov[ebp - 170h], eax
			lea     eax, [ebp - 16Ch]
			push    eax
			mov     ecx, [ebp - 170h]
			push    ecx
			call    dword ptr[ebp - 2Ch]
			add     esp, 8
			mov[ebp - 30h], eax
			mov     eax, [ebp - 10h]
			mov[ebp - 174h], eax
			mov     eax, [ebp - 14h]
			mov[ebp - 178h], eax

		loc_432426 :
		mov     eax, [ebp - 174h]
			cmp     eax, [ebp - 178h]
			jnb     loc_432507
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax]
			cmp     ecx, 0BEh
			jnz     loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 1]
			cmp     ecx, 5
			jnz     loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 2]
			test    ecx, ecx
			jnz     loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 3]
			cmp     ecx, 7
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 4]
			cmp     ecx, 80h
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 29h]
			cmp     ecx, 0BEh
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 2Ah]
			cmp     ecx, 57h
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 2Bh]
			test    ecx, ecx
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 2Ch]
			cmp     ecx, 7
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			movzx   ecx, byte ptr[eax + 2Dh]
			cmp     ecx, 80h
			jnz     short loc_4324F3
			mov     eax, [ebp - 174h]
			sub     eax, 12A0Bh
			mov[ebp - 24h], eax
			jmp     short loc_432507

		loc_4324F3 :
		mov     eax, [ebp - 174h]
			add     eax, 1
			mov[ebp - 174h], eax
			jmp     loc_432426

		loc_432507 :
		mov     byte ptr[ebp - 198h], 0
			mov     byte ptr[ebp - 197h], 0
			mov     byte ptr[ebp - 196h], 0
			mov     byte ptr[ebp - 195h], 0
			mov     byte ptr[ebp - 194h], 0
			mov     byte ptr[ebp - 193h], 0
			mov     byte ptr[ebp - 192h], 0
			mov     byte ptr[ebp - 191h], 0
			mov     byte ptr[ebp - 190h], 0
			mov     byte ptr[ebp - 18Fh], 0
			mov     byte ptr[ebp - 18Eh], 0
			mov     byte ptr[ebp - 18Dh], 0
			mov     byte ptr[ebp - 18Ch], 0
			mov     byte ptr[ebp - 18Bh], 0
			mov     byte ptr[ebp - 18Ah], 0
			mov     byte ptr[ebp - 189h], 0
			mov     byte ptr[ebp - 188h], 0
			mov     byte ptr[ebp - 187h], 0
			mov     byte ptr[ebp - 186h], 0
			mov     byte ptr[ebp - 185h], 0
			mov     byte ptr[ebp - 184h], 0
			mov     byte ptr[ebp - 183h], 0
			mov     byte ptr[ebp - 182h], 0
			mov     byte ptr[ebp - 181h], 0
			mov     byte ptr[ebp - 180h], 0
			mov     byte ptr[ebp - 17Fh], 0
			mov     byte ptr[ebp - 17Eh], 0
			mov     byte ptr[ebp - 17Dh], 0
			mov     byte ptr[ebp - 17Ch], 0
			push    1Dh
			mov     eax, [ebp + 18h]
			add     eax, 284h
			push    eax
			lea     ecx, [ebp - 198h]
			push    ecx
			call    dword ptr[ebp - 30h]
			add     esp, 0Ch
			mov     eax, 5Ch
			mov[ebp - 1D4h], ax
			mov     eax, 5Ch
			mov[ebp - 1D2h], ax
			mov     eax, 2Eh
			mov[ebp - 1D0h], ax
			mov     eax, 5Ch
			mov[ebp - 1CEh], ax
			mov     eax, 42h
			mov[ebp - 1CCh], ax
			mov     eax, 75h
			mov[ebp - 1CAh], ax
			mov     eax, 66h
			mov[ebp - 1C8h], ax
			mov     eax, 66h
			mov[ebp - 1C6h], ax
			mov     eax, 65h
			mov[ebp - 1C4h], ax
			mov     eax, 72h
			mov[ebp - 1C2h], ax
			mov     eax, 65h
			mov[ebp - 1C0h], ax
			mov     eax, 64h
			mov[ebp - 1BEh], ax
			mov     eax, 49h
			mov[ebp - 1BCh], ax
			mov     eax, 4Fh
			mov[ebp - 1BAh], ax
			mov     eax, 44h
			mov[ebp - 1B8h], ax
			mov     eax, 65h
			mov[ebp - 1B6h], ax
			mov     eax, 76h
			mov[ebp - 1B4h], ax
			mov     eax, 63h
			mov[ebp - 1B2h], ax
			mov     eax, 69h
			mov[ebp - 1B0h], ax
			mov     eax, 65h
			mov[ebp - 1AEh], ax
			mov     eax, 4Ch
			mov[ebp - 1ACh], ax
			mov     eax, 69h
			mov[ebp - 1AAh], ax
			mov     eax, 6Eh
			mov[ebp - 1A8h], ax
			mov     eax, 6Bh
			mov[ebp - 1A6h], ax
			mov     eax, 4Eh
			mov[ebp - 1A4h], ax
			mov     eax, 61h
			mov[ebp - 1A2h], ax
			mov     eax, 6Dh
			mov[ebp - 1A0h], ax
			mov     eax, 65h
			mov[ebp - 19Eh], ax
			xor     eax, eax
			mov[ebp - 19Ch], ax
			push    0
			push    80h
			push    3
			push    0
			push    0
			push    0C0000000h
			lea     eax, [ebp - 1D4h]
			push    eax
			call    dword ptr[ebp - 18h]
			add     esp, 1Ch
			mov[ebp - 1D8h], eax
			mov     dword ptr[ebp - 1DCh], 0
			push    0
			lea     eax, [ebp - 1DCh]
			push    eax
			push    1Dh
			lea     ecx, [ebp - 198h]
			push    ecx
			mov     edx, [ebp - 1D8h]
			push    edx
			call    dword ptr[ebp - 1Ch]
			add     esp, 14h
			mov[ebp - 1E0h], eax
			mov     eax, [ebp - 1D8h]
			push    eax
			call    dword ptr[ebp - 20h]
			add     esp, 4
			mov     dword ptr[ebp + 8h], 0
			mov     eax, [ebp - 24h]
			add     eax, 5
			mov[ebp - 24h], eax
			//压入参数
			mov     eax, [ebp + 1Ch]
			push    eax
			mov     ecx, [ebp + 18h]
			push    ecx
			mov     edx, [ebp + 14h]
			push    edx
			mov     eax, [ebp + 10h]
			push    eax
			mov     ecx, [ebp + 0Ch]
			push    ecx
			mov     edx, [ebp + 8]
			push    edx
			mov     edx, [ebp - 24h]
			//压入返回地址
			call NEXT
			NEXT :
			pop eax
			add eax,12
			push eax
			//压入ebp
			mov     edi, edi
			push    ebp
			mov     ebp, esp
			jmp     edx
			pop     edi
			pop     esi
			pop     ebx
			mov     esp, ebp
			pop     ebp
			retn
	}
}




