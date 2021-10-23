#include "API_Hook.h"
#include "detours.h"
#include <shlwapi.h>
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")

static BOOL (WINAPI* OldWriteProcessMemory)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
) = WriteProcessMemory;

char* itoa1(int num, char* str, int radix)
{
	char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";//������
	unsigned unum;//���Ҫת���������ľ���ֵ,ת�������������Ǹ���
	int i = 0, j, k;//i����ָʾ�����ַ�����Ӧλ��ת��֮��i��ʵ�����ַ����ĳ��ȣ�ת����˳��������ģ��������������k����ָʾ����˳��Ŀ�ʼλ��;j����ָʾ����˳��ʱ�Ľ�����

					//��ȡҪת���������ľ���ֵ
	if (radix == 10 && num < 0)//Ҫת����ʮ�����������Ǹ���
	{
		unum = (unsigned)-num;//��num�ľ���ֵ����unum
		str[i++] = '-';//���ַ�����ǰ������Ϊ'-'�ţ�����������1
	}
	else unum = (unsigned)num;//����numΪ����ֱ�Ӹ�ֵ��unum

							  //ת�����֣�ע��ת�����������
	do
	{
		str[i++] = index[unum % (unsigned)radix];//ȡunum�����һλ��������Ϊstr��Ӧλ��ָʾ������1
		unum /= radix;//unumȥ�����һλ

	} while (unum);//ֱ��unumΪ0�˳�ѭ��

	str[i] = '\0';//���ַ���������'\0'�ַ���c�����ַ�����'\0'������

				  //��˳���������
	if (str[0] == '-') k = 1;//����Ǹ��������Ų��õ������ӷ��ź��濪ʼ����
	else k = 0;//���Ǹ�����ȫ����Ҫ����

	char temp;//��ʱ��������������ֵʱ�õ�
	for (j = k; j <= (i - 1) / 2; j++)//ͷβһһ�Գƽ�����i��ʵ�����ַ����ĳ��ȣ��������ֵ�ȳ�����1
	{
		temp = str[j];//ͷ����ֵ����ʱ����
		str[j] = str[i - 1 + k - j];//β����ֵ��ͷ��
		str[i - 1 + k - j] = temp;//����ʱ������ֵ(��ʵ����֮ǰ��ͷ��ֵ)����β��
	}

	return str;//����ת������ַ���
}


BOOL DetourWriteProcessMemory(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T  *lpNumberOfBytesWritten
)
{
	//MessageBoxA(NULL, "tets", "tets", MB_OK);
	Sleep(100);
	if (lpBuffer != NULL && nSize != 0x00)
	{
		DWORD currentTime = GetTickCount();
		CHAR szCurrentTime[MAX_PATH] = { 0 };
		itoa1(currentTime, szCurrentTime, 10);
		//printf("%s", szCurrentTime);

		//CreateFile
		HANDLE hFile = NULL;
		hFile = CreateFileA(szCurrentTime,
			(GENERIC_READ | GENERIC_WRITE),
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (hFile == NULL)
			return OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

		//WriteFile
		DWORD NumberOfBytesWritten = 0;
		if (WriteFile(hFile, lpBuffer, nSize, &NumberOfBytesWritten, NULL) == FALSE && NumberOfBytesWritten != 0)
			return OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

	}
	return OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}



/*
	@ ����ʵ��
*/
VOID Hook()
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)OldWriteProcessMemory, DetourWriteProcessMemory);
	DetourTransactionCommit();
}

VOID UnHook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)OldWriteProcessMemory, DetourWriteProcessMemory);
	DetourTransactionCommit();
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if (DetourIsHelperProcess())
	{
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		Hook();
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{

		UnHook();
	}
	return TRUE;
}