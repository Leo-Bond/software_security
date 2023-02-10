
#include <stdio.h>
#include <Windows.h>




#pragma code_seg(".wdy")
int shellcode() {
	typedef struct _UNICODE_STRING {
		WORD Length;
		WORD MaximumLength;
		PWORD Buffer;
	}UNICODE_STRING;
	typedef struct _PEB_LDR_DATA {
		ULONG	Length;				//           : Uint4B
		BOOLEAN Initialized;		//: UChar;内存对齐了
		PVOID SsHandle;		// : Ptr32 Void
		LIST_ENTRY InLoadOrderModuleList;// : _LIST_ENTRY
		LIST_ENTRY InMemoryOrderModuleList;// : _LIST_ENTRY
		LIST_ENTRY InInitializationOrderModuleList;//: _LIST_ENTRY
	}PEB_LDR_DATA, * PPEB_LDR_DATA;
	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;//_LIST_ENTRY
		LIST_ENTRY InMemoryOrderLinks;//_LIST_ENTRY
		LIST_ENTRY InInitializationOrderLinks;//_LIST_ENTRY
		VOID* DllBase;//Ptr32 Void模块基地址
		VOID* EntryPoint;//Ptr32 Void
		ULONG SizeOfImage;//Uint4B
		UNICODE_STRING FullDllName;//_UNICODE_STRING
		UNICODE_STRING BaseDllName;//_UNICODE_STRING
		ULONG Flags;//Uint4B
		USHORT LoadCount;//Uint2B
		USHORT TlsIndex;//Uint2B
	}LDR_DATA_TABLE_ENTRY, LDR_MODULE, * PLDR_MODULE;


	//typedef struct _WIN32_FIND_DATAA {
	//	DWORD dwFileAttributes;
	//	FILETIME ftCreationTime;
	//	FILETIME ftLastAccessTime;
	//	FILETIME ftLastWriteTime;
	//	DWORD nFileSizeHigh;
	//	DWORD nFileSizeLow;
	//	DWORD dwReserved0;
	//	DWORD dwReserved1;
	//	_Field_z_ CHAR   cFileName[MAX_PATH];
	//	_Field_z_ CHAR   cAlternateFileName[14];
	//#ifdef _MAC
	//	DWORD dwFileType;
	//	DWORD dwCreatorType;
	//	WORD  wFinderFlags;
	//#endif
	//} WIN32_FIND_DATAA, * PWIN32_FIND_DATAA, * LPWIN32_FIND_DATAA;


	typedef FARPROC(WINAPI* PGETPROCADDRESS)(HMODULE hModule, PCSTR lpProcName);
	typedef HMODULE(WINAPI* PLOADLIBRARYA)(LPCTSTR lpFileName);
	typedef BOOL(WINAPI* PCOPYFILE)(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL    bFailIfExists);
	typedef HANDLE(WINAPI* PFINDFIRSTFILEA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
	typedef BOOL(WINAPI* PFINDCLOSE)(HANDLE hFindFile);


	LDR_DATA_TABLE_ENTRY* pPLD = NULL, * pBeg = NULL;

	PGETPROCADDRESS pGetProcAddress = NULL;
	PLOADLIBRARYA  pLoadLibraryA = NULL;
	PFINDFIRSTFILEA pFindFirstFileA = NULL;
	PCOPYFILE pCopyFile = NULL;
	PFINDCLOSE pFindClose = NULL;


	WORD* pFirst = NULL, * pLast = NULL;
	DWORD dwKernel32Base = 0;
	DWORD dwUser32Base = 0;

	char szKernel32[] = { 'K',0,'E',0,'R',0,'N',0,'E',0,'L',0,'3',0,'2', 0,'.',0,'D',0,'L',0,'L',0,0,0 };
	char szUser32[] = { 'U','S','E','R','3','2','.','d','l','l',0 };
	char szGetProcAddress[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
	char szLoadLibraryA[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	char szFindFirstFileA[] = { 'F', 'i', 'n', 'd', 'F', 'i', 'r', 's', 't', 'F', 'i', 'l', 'e', 'A',0 };
	char szFindNextFileA[] = { 'F', 'i', 'n', 'd', 'N', 'e', 'x', 't', 'F', 'i', 'l', 'e', 'A' ,0 };
	char szFindClose[] = { 'F', 'i', 'n', 'd', 'C', 'l', 'o', 's', 'e',0 };
	char szCopyFile[] = { 'C','o','p','y','F','i','l','e', 'A', 0 };

	__asm {
		mov	eax, fs: [0x30]			//指向peb
		mov	eax, [eax + 0x0c]		//peb->ldr
		add eax, 0x0c				//InLoadOrderModuleList
		mov pBeg, eax				//pBeg指向第一个模块结构
		mov eax, [eax]
		mov pPLD, eax				//pPLD指向第二个模块结构
	}
	while (pPLD != pBeg) {		//循环模块双向链表
		pLast = (WORD*)pPLD->BaseDllName.Buffer;		//指向模块名字的指针
		pFirst = (WORD*)szKernel32;
		while (*pFirst && (*pFirst == *pLast || *pFirst + 0x20 == *pLast))		//不相同或者结尾就停下
			pFirst++, pLast++;
		if (*pFirst == *pLast) {					//说明是结尾了，比较正确
			dwKernel32Base = (DWORD)pPLD->DllBase;
			break;
		}
		pPLD = (LDR_DATA_TABLE_ENTRY*)pPLD->InLoadOrderLinks.Flink;		//否则就不是所找的dll，下一轮循环
	}

	//pPLD指向kernel32模块结构了,要遍历kernel32的导出表找到getprocaddress
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)dwKernel32Base;
	IMAGE_NT_HEADERS* pINtH = (IMAGE_NT_HEADERS*)((DWORD)dwKernel32Base + pDosHeader->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)((DWORD)dwKernel32Base + pINtH->OptionalHeader.DataDirectory[0].VirtualAddress);//导出表va
	DWORD* pAddOfFun_Raw = (DWORD*)((DWORD)dwKernel32Base + pIED->AddressOfFunctions);		//函数地址表，序号最大减去最小
	DWORD* pAddOfName_Raw = (DWORD*)((DWORD)dwKernel32Base + pIED->AddressOfNames);	//以名字导出函数，字母排序的
	WORD* pAddOfOrd_Raw = (WORD*)((DWORD)dwKernel32Base + pIED->AddressOfNameOrdinals);//每个项占两个字节,和名字表个数一样
	//找函数地址顺序，函数名字表中得到索引，根据索引在序号表找到索引，根据索引找地址表中地址
	//序号直接减去序号base在地址表找地址
	DWORD dwCnt = 0;//函数在函数表中索引
	char* pFinded = NULL, * pSrc = szGetProcAddress;//要比对函数
	for (; dwCnt < pIED->NumberOfNames; dwCnt++) {//所有函数名字
		pFinded = (char*)((DWORD)dwKernel32Base + pAddOfName_Raw[dwCnt]);
		while (*pFinded && *pFinded == *pSrc) {
			pFinded++, pSrc++;
		}
		if (*pFinded == *pSrc) {//找到了
			pGetProcAddress = (PGETPROCADDRESS)((DWORD)dwKernel32Base + pAddOfFun_Raw[pAddOfOrd_Raw[dwCnt]]);
			break;
		}
		pSrc = szGetProcAddress;
	}
	//找到了getprocaddress

	pLoadLibraryA = (PLOADLIBRARYA)pGetProcAddress((HMODULE)dwKernel32Base, szLoadLibraryA);


	pFindFirstFileA = (PFINDFIRSTFILEA)pGetProcAddress((HMODULE)dwKernel32Base, szFindFirstFileA);
	pCopyFile = (PCOPYFILE)pGetProcAddress((HMODULE)dwKernel32Base, szCopyFile);
	pFindClose = (PFINDCLOSE)pGetProcAddress((HMODULE)dwKernel32Base, szFindClose);

	WIN32_FIND_DATAA fileData;
	char fileName[] = { '*', '.', 't', 'x', 't', 0 };
	char newPath[] = { '2', '0', '2', '0', '3', '0', '2', '1', '8', '1', '1', '0', '5', '.', 't', 'x', 't', 0 };
	HANDLE hSearchFile = pFindFirstFileA(fileName, &fileData);
	pCopyFile(fileData.cFileName, newPath, FALSE);
	pFindClose(hSearchFile);




}


int main() {
	shellcode();

	return 0;
}
