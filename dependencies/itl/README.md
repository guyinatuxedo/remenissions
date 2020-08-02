# itl

Have you ever had the issue where you go to ld_preload a binary with a different libc (effectively swapping out the libc file a binary gets linked with), only to find out you don't have the right linker? This tool itl (Inspire The Liars) attempts to solve that problem easily. It essentially is a wrapper for patchelf to patch the binary to use the correct linker, and the tool also has the linkers on hand that it can just copy into the directory.

## Usage

To use the tool, just run the `itl` command and specify the binary you want to ld_preload (`-b` flag), and the libc you want to ld_preload it with (`-l` flag):

```
$    itl -b popping_caps -l libc.so.6
Libc Version: 2.27
```

Also there is a `-e` flag, that if you use it, it will write a pwntools script called `exploit.py` which handles ld_preloading for you:

```
$    itl -b popping_caps -l libc.so.6 -e
Libc Version: 2.27
Creating Exploit
```

Currently this tool supports the following libc version:
```
2.30     
2.29     
2.27     
2.24     
2.23    
2.21    
2.19     
```

## Install

To install this tool, just run the python script `install` as sudo:

```
$    sudo ./install
Installing itl (Inspire The Liars)
Reading package lists... Done
Building dependency tree       
Reading state information... Done
patchelf is already the newest version (0.10-2).
0 upgraded, 0 newly installed, 0 to remove and 30 not upgraded.
```

The install script essentially does two things. The first is it installs `patchelf`. The second thing is it writes the install directory (the directory you have the repo cloned to) to the tool. It then saves a copy of the tool to both the install directory, and `/usr/bin`.

## Manually Swapping Linker

First you need to find the actual binary for the linker version. If you have the libc version `2.27`, you will need the `2.27` linker:

```
$    cp /Hackery/inspire_the_liars/linkers/ld-2.27.so .
$    chmod +x ld-2.27.so
```

After that you can just patch the binary using `patchelf` to set the linker to the one you have just copied:

```
$    patchelf --set-interpreter /home/guyinatuxedo/Documents/manu/ld-2.27.so ./popping_caps
```

After that you can ld_preload. This is one example with a pwntools script:

```
$    patchelf --set-interpreter /home/guyinatuxedo/Documents/manu/ld-2.27.so ./popping_caps
```

## Misc

The method I used to deal with this issue is based off of:
```
https://teamrocketist.github.io/2019/08/17/Pwn-RedpwnCTF-penpal-world/
```

If you want to contact me, this discord is probably the best way:

```
https://discord.gg/p5E3VZF
```

Also if you're curious why this tool is called Inspire The Liars, it is named after this song by Dance Gavin Dance:

```
https://www.youtube.com/watch?v=Z-aQrBZ4Duw
```