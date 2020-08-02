# remenissions

This is an autopwner for simple ctf pwn challenges. It has pwned 100+ ctf challenges, which can be found in `https://github.com/guyinatuxedo/remenissions_test`.

## Usage

To use remenissions:

```
$	remenissions -b <binary name>
```

Example:

```
$	remenissions -b chall-test_csaw18-getit
```

If you have a libc file:

```
$	remenissions -b chall-test_encryp19-pwn2 -l libc-2.30.so
```

If you have the ip/port that the challenge is running on. This is recommended as it will increase the number of ways remenissions can possible solve a challenge:

```
$	remenissions -b hidden_flag_function_with_args -i 4c1f411430b8fc27.247ctf.com -p 50402
```

If you have additional files that are needed to run the binary (looking at you hack@ucf):

```
$	remenissions -b chall-test_hackucf-ret -a libpwnableharness32.so
```

If remenissions successfully generates an exploit, you will see a string like this:

```
Exploit Successful: exploit-BofFunc.py
```

And you should see an exploit like this:

```
$	ls | grep verified
verified-exploit-BofFunc.py
```

If remenissions cannot pwn the binary, you will see a string like this:

```
Could not pwn binary
```

## Install

So to install remenissions, there are currently two defined methods. Keep in mind that remenissions was developed and tested on Ubuntu. The first is an install script. You just need to first edit it, and set the directory for where ghidra is on your system:

Edit the script

```
$	vim setup.sh
```

Set this variable to your ghdira directory:

```
GHIDRA_DIR="/tools/ghidra"
```

Which your ghidra directory should look like this:

```
$	pwd
/tools/ghidra
$	ls
docs        Ghidra                          ghidraRun      GPL      licenses  server
Extensions  ghidra_9.1_PUBLIC_20191023.zip  ghidraRun.bat  LICENSE  projects  support
```

Then just run the setup script:

```
$	./setup.sh
```

The second method is a manual installation. The docs for this can be found under `docs/install.md`.

Currently working on making a dockerfile for remenissions, more to come.

## How Does it Work?

Currently documenting the internal working of remenissions, more to come.

## Questions

If you have any questions, find any bugs, or have any potential feature suggestions, post them in here:

```
https://discord.gg/p5E3VZF
```

## Why the name?

Remenissions is the name of a great Avenged Sevenfold song: `https://www.youtube.com/watch?v=tysmwGx7TNU`
