# remenissions

This is an autopwner for simple ctf pwn challenges. It has pwned 100+ ctf challenges, which can be found in `https://github.com/guyinatuxedo/remenissions_test`.

## Usage

To use remenissions:

```console
$ remenissions -b <binary name>
```

Example:

```console
$ remenissions -b chall-test_csaw18-getit
```

If you have a libc file:

```console
$ remenissions -b chall-test_encryp19-pwn2 -l libc-2.30.so
```

If you have the ip/port that the challenge is running on. This is recommended as it will increase the number of ways remenissions can possible solve a challenge:

```console
$ remenissions -b hidden_flag_function_with_args -i 4c1f411430b8fc27.247ctf.com -p 50402
```

If you have additional files that are needed to run the binary (looking at you hack@ucf):

```console
$ remenissions -b chall-test_hackucf-ret -a libpwnableharness32.so
```

If remenissions successfully generates an exploit, you will see a string like this:

```console
Exploit Successful: exploit-BofFunc.py
```

And you should see an exploit like this:

```console
$ ls | grep verified
verified-exploit-BofFunc.py
```

If remenissions cannot pwn the binary, you will see a string like this:

```console
Could not pwn binary
```

## Install

So to install remenissions, there are currently three defined methods. Keep in mind that remenissions was developed and tested on Ubuntu. The first is an install script. You just need to first edit it, and set the directory for where ghidra is on your system:

Edit the script

```console
$ vim setup.sh
```

Set this variable to your ghdira directory:

```console
$ GHIDRA_DIR="/tools/ghidra"
```

Which your ghidra directory should look like this:

```console
$ pwd
/tools/ghidra

$ ls
docs        Ghidra                          ghidraRun      GPL      licenses  server
Extensions  ghidra_9.1_PUBLIC_20191023.zip  ghidraRun.bat  LICENSE  projects  support
```

Then just run the setup script:

```console
$ ./setup.sh
```

The second method is a manual installation. The docs for this can be found under `docs/install.md`.

The third method is a vm that I made that has remenissions already setup (username is `remenissions`, password is `password`), which can be found here: `https://drive.google.com/file/d/1UfQ9F5zDsdbfdgbgSkbHUhn6CUT_J7zw/view?usp=sharing`

I initially tried to use a dockerfile, however due to a lot of issues, I went with a vm instead.

## Docker

Skip all the install steps and just use docker:  
```console
$ docker build -t remenissions .

$ docker run --rm -it -v $(pwd):/shared remenissions
```
If you're lazy and don't wanna remember docker stuff, just add this alias to your bashrc:
```console
$ alias remenissions='docker run --rm -it -v $(pwd):/shared remenissions'
```
This will drop you into a tmux session in a docker container with remenissions installed.  
Just use remenissions as you normally would in this docker container.

Docker support was added by https://github.com/MEhrn00. As of now, I have not run this through the hundreds of test cases, so there may or may not be stability issues.

## How Does it Work?

For documentation about how it works, you can check under `/docs`

[Documentation](https://github.com/guyinatuxedo/remenissions/tree/master/docs)


## Questions

If you have any questions, find any bugs, or have any potential feature suggestions, post them in here:

```
https://discord.gg/p5E3VZF
```

## Why the names?

Remenissions is the name of a great Avenged Sevenfold song: `https://www.youtube.com/watch?v=tysmwGx7TNU`

Solway_firth is the name of a great slipknot song: `https://www.youtube.com/watch?v=V3ADK6gsDGg`

Diamond Eyes is the name of a great shinedown song: `https://www.youtube.com/watch?v=hez6tDpiWDA`

Death Stranding is the name of a great song: `https://www.youtube.com/watch?v=bv2yNre7saU`

## Special Thanks

Special thanks to these people, for dealing with my memes while making this:

```
noop
mmaekr
SmoothHacker
```
