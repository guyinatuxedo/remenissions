## Installation

So this is meant to be a writeup for how to manually install remenissions, since it is a bit more involved than `sudo apt-get install something`. There are a lot of moving parts, and depending on your environment the setup might be different. This writeup is just me setting up remenissions on a blank vm manually, While the exact setup may be slightly different depending on your enviornment, all of the main points are covered and the deviations shouldn't be too bad.


## Git clone / Install Directories

Of course, you will need git:

```console
$ sudo apt-get install git
```

Clone the repo:

```console
$ git clone https://github.com/guyinatuxedo/remenissions.git
```

Now you will need to set the install directories in `remenissions/solway_firth.py`. To do this, edit this file:

```console
$ vim /Hackery/remenissions/remenissions
```

Set this line to the installation directory:

```console
$ INSTALL_DIR = "/Hackery/remenissions/"
```

Edit this file next:

```console
$ vim /Hackery/remenissions/solway_firth.py
```

Set this line to the installation directory:
```console
$ INSTALL_DIR = "/Hackery/remenissions/"
```

Then next, make a symbolic link to `remenissions` from your `$PATH` directories:

```console
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
$ sudo ln -s /Hackery/remenissions/remenissions /usr/local/bin/remenissions
```

You will also need to install `pwntools` (from `http://docs.pwntools.com/en/latest/install.html`):

```console
$ sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
$ sudo python3 -m pip install --upgrade pip
$ sudo python3 -m pip install --upgrade pwntools
```

Now with the exact version of pwntools you get, there is one thing you need to watch out for with `gdb.attach()`. That is if the argument to execute gdb commands is either `execute` or `gdbscript`. I have a constant in `solway_firth.py` called `EXECUTE_STRING` which you can set this, if the default value doesn't match your enviornment.

```console
$ EXECUTE_STRING = "gdbscript"
#EXECUTE_STRING = "execute"
```

## GDB-Gef Setup

This tool utilizes gdb with the `gef` wrapper. Gdb should come installed by default on linux, however if not just google how to install it. 

For the wrapper `gef`, you can find it here with install instructions `https://github.com/hugsy/gef`. I also included a version under `dependencies` in case there was an update made to `gef` that would break something with my static analysis, there was a functioning copy that can be used until I fix it.

Also there is one gdb script that you will need to add to your `.gdbinit` file (`far_away.py`). To add these two, you can edit this file:

```console
$ vim ~/.gdbinit
```

Add these two lines (replace `/Hackery/remenissions/` with the path to the `remenissions` directory on your box).

```console
$ source /Hackery/remenissions/dependencies/gef/.gdbinit-gef.py
$ source /Hackery/remenissions/far_away.py
```

## one_gadget

Remenissions needs uses `one_gadget` to find one gadgets.

First, you may need to install `gem` and `ruby` first:

```console
$ sudo apt-get install gem
$ sudo apt-get install ruby
```

Then install `one_gadget`:

```console
$ sudo gem install one_gadget
```

## Ghidra / Death Stranding

For static analysis, remenissions uses ghidra, so we will need to set it up. First download ghidra, and unzip it.

```console
$ wget https://ghidra-sre.org/ghidra_9.1.2_PUBLIC_20200212.zip
$ unzip -D ghidra_9.1.2_PUBLIC_20200212.zip
```

You will also need to install java:

```console
$ sudo apt-get install openjdk-11-jdk
$ sudo apt-get install openjdk-11-jre-headless
```

Run the `ghidraRun` script, just to make sure the ghidra installation is working.

Now you will need to specify the path of the headless analyzer elf `analyzeHeadless` which will probably be under the `support` direcotry of the ghidra folder for remenissions. Edit remenissions:

```console
$ vim /Hackery/remenissions/remenissions
```

Specify the ghidra headless analyzer directory with this line:

```console
$ HEADLESS_GHIDRA_DIR = "/tools/ghidra/ghidra_9.1.2_PUBLIC/support/"
```

The last thing you will need to do is place `death_stranding.py` in the ghidra scripts directory. 

```console
$ cp /Hackery/remenissions/static_analyzer/death_stranding.py /tools/ghidra/ghidra_9.1.2_PUBLIC/Ghidra/Features/Python/ghidra_scripts/
```

## itl

The tool `itl` (from `https://github.com/guyinatuxedo/itl`) is used to deal with linking issues. You can find a copy of it under `/dependencies/`.

```console
$ cd /Hackery/remenissions/dependencies/itl/
$ sudo ./install 
```

## sf

The tool `sf` is used as a payload generation api (from `https://github.com/guyinatuxedo/sf`). It is used by the exploits generated from `remenissions`.

You might need to install `pip3`:

```console
$ sudo apt-get install python3-pip
```

And you might need to install `setuptools`:

```console
$ sudo pip3 install setuptools
```

Then install `sf`:

```console
$ cd /Hackery/remenissions/dependencies/sf/
$ sudo python3 setup.py install
```

## The_Night

`The_Night` is a tool used for remote libc identification (from `https://github.com/guyinatuxedo/The_Night`). To install it:

First install `zstandard`:

```console
$ sudo pip3 install zstandard
```

```console
$ cd /Hackery/remenissions/dependencies/The_Night/
```

You will first need to download the libcs / parse the symbols (may take a few minutes):

```console
$ python3 download.py 
Downloading: libc6-amd64_2.10.1-0ubuntu15_i386.so
Downloading: libc6-amd64_2.10.1-0ubuntu19_i386.so
Downloading: libc6-amd64_2.11.1-0ubuntu7.11_i386.so
.	.	.
```

Then you can install `The_Night`:

```console
$ sudo python3 setup.py install
```

Lastly you will need to se the `THE_NIGHT_LIBCS` value in `solway_firth.py` to the directory of the `The_Night` libcs directory:

```
THE_NIGHT_LIBCS = "/Hackery/remenissions/dependencies/The_Night/libcs/"
```

## ROPgadget

Nothing should be needed for this, I just wanted to say that there was a cop of `ropgadget.py` under `/dependencies/` (from `https://github.com/JonathanSalwan/ROPgadget`).
