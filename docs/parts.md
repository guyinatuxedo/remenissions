# Reminissions Parts

First off, here are the various parts that make up remenissions:

```
Basic Attributes Enumerator:
Static Analyzer:    
Dynamic Analyzer:
Exploit Generation:
Exploit Verification:
Main Control Unit:
```

After I am done explaining the various components of remenissions, I go on to explain the different bugs remenissions can work with, and the various attacks it can do leveraging those bugs. At its core, remenissions is essentially a decision tree (no fancy AI, Machine learning, Blockchain, Cloud Based, Cyber Deep Learning memory here). When making this autopwner, there was the problem I wanted to put a lot of work into. That is the fact that within a binary, there are just so many different ways you can do things, that with an autopwner it's not really a matter of if something is done differently what you expect and breaks something, it's a matter of when. So when I made this, I tried to identify likely points of failure, and implement redundancies to deal with it. You will see that in various parts throughout here, including things like exploit correction and multiple analysis methods to find the same bug.

## Basic Attributes Enumerator

This is a very simple part. The purpose of it is to essentially check out the attributes of the file, that will affect how we go about pwning the binary. It does this by wrapping the `file` command, and utilizing pwntool's `ELF()` functionality, so it's nothing really special. The parts that we are looking for are:

```
architecture:    (x86 or x64)
linkage:        (dynamically linked or static)
are certain functions present:    (like puts or system)
are certain strings present:    (like "/bin/bash" or "/bin/sh")
binary mitigations present: (true / false)
    stack canary
    nx
    pie
    relro
```

This is the first thing that remenissions does, right after making it's working directory. The reason for this being is that there are certain attributes that have a lot of affect on how we go about analyzing, and pwning the binary. For instance if the binary is statically linked, remenissions will not do static analysis on the binary, and revert to dynamic analysis. This is because chances are if it's statically compiled, it is stripped, and with how static analysis works, it needs symbols in order to operate properly. In addition to that it takes a while to analyze a statically linked binary, just because of how much code is in the binary.

This portion is contained in the file `sitd` (named after a great Ice Nine Kills song). It is a standalone python3 file, which can be called as is. There are two arguments for it, `-b` to specify the binary, and `-e` to specify if we are running it as part of an automated tool, which it will output it's findings to `sitd-out` (which is how remenissions uses it):

```
$    ./sitd -h
usage: sitd [-h] [-b B] [-e [E]]

A Tool

optional arguments:
  -h, --help  show this help message and exit
  -b B        The binary you are working with.
  -e [E]      Use this flag to direct output to a file, mainly used for
              autmoation purposes.
$    ./sitd -b /Hackery/test_remenissions/0_var-unit-tests/0_64/chall-test_var-0-x64
[*] '/Hackery/test_remenissions/0_var-unit-tests/0_64/chall-test_var-0-x64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
Architecture:      amd64
Dynamically Linked True
Stack Canary:      False
NX Stack:          True
PIE:               True
RELRO:             False
Imported Target Functions: {'system': None, 'puts': None}
Interesting Strings:       {b'/bin/sh': 8196, b'/bin/bash': None}
```

## Death Stranding (static analyzer)

So the static analyzer is called death stranding (because wtf was that game). It uses Jython API from Ghidra's Headless Analyzer, to do static analysis (just looking at the code itself). I went with Jython over Java, because this is a tool for hackers, and anecodotally hackers are much more comfortable with python over java.

### Premise

So the static analyzer primarily serves two purposes. The first is finding bugs (it's the primary method remenissions uses to do that). The second is to find alternate win conditions. With any ctf pwn problem, a win condition 99.9% of the time is to get the binary to pop a shell, regardless if it is the intended solution. However with a lot of challenges, the win condition isn't something you know before you look at the binary. This can include things like a function you have to call, or a code path you have to take, that just reads out the flag for you. Since unlike popping a shell, I can't assume that that is a valid win condition before I analyze the binary, I have to incorporate finding those alternate win conditions in my analysis.

Essentially how this works, is it checks to see if certain predefined libc functions are called in the binary. If they are present, then it will check all references to them. It will look at it's arguments, to determine if a bug is present.

Here is the list of functions that I check for vulnerabilities:
```
gets:     bof
read:     bof
fgets:    bof
scanf:    bof
fscanf:   bof
fread:    bof
strcpy:   bof
strncpy:  bof
printf:   infoleak / fmt string
```

A few things. First off for `strcpy/strncpy`, I only have analysis support for input via `argv[1]`. The rest of the bof functions only have input support for `stdin`. For the `stdin` functions, if I find a valid function call that is not a buffer overflow, I mark it as an input. Inputs are mainly used for situations where either there is a format string bug, or we are writing to a function pointer (for more on inputs, checkout the format string section). Also I realize that the functions that I have checked for, are not the only ways a buffer overflow bug can be introduced into a binary. For that I have as a backup, the dynamic analyzer, which can detect and model buffer overflow bugs without knowledge or as many assumptions on how the buffer overflow occurs as here (checkout dynamic analysis for more).

Here are a list of functions that I check for alternate win functions:
```
open
fopen
system
execve
```

For these, essentially all I am doing is grabbing the string argument to the function. Then after I have it, I will check if a predefined list of strings exist in the string. For functions like `system` the strings are like `sh` and `cat` (the reason `sh` is because it is contained in both `/bin/sh` and `/bin/bash`, which are common strings for instances I am looking for). For functions like `open`, I am checking for strings like `flag` or `key`. This is for situations where the win function is reading from a file that has the flag. Of course, this assumes that the flag file is named something like `flag.txt`, or `key`, because if it's not, this won't detect it. If it does detect a function that matches this, then it marks the function the libc function call is made in as a win function.

In addition to that, there are several scenarios that cause my analysis for finding the string argument to break. In situations like these where my analysis isn't sure what the string argument is, I just mark the function which the libc function call is made in, as a possible win function. When I initially designed it, I anticipated having a different code path for possible win functions, than normal win functions. As a result I made two seperate code paths for them. Looking back at it now, other than this one distinction where I don't know the string argument, the two code paths are identical in terms of the attack they carry out.

One more thing, I realize that the algorithm I have for detecting win functions isn't perfect. it's designed to say if a function could be a possible win function, not that it definitely is. This is because I will accept potential false positives, in exchange for less false negatives. This is because with the design of my autopwner, a false positive here would just mean that remenissions will try some attacks that it couldn't land, which will just take a few more seconds. However a false negative would mean that remenissions have no hope of solving it. So I made this part a bit more relaxed, to expand the total number of challenges it could solve.

For how this realistically works, first off I will set up the decompiler with the `setupDecompiler()` function. Then proceeding that I will check for alternate win conditions with `checkWinConditions()` (I do it before `checkTargetFunctions()` for branch analysis):

```
def checkWinConditions():
  function = getFirstFunction()
  while function is not None:
    funcName = function.getName()
    if funcName in winFuncs.keys():
      if checkGot(function) == False:
        winFuncs[funcName](function)
    function = getFunctionAfter(function)
  reportAltWinConditions()

def checkTargetFunctions():
  function = getFirstFunction()
  while function is not None:
    funcName = function.getName()
    if funcName in targetFunctions.keys():
      if checkGot(function) == False:
        targetFunctions[funcName](function)
    function = getFunctionAfter(function)
```

These two functions are pretty much identical. They just get the first function, check if it's one of the functions we need to check. If it is, it runs the corresponding analysis function. If not, it then just iterates through the rest of the functions, until it reaches the end.

Also while death stranding is used by remenissions, it is perfectly capable of being used as it's own standalone tool. For instance:

```
$   /tools/ghidra/support/analyzeHeadless  /Hackery/proj_remenissions/ p1 -process chall-test_var-0-x64 -postscript death_stranding.py

. . .

+-------------------------------------------------------------------------+
|                          Stack Buffer Overflow                          |
+-------------------------------------------------------------------------+
Function:     gets
Calling Function:   main
Address:      0x1181
Overwriteable Values:   [72, 16, 12, 'return_address']
Additional Cmps:    [[12, 16435934, 11, 2, 4], [16, 16435934, 11, 2, 4]]
Indirect Calls:     []
Input type:     stdin
Write as much as you want.
```

### Analysis Functions

So let's take a look at the actual functions used to evaluate if there is either a bug, or an alternate win condition. Here is the function used to check if there is a vulnerable `read` function call:

```
def analyzeRead(function):
  referencesTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
  for reference in referencesTo:
    if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
      continue
    address, callPcodes, callingFunction = processReference(reference)

    for callPcode in callPcodes:
      if callPcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
        continue
      buff = callPcode.getInput(2)
      size = callPcode.getInput(3).getOffset()
      offset = stackOffsetFromVarnode(buff)

      # Check if we can overflow it
      if checkOverflow(callingFunction, offset, size) == True:
        logStack(function, callingFunction, address, offset, "stdin", size)
      # If it isn't a buffer overflow, mark it as an input
      else:
        logInput(function, callingFunction, address, offset, "stdin", size)
```

So the first for loop / if then statement will iterate through all of the references, and give us the ones that are actual function calls. Then we will grab the pcodes for that function call (pcodes are Ghidra's intermediate language that it uses to decompile assembly code). Then once we have the pcode for the actual call (since when we decompile it to pcodes, we get a pcode block), we grab the arguments to the call. Then from there we can just check if it is a bug, since we know the arguments. If it is a buffer overflow, we log it as a stack buffer overflow. If not we log it as an input.

Let's take a look at the function to evaluate if an `fopen()` call is an alternate win condition:

```
def checkWinFopen(function):
  checkWinSingleArg(openWinArgs, function)

def checkWinSingleArg(winStrings, function):
  referencesTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint())
  for reference in referencesTo:

    if str(reference.getReferenceType()) != "UNCONDITIONAL_CALL":
      continue  
    address, callPcodes, callingFunction = processReference(reference)
    for callPcode in callPcodes:
      if callPcode.getOpcode() != ghidra.program.model.pcode.PcodeOp.CALL:
        continue
      string = getString(callPcode.getInput(1))
      if string == "":
        possibleAltWinFuncs.append(addressToHex(getFunctionContaining(reference.getFromAddress()).getEntryPoint()))
      checkString(string, winStrings, reference)  
```

All of the functions to check for alternate win conditions, all call `checkWinSingleArg`, since the string argument we are interested in for all of them is in the same spot. For this, we can see that it effectively just finds the string argument we are interested in (the first argument to the function call). If it contains any of the desired strings, we mark it as a win function in the `checkString` function. If analysis can't find the string, then we just assign it as a possible win function.

### Branch Analysis / Indirect Call Overwrite

So one type of problem we see a lot, can be demonstrated with this testcase's source code:

```
#include <stdio.h>
#include <stdlib.h>

void main(void)
{

  char buf[50];
  int target0;
  int target1;

  gets(buf);

  if (target0 == 0xfacade)
  {
    system("/bin/sh");
  }

  if (target1 == 0xfacade)
  {
    system("/bin/sh");
  }
}
```

We can see clearly, the solution here is to cause either of the two if then statement conditionals to be true. While this might be easier for a beginner, from the perspective of automatically solving this challenge, it presents several issues for us that would make it harder than a challenge that is just something like calling a win function. We need to first identify that there is a branch that is based on a conditional, that we actually have control over. We need to identify the parameters behind how our input can control it. Then we need to identify which code path we want to take.

In addition to that, we may see something like this, where we can to a function pointer:

```
#include <stdio.h>
#include <stdlib.h>


void pwn(void)
{
  system("/bin/sh");
}

void main(void)
{

  char buf0[20];
  volatile int (*ptr)();
  char buf1[200];

  fgets(buf0, 100, stdin);

  ptr();

}
```

For this one, I just have to have the autopwner figure out how to write to the instruction pointer, and what to call with it.

How I go about looking for these things, is I first wait for there to be some input. This could either be a stack buffer overflow, or an input. Once it finds one, it will check for these things with the `checkStack` function. This will get the pcodes (the IL Ghidra uses to decompile stuff) for the function the function call for the input is made in. It will iterate through all of the pcodes for the function. However it will only start checking pcodes, after it has reached the pcode where the function call for our input exists. The reason for that is for these types of challenges, we have no way of influencing the behavior of the binary before we give input, so anything that happens before that for these challenges I can't influence, so I'm not worried about it. After that, I will check if the opcode for a pcode either matches a conditional, or an indirect call.

If the opcode matches that of one of the conditionals, then I will check it with the `processCmp` function. This will look for the proceeding `CBRANCH` pcode, which specifies that if the conditional is true, where code flow ends up at. I take the address of where the conditional ends up at as one code path, and for the other code path I used the very next pcode after the `CBRANCH`. I get the pcodes for those two code paths, and then run them through the `checkBranch` function, which checks for function calls. If a function call is made to either a win function (which is why we check for alternate win functions before bugs), or a libc function call is made that would qualify as an alternate win condition, that path is marked as the one we want to take. If a function call is made to a defined "losing function", then that path is one we don't want to take. Then we will model the check, which is a dictionary that has the following values:

```
stackOffset:    stack offset to variable in check
value:          the value it is being compared to
branchType:     the type of check being done
desiredOutcome: the estimate as to which code path it should take
size:           the size of the value being checked
```

Now a few things about this, this branch analysis isn't perfect. Even if everything works properly, there are still some scenarios in which case this branch analysis algorithm could get it wrong. On top of that, I've seen several instances where the pcodes for the checks would be wrong, and would incorrectly identify which code paths would be taken upon which conditions (not to diss Ghdira, it's an amazing tool that works on an insanely hard problem). Because of that, unless I have some mechanism that can reliably identify incorrect pcodes and correct them, no matter how intense my branch analysis is, it will always have some non-negligible degree of error.

However one thing Ghidra is great with, is identifying the value being compared to, along with the type of compare, and the stack variable that is being checked. If we have those three pieces of information, we can just try hitting one code path first, and then the other. Since we have exploit verification, we can tell if we pwned the binary or not. So effectively I treat the `desiredOutcome` as more of a best guess. If that fails, then in exploit correction I can just go through and brute force the checks until I get it right. This will need to have 2^n exploits, where n is the number of checks. Fortunately most ctf problems like this have very few checks, so it doesn't give us too bad of a performance hit. The plus side to this, is that since we are able to effectively model all of the checks in a way where it becomes a binary choice which path we take, by brute forcing it we will arrive at the same spot that a perfect branch analysis algorithm would get us to, just take a few more seconds.

If the opcode is that of an indirect call (`CALLIND`), then I just grab the stack offset being called (I assume it is a stack variable being called) and record it.

One last thing, for stack based buffer overflows, branch analysis never really goes away, since we have things like this:

```
#include <stdio.h>
#include <stdlib.h>

void win(void)
{
  system("/bin/sh");
}

void main(void)
{
  char vuln[20];
  int var0;
  fgets(vuln, 100, stdin);

  if (var0 != 0xfacade)
  {
    exit(0);
  }


}
```

Here, the objective is to call the `win` function via overwriting the return address. However in order to do so, we need to overwrite a variable to alter a certain check. There are countless examples of challenges like this. So even though the attack method might be something like shellcode / rop / etc, branch analysis never really goes away. Also atm my branch analysis can only handle comparisons for things with numerical values.

Also for the values assigned to the best guess, as to which way we want to go in a branch, these are the values and their meaning:

```
0:  Want to pass
1:  Don't want to pass
2:  idk
```

### Memory Regions

So there are several problems that we have to deal with regarding memory regions. One of which is PIE, which is when the binary is addressed to offsets starting at `0x0`, and the actual address is a random value generated at runtime plus the offset. Those offsets in the binary start at `0x0`, however Ghidra automatically rebases everything to start at `0x100000`. As such the offsets we get from ghidra will be `0x100000` greater than the actual offset (that is for `x64`, for `x86` it's `0x10000`), which obviously causes problems. How I deal with this is I just rebase everything to start at `0x0` in the binary. For this I have to iterate through all of the memory blocks, and set the addresses. This does cause one problem however.

Ghidra pcodes use something called varnodes, which are how it models things like variables and function arguments. When we look at a varnode, we just see the offset not the memory region (at least with how I'm doing it). So in instances where an infoleak is being given through `printf`, we need to determine what memory region it is from. I first did this by checking first if it's within the range of GOT section offset (since if it's just doing something like printing the libc address of `printf`, this is the offset that will show up). Then check if it's within the range of PIE section offsets. Then after that I assumed it was from the stack. This worked pretty well, until I hit some problems that implemented PIE.

Thing is, since I was rebasing everything to start at `0x0` in the binary segment, I could get a stack offset to something like `0xf0`, that would be within the `PIE` offset range. As such with my algorithm, it would misidentify a stack infoleak as a pie infoleak. How I dealt with this is I introduced another check before everything else, that would check if the offset is both within the range of offsets for the pie range, and the stack frame. If so I would log it as both a PIE infoleak, and a Stack infoleak. This would cause it to possibly attempt some attacks it can't actually do, however it would still solve the challenge.

Also another issue that occurs. With 32 bit binaries with pie enabled, ghidra has a hard time naming functions that it has symbols for. To deal with this, using objdump I just grabbed the function names and their starting address. Then with file I/O and cmd arguments, I would pass these to death stranding, and have it rename them. For `x64` binaries with PIE enabled, I would just put `rebase` as the argument, to specify that we are just rebasing it.

Another issue with stack variables. The offset that ghidra gives you for stack variables, is the offset from the return address. So if a stack variable is let's say `80`, there are 80 bytes between the start of that variable and the return address. This is true for all scenarios I've seen, except for some intermittent cases with the main function for `x86` binaries. To deal with this, if we have stack input to the main function of an `x86` binary, I will just use the dynamic analyzer to check it. If it's not correct, I will find the actual offset and adjust everything.

### misc

I handle I/O to death stranding via reading / writing to files, that are specified in the command line arguments to death stranding. For more details you can see the actual commands I use from within remenissions.

Also I wanted to say something if you wanted to get started with using Ghidra's api for it's headless analyzer. What you're doing is you're effectively running the headless analyzer, and then specifying your script through a command line argument. There are certain directories that it looks for in those scripts (although iirc you can specify additional directories for it to look for). I posted above the actual command you can use to run death stranding (or you could just look under remenissions). I would highly recommend looking at the api docs, they're amazing (example: https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html).


## Solway Firth

So this is the part of remenissions that actually handles developing the exploit. I will explain some of the various parts of how I generate exploits.

The exploits generated are in Python 2. The reason for this being, is that all of my exploits use pwntools. In the Python 3 version, there's a bug I ran into. When you attach gdb to a target process, and then the gdb session closes before the exploit is done, it will try to delete a tmp file which doesn't exist, and crash. I didn't want to patch it out as part of the remenissions installation process, or wait for a pull request to be merged, so I just stuck with python 2.

### Constructing Payloads

So for constructing payloads, we use a list to store the various parts. When we make a new part to the payload, we append it to the list. For items appended to the list, there are really 5 defined types of things we can append to the list. There are strings, integers, stack values, pie values, and libc values. For strings, the item is pretty much the string. For integers, I append a list that has two values, the integer value and the size of the integer. For libc / stack / pie values, they are pretty much like integers, except they have an extra item at the beginning of the list which specifies what memory region it is. Once I have all of the payload parts in the main list, I just pass it to the `constructPayload()` function to construct the payload.

### Overwriting Variables / Branch Analysis

So one common thing I need to do is overwrite stack variables. Another common thing I need to do is fill up the space between the start of our input, and the return address (for buffer overflow bugs). Because these things directly overlap, I have the `overwriteVarsHelper()` function to handle this problem (for the initial attacks, not correction). The `fill` argument is to specify if we just want to overwrite the variables, or actually fill the space between the start of the input and the return address (so it can handle both tasks individually, or combined).

So what `overwriteVarsHelper` does effectively, is return a list. This list is composed of strings, and integers. The integers are for the checks. The strings are essentially the filler values between checks.

For correction, what I do, is I use the `getPayloadPermutations()` function to generate different payload permutations to get the conditionals to hit all of the code paths. We can do this since from the information we get from modeling the checks, we can essentially treat each check as a binary value if we either pass or fail it. I haven't seen a situation yet where the information provided from death stranding needed to do this is wrong. Then I return a list of the payloads, which get iterated through. In the future I hope to implement a form of analysis, where it will just figure out and report back a payload that will figure out how to get a function we have input to hit the return (since a lot of our attacks rely on overwriting a return address that is executed). This should help the run times with certain things.

### Dealing with Given Infoleaks

So Remenissions has two defined methods to get infoleaks. The first is when the binary just gives you an infoleak. With the simple ctf challenges that remenissions is aimed at, this is actually kind of common. The other is leveraging format strings.

The reason why there are only two, is because the other methods to get an infoleak like index array out of bound, overflowing a printed buffer the right amount, etc., typically requires more complex input mapping that goes beyond the scope I wanted remenissions to handle.

## Diamond Eyes (Dynamic Analyzer)

So this is the dynamic analyzer I made for remenissions. The purpose of this is to analyze programs for vulnerabilities while it is running. It is to compliment the static analysis, to find bugs that it can't find with the static analysis. I designed it in this way.

Now I'm not going to lie, how I made it was pretty hacky. Effectively I just wrap gdb, and turn it into a simple fuzzer that monitors the output. There are several reasons why I did this. I wanted easy access to both the debugger, and stdin/stdout (which I don't have from gdb's api). All of the solutions I found for automating gdb pretty much were gdb wrappers like this, so I figured I would just make my own.

Now how this fuzzer works, is I set breakpoints on read / write syscalls, so it breaks at the syscalls made for either input/output. I break on syscalls that way I do not need to have symbols, so I can analyze statically compiled stripped binaries.

Also another major use I have for the dynamic analyzer, is at times I will use it to check things, such as the stack layout or format string offset.

## Exploit Generation

For exploit generation, I use the solway_firth module. Effectively I pass it various bug models, with a particular function call representing a particular attack type, and it will generate the exploits.

## Exploit Verification

Exploit verification works via a gdb script, that I pass the command to run it as an argument to `gdb.attach()` in the test exploit scripts. Effectively I check to see if one of a few conditions is met. This works for dynamically linked binaries, via setting breakpoints for certain functions and syscalls. If a call to `system("/bin/sh")` or something like `puts("flag{take_control_of_the_}")`, I mark it as a pwned idea. Also if I syscall to something like `execve("/bin/sh")`, I mark that as a successful exploit. I communicate the success / failure of an exploit via file IO.

## Main Control Unit

So the main control unit is `remenissions`. It effectively just makes the decisions on what happens, and calls other things to do the work. It effectively serves as the decision tree.

So the decision tree for how remenissions works is this. First I get the basic attributes of binary. If it is dynamically linked, I run the static analyzer against it to get bugs and alternate win conditions. If it is statically linked, then I run the dynamic analyzer Then I go through, and count the total number of bugs / alternate win conditions found. Then I go through, and attempt an attack for every type of attack that I have the conditions meant for (this way I don't have to 100% be sure what attack type works for a challenge, and I can also get unintended solutions). Then if none of those work, I run correction for all of the attempted attacks.

If that doesn't work, then I retry static analysis (if applicable) and then run dynamic analysis if I didn't already run it. Then I go through the process of generating exploits / corrections. Then if that doesn't work I try to use the last resort attacks, which currently only has remote libc id.
