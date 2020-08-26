[GitHub](http://github.com)

https://askubuntu.com/questions/41629/after-upgrade-gdb-wont-attach-to-process

```
atexit.register(lambda: os.unlink(tmp.name))
```


How I want things laid out:
```
0.) First the various parts of remenissions

```

# How Remenissions works

So this is essentially just a giant text dump explaining remenissions works. First off, here are the various parts that make up remenissions:

```
Basic Attributes Enumerator:
Static Analyzer:    
Dynamic Analyzer:
Exploit Generation:
Exploit Verification:
Main Control Unit:
```

After I am done explaining the various components of remenissions, I go on to explain the different bugs remenissions can work with, and the various attacks it can do leveraging those bugs. At its core, remenissions is essentially a decision tree (no fancy AI, Machine learning, Blockchain, Cloud Based, Cyber Deep Learning memory here). When making this autopwner, there was the problem I wanted to put a lot of work into. That is the fact that within a binary, there are just so many different ways you can do things, that with an autopwner it's not really a matter of if something is done different what you expect and breaks something, it's a matter of when. So when I made this, I tried to identify likely points of failure, and implement redundancies to deal with it. You will see that in various parts throughout here, including things like exploit correction and multiple analysis methods to find the same bug.

### Basic Attributes Enumerator

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

### Death Stranding (static analyzer)

So the static analyzer is called death stranding (because wtf was that game). It uses Jython API from Ghidra's Headless Analyzer, to do static analysis (just looking at the code itself).

#### Premise

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

#### Analysis Functions

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

#### Branch Analysis / Indirect Call Overwrite

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

Now a few things about this, this branch analysis isn't perfect. Even if everything works properly, there are still some scenarios in which case this branch analysis algorithm could get it wrong. On top of that, I've seen several instances where the pcodes for the checks would be wrong, and would incorrectly identify which code paths would be taken upon which conditions (not to diss Ghdira, it's an amazing tool that works on an insanely hard problem). Because of that, unless if I have some mechanism that can reliably identify incorrect pcodes and correct them, no matter how intense my branch analysis is, it will always have some non-negligible degree of error.

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

#### Memory Regions

So there are several problems that we have to deal with regarding memory regions. One of which is PIE, which is when the binary is addressed to offsets starting at `0x0`, and the actual address is a random value generated at runtime plus the offset. Those offsets in the binary start at `0x0`, however Ghidra automatically rebases everything to start at `0x100000`. As such the offsets we get from ghidra will be `0x100000` greater than the actual offset (that is for `x64`, for `x86` it's `0x10000`), which obviously causes problems. How I deal with this is I just rebase everything to start at `0x0` in the binary. For this I have to iterate through all of the memory blocks, and set the addresses. This does cause one problem however.

Ghidra pcodes use something called varnodes, which are how it models things like variables and function arguments. When we look at a varnode, we just see the offset not the memory region (at least with how I'm doing it). So in instances where an infoleak is being given through `printf`, we need to determine what memory region it is from. I first did this by checking first if it's within the range of GOT section offset (since if it's just doing something like printing the libc address of `printf`, this is the offset that will show up). Then check if it's within the range of PIE section offsets. Then after that I assumed it was from the stack. This worked pretty well, until I hit some problems that implemented PIE.

Thing is, since I was rebasing everything to start at `0x0` in the binary segment, I could get a stack offset to something like `0xf0`, that would be within the `PIE` offset range. As such with my algorithm, it would misidentify a stack infoleak as a pie infoleak. How I dealt with this is I introduced another check before everything else, that would check if the offset is both within the range of offsets for the pie range, and the stack frame. If so I would log it as both a PIE infoleak, and a Stack infoleak. This would cause it to possibly attempt some attacks it can't actually do, however it would still solve the challenge.

Also another issue that occurs. With 32 bit binaries with pie enabled, ghidra has a hard time naming functions that it has symbols for. To deal with this, using objdump I just grabbed the function names and their starting address. Then with file I/O and cmd arguments, I would pass these to death stranding, and have it rename them. For `x64` binaries with PIE enabled, I would just put `rebase` as the argument, to specify that we are just rebasing it.

Another issue with stack variables. The offset that ghidra gives you for stack variables, is the offset from the return address. So if a stack variable is let's say `80`, there are 80 bytes between the start of that variable and the return address. This is true for all scenarios I've seen, except for some intermittent cases with the main function for `x86` binaries. To deal with this, if we have stack input to the main function of an `x86` binary, I will just use the dynamic analyzer to check it. If it's not correct, I will find the actual offset and adjust everything.

#### misc

I handle I/O to death stranding via reading / writing to files, that are specified in the command line arguments to death stranding. For more details you can see the actual commands I use from within remenissions.

Also I wanted to say something if you wanted to get started with using Ghidra's api for it's headless analyzer. What you're doing is you're effectively running the headless analyzer, and then specifying your script through a command line argument. There are certain directories that it looks for in those scripts (although iirc you can specify additional directories for it to look for). I posted above the actual command you can use to run death stranding (or you could just look under remenissions). I would highly recommend looking at the api docs, they're amazing (example: https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html).


### Solway Firth

So this is the part of remenissions that actually handles developing the exploit. I will explain some of the various parts of how I generate exploits. 

The exploits generated are in Python 2. The reason for this being, is that all of my exploits use pwntools. In the Python 3 version, there's a bug I ran into. When you attach gdb to a target process, and then the gdb session closses befroe the exploit is done, it will try to delete a tmp file which doesn't exist, and crash. I didn't want to patch it out as part of the remenissions installation process, or wait for a pull request to be merged, so I just stuck with python 2.

#### Constructing Payloads

So for consturcting payloads, we use a list to store the various parts. When we make a new part to the payload, we append it to the list. For items appended to the list, there are really 5 define types of things we can append to the list. There are strings, integers, stack values, pie values, and libc values. For strings, the item is pretty much the string. For integers, I append a list that has two values, the integer value and the size of the integer. For libc / stack / pie values, they are pretty much like integers, except they have an extra item at the beginning of the list which specifies what memory region it is. Once I have all of the payload parts in the main list, I just pass it to the `constructPayload()` function to construct the payload.

#### Overwritting Variables / Branch Analysis

So one common thing I need to do is overwrite stack variables. Another common thing I need to do is fill up the space between the start of our input, and the return address (for buffer overflow bugs). Because these things directly overlap, I have the `overwriteVarsHelper()` function to handles this problem (for the initial attacks, not correction). The `fill` argument is to specify if we just want to overwrite the variables, or actually fill the space between the start of the input and the return address (so it can handle both tasks individually, or combined).

So what `overwriteVarsHelper` does effectively, is return a list. This list is comprised of strings, and integers. The integers are for the checks. The strings are essentially the filler values between checks.

For correction, what I do, is I use the `getPayloadPermutations()` function to generate different payload permutations to get the conditionals to hit all of the code paths. We can do this since from the information we get from modeling the checks, we can essentially treat each check as a binary value if we either pass or fail it. I haven't seen a situation yet where the infromation provided from death stranding needed to do this is wrong. Then I return a list of the payloads, which get iterated through. In the future I hope to implement a form of analysis, where it will just figure out and report back a payload that will figure out how to get a function we have input to hit the return (since a lot of our attacks rely on overwriting a return address that is executed). This should help the run times with certain things. 

#### Dealing with Given Infoleaks

So Remenissions has two defined methods to get infoleaks. The first is when the binary just gives you an infoleak. With the simple ctf challenges that remenissions is aimed at, this is actually kind of common. The other is leveraging format strings.

The reason why there are only two, is because the other methods to get an infoleak like index array out of bound, overflowing a printed buffer the right amount, etc., typically requires more complex input mapping that goes beyond the scope I wanted remenissions to handle.



### Dynamic Analyzer

### Exploit Generation

### Exploit Verification

### Main Control Unit

## Bug Types

### Stack

So this is essentially a buffer overflow on the stack. The particular pieces of data that I use to model a stack bof are:

```
type:               The type of bug, "stack"
function:           The name of the libc function
callingFunction:    The function the vulnerable function call is made
address:            The address which the vulnerable function call is
overwriteableVars:  A list of the variables which can be overwritten by this bug
checks:             A list of compares that happen to the variables this bug can write to
calledPtrs:         A list of the variables which are function pointers that are called
inpType:            The type of input expected, either STDIN or argv atm
writeSize:          The size of the write
```

A few things about this.

The variables I store, will either be one of two things. It will be a numerical value specifying the offset from the return address (since that is how ghidra's api specifies variables). Or it will be a string like `return_address`, specifying that using this bug, we can overwrite the return address.

For more on `checks`, checkout branch analysis.

The writesize will either be a numerical value, or `None`. If it is a numerical value, this value will mean either one of two things. If `return_address` is listed in the `overwriteableVars`, it will specify the number of bytes it can write starting at the return address. If `return_address` is not listed in `overwriteableVars`, it means the number of bytes it can write starting at the start of our input. If this value is set to `None`, it means that there is no size restriction on our input, like with the function `gets`.

How ghidra identifies binaries is by the name. If you have multiple binaries with the same name that you are working with, you're going to have conflictions. Also the first time you are working with a binary in reference to a project, you have to import it, then you can just process it. To deal with this, I just have a text file that lists the binaries that have been imported, and check it each time I run remenissions. If the binary name is not in the text file, I import it, append the filename to the textfile, then carry on.

### Infoleak

So for an infoleak, these are the pieces of data that I model:

```
type:             Infoleak
function:         The function call that is made for the infoleak
callingFunction:  The function the infoleak happens in
address:          The address the infoleak happens at
memoryRegion:     The memory region the infoleak is from
string:           The fmt string used for the infoleak
offset:           The offset to the desired memory base
fmtIndex:         Effectively which fmt string the infoleak is from
```

A few things about this. The desired memory base for PIE and Libc, is the base of those regions. For the stack, it is the start of our input.

### Fmt String

Possible Fmt String

```
type:
function:
callingFunction:
address:
stackoffset:
```

```
type:
function:
callingFunction:
address:
stackoffset:
inpMethod:
```

### Input

```
type:               
function:           
callingFunction:    
address:            
stackOffset:        
checks:             
calledPtrs:         
inpType:            
writeSize:          
```

## Attacks

So here is where I describe the various attacks remenissions has. The correction for an attack is just the attack name with `correct` appended to the beginning. For instance the correction for the `bofVar` function is `correctBofVar`.

### Overwrite Variables - bofVar

This portion covers this attack:
```
bofVar
```

So this attack is overwritting a variable on the stack. For instance take a look at this code:

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

Here the intended solution is to leverage the buffer overflow bug to overwrite the value of either `target0` or `target1` with `0xfacade`. In order to automate solving this challenge, there are two things we need to effectively model. The stack overflow bug, and the conditionals. For the stack overflow bug, we need to know things like where the input starts, how much we can write, and the address of the bug. For the checks, we need to model what checks happen after the bug. Since I assume that the code flow is linear, to see what checks are after the input, I just look for checks after the check (if there are jumps that would redirect code flow, it would break this, but I haven't ran into this problem yet). For the check, the things we need to model are what stack value is being checked, the value it is being compared to, the type of compare, and which way we would want to go. I went into more details about how I analyze and model these things earlier.

There is a third possible thing we would need to analyze, and model. That is alternate win functions. This is a part of the branch analysis for determining what we want to do with a check.

The function that is responsible for carrying out this attack is `overwriteVars`. There is a lot of function calls that happen in here that happen in other attacks, so I'm just going to quickly go through them real quick.

We see that there is `prepStackVuln()`, which effectively just sorts the checks in the stack vuln, by the stack offset of the check. The next thing after that is the `overwriteVarsHelper()` function, which handles generating the payload parts for overwriting variables, and filling up the space to the return address (although in this instance we are really woried about just overwriting the stack variables). 

In this function, I have a check to see if the function being used is fread. If it is, then I specify that I want to fill up the space to the return address. The reason for this, is `fread` will require a certain amount of bytes to be scanned in, so this verifies that that happens. This isn't present in the correction, and this attack is the only one that has support for this.

After that, I check if the input is through either `stdin` or through `argv`. If it is through `stdin`, I setup the exploit and then construct the payload through the normal means. If is argv however, it is a bit different code path. The `constructPayloadArgv()` differs in the fact that it both sets up, and constructs the payload, since the payload has to be generated and sent when we start the binary. 

Also since exploit verification is a bit different. This is because, the normal exploit verification relies on starting the process, then attaching gdb to it. The issue with doing that with challenges that take input through argv, is by the time gdb actually attaches to the process, the process is done (since the input is given before the `gdb.attach()`). So how I handle exploit verification here, is append a bit of code to the end of the  exploit. This will repeatedly print out output from the binary, while sending it the strin `echo flag{`. That is because, realistically, there are two win conditions we are checking for. One of which is that it just prints the flag, in which case we will parse the output to determine we solved it. The other that is we popped a shell, which the command `echo flag{` will cause it to output the string `flag{`. Either way we just have to parse through the output for the `flag{` string, to determine if we solved the challenge.

For correction for this attack, there is the `correctOverwriteVars()` function. The main difference between this and the normal attack, is this will cycle through the various payload permuations for the different possible ways to deal with the checks.

The base exploit name for these attacks is `exploit-bofVar.py` 

Also one last thing. A lot of the problems that this is the intended solution for, can be solved through other means. As such, you might find a few testcases marked for this attack that are solved through a similar attack, due to the design of remenissions attempting those attacks first.

### Overwrite Return Address to Function - bofFunc

This covers the following attacks:
```
bofFunc
bofFuncArgv
bofFuncWInfoleak
bofSystem
bofSystemWInfoleak
```


So this is the type of attack that overwrites the return address to point to a function. For instance:

```
#include <stdio.h>
#include <stdlib.h>

void win(void)
{
  system("/bin/sh");
}

int main(void)
{
  char hi[20];
  gets(hi);
}
```

Here we have an example of one problem. The solution here is to use the `gets` buffer overflow to overwrite the return address to point to `win`. The things we need to detect for this, is the buffer overflow bug, and the win function, which I covered earlier how remenissions does that. 

Now if you're looking through the attacks for this one, you will see there is a differentiation for the win functions. You will see there's something like `winFuncs` and `possibleWinFuncs`. This is because why the alternate win function detection death stranding does, it can be sometimes ambigous if a function is an alternate win function, so I just mark it as a `possibleWinFuncs`. When I made it this way, I wanted two seperate code paths for dealing with these two things, in case I wanted ot deal with them in seperate ways. However the code paths for dealing with them are pretty identical.

Now let's say we have a binary with source code like this, that has either multiple alternate win functions, or multiple functions that death stranding marks as win functions, when in reality there is only one win function:

```
#include <stdio.h>
#include <stdlib.h>

void falseWin0(void)
{
  system("trashed and scattered");
}

void win(void)
{
  system("/bin/sh");
}

void falseWin1(void)
{
  system("people = shit");
}

void falseWin2(char inp)
{
  system(inp);
}

void vuln(void)
{
  char vuln[20];

  fgets(vuln, 100, stdin);

}

void main(void)
{
  vuln();
}
```

This is where correction kicks in. For correction, for each payload permutation from the overwrite vars functionallity, I will iterate through each win function. That way I cycle through all of the win functions, with the payload permutations.

Now let's say we have this problem, but with a binary that has PIE, so we will need to break aslr in the PIE region in order to know the address to call. For instance this:

```
#include <stdio.h>
#include <stdlib.h>

void win(void)
{
  system("/bin/sh");
}

int main(void)
{
  char hi[20];
  printf("The sin, and the sentence: %p\n", main);
  gets(hi);
}
```

The way Remenissions gets infoleaks, mainly revolves around two things. These two things are leveraging format strings, and when the binary gives you an infoleak like with this challenge. Since we aren't dealing with a format string, we only really have the option where it gives us an infoleak to work with. This doesn't change the attack too much, I just add a call to the `setupPieInfoleak()` at the beginning of each exploit, which sets scanning in and parsing out the infoleak. Then I just specify that the function is from the pie segment, so exploit generation knows to add the pie base to it.

We also have instances like this, where we don't have a win function, but `system` is imported, along with the string `/bin/sh` being in the PIE segment:

```
#include <stdio.h>
#include <stdlib.h>

char *binsh0 = "set me free";
char *binsh1 = "/bin/sh";

void systemFunct(void)
{
        system("echo 'hi'");
}

void vuln(void)
{
  char hi[20];
  fgets(hi, 100, stdin);
} 


void main(void)
{
  vuln();
}
```

Here there isn't a single function we can call to solve the challenge. However what we can do, is call `system` with the argument being `/bin/sh`. This will solve the challenge. For `x64` this means I need to get a `pop rdi ; ret` instruction. For `x86` I just need the address of system and binsh. For correction I just iterate through the different payload permutations (there should only be one system address, so I shouldn't need to iterate through that). I also implemented an attack for that with PIE alsr breaking, that deals with PIE just like how we described.

Also `bufFuncArgv` is essentially just `bufFunc`, except it passes input in through `argv` instead of stdin.

### Overwrite Return Address to Stack Shellcode - bofShellcode

This covers the following attack:
```
bofShellcode
```

So with this type of attack, we are overwritting the return address to point to shellcode that we placed on the stack. For this, we will need a stack overflow bug, and a stack infoleak bug. It's similar to bofFunc attacks, where we are overwritting the saved return address, and parsing out an infoleak (although here, it will be with every exploit, instead of those with just PIE). The main difference is that we are going to have to place shellcode on the stack. This can be complicated when we have a situation like this:

```
#include <stdio.h>
#include <stdlib.h>

void vuln(void)
{
  char buf[10];
  int t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14;
  

  printf("Stack Infoleak: %p\n", buf);

  t1 = t2 = t3 = t4 = t5 = t6 = t7 = t8 = t9 = t10 = t11 = t12 = t13 = t14 = 0xdead;


  fgets(buf, 124, stdin);


  if ((t0 != 0xfacade) && (t14 != 0xfacade))
  {
    exit(0);
  }
}

void main(void)
{
  vuln();
}
```

Here we have a situation, where we need to set certain stack variables to certain constant values, in order to return and get our shellcode to execute. I have three different methods on how to deal with this:

```
0.) place shellcode between cmp values
1.) place shellcode after return address
2.) place shellcode over cmp values, when first two aren't possible
```

Depending on the scenario, we will choose one of the three options. For the last option, I don't bother with setting any of the check values. If we have a large enough write, placing shellcode after the return address will be a great option. This is because it is outside of the stack frame, which for most of the targets remenissions is designed for, that shouldn't get in the way.

Another problem we have to deal with, is how we need to use different shellcodes for different situations. For instance in one example, we may have limited space to store our shellcode. In another, we may have restrictions on the bytes we can scan in (like with `scanf`). To deal with this, I defined a list of different shellcodes for `x86` and `x64`, along with the default one. For the initial use, it will go with the default one (unless if `scanf` is used, which it will go with the `scanf` specific shellcode). If that doesn't work then in correction it will cycle through all of the different shellcodes for that architecture. 

For correction, for each shellcode I iterate through all of the different check permutations. For the initial attack, I use the `placeShellcode()` function, and for correction I use the `correctPlaceShellcode()`. 

Another thing we have to keep track of with those functions, is where we are placing our shellcode in relation to the start of our input. For how I deal with infoleaks, when I get one, I will add / subtract some offset to it, to get a predefined value. For the libc / pie segments, I choose the base of those memory regions. However for simplicity sake with the stack, I choose the start of our input. By keeping track of where our shellcode is in relation to the start of our input, leveraging the existing functionallity to overwrite the saved return address to the start of our shellcode is pretty easy.

### Overwrite Function Pointer - indrCall

This contains the following attacks:

```
indrCall
indrCallPie
indrCallLibc
indrCallShellcode
```

So this type of attack revolves entirely around being able to overwrite a pointer that is indirectly called (write occurs through a buffer overflow). For instance:

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

Here we have a buffer overflow bug, where we can overwrite a function pointer that is indirectly called. I detect this in Death Stranding, as a part of the analysis with a buffer overflow (talked about in the `branch analysis / indirect call` section above). Basically after a buffer overflow, it just checks the proceeding pcodes for a pcode for an indirect call.

Now after we detect an indirect call we can write to with a buffer overflow, the next thing is to decide what we execute. For that I have three options really:

```
Win Function
Shellcode on the Stack
Libc Onegadget
```

The Win Function is the same as the one defined in `bofFunc`. This is where the `indrCall` and `indrCallPie` attacks come from. Realistically the only difference between these two attacks, is `indrCallPie` is for binaries with PIE enabled, and a PIE infoleak is given.

For correction for these attacks, I iterate through overwriting each of the indirect pointers, for each win funciton.

The `indrCallLibc` is only available for `x64` binaries. The reason for this is since it revolves around Onegadget, which requires a lot more setup for `x86` binaries. This requires a libc infoleak to be given. For correction I iterate through all of the available indirect pointers, along with all of the available onegadgets.

Finally there is the `indrCallShellcode`, which stores shellcode on the stack and then overwrites an indirect pointer to that shellcode. For placing the shellcode, it uses the `placeShellcodeIndrCall` function, which is similar to the one used for `bofShellcode`. However instead of overwritting the return address, it focuses on overwritting the pointer instead. For correction, I iterate through all of the shellcodes for the arch, and the reachable indirect ptrs. Also this requires a stack infoleak to be given.

Now for how I actually model the indirect call. I leverage the existing branch analysis functionallity. Essentially I just add a check, that the desired outcome is equal to `"set"`, to specify that the value of the check is what it absolutely should be.
