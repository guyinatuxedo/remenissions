# Bug Types

## Stack

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

## Infoleak

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

A few things about this. The desired memory base for PIE and Libc, is the base of those regions. For the stack, it is the start of our input. These infoleaks are used to break ASLR in either the stack, libc, or pie memory regions, to use for certain attacks.

## Fmt String

So for format strings, when they are first detected they are marked as possible format strings. Then after we have all of the bugs, we check if it is an actual format string bug by checking if there is an input that corresponds to the source of the potential format string, which is then marked as the input to the format string bug. An input can either be a stack overflow bug, or an input. Here are the pieces of data I model for both.

Possible Fmt String:

```
type:
function:
callingFunction:
address:
stackoffset:
```

Fmt String:

```
type:
function:
callingFunction:
address:
stackoffset:
inpMethod:
```

## Input

So this is pretty much input to the stack, that isn't an overflow. It is primarily used for format strings, and indirect calls. The things we model are pretty similar to a stack overflow book.

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

## Call Input Bug

So this bug is effectively one where our input is called.

```
function:
callingFunction:
address
offset:
inp_num:
```
