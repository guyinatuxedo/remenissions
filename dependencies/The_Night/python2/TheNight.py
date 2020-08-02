import os

# Calculate the offset of the symbols for the current libc
def lookLibcOffset(symbol0, symbol1, file):
    libcFile = open(installDirectory + "symbols/" + file, "r")
    symbol0Found = False
    symbol1Found = False

    offset = 0
    
    for line in libcFile:
        if symbol0Found == symbol1Found == True:
            break
        if symbol0 in line:
            if line.split(" ")[0] == symbol0:
                offset0 = int(line.split(" ")[1], 16)
                symbol0Found = True
        if symbol1 in line:
            if line.split(" ")[0] == symbol1:
                offset1 = int(line.split(" ")[1], 16)
                symbol1Found = True

    if symbol0Found == symbol1Found == True:
        offset = offset0 - offset1 
    
    return offset

# Calculate the offset of the symbols given, and iterate through all of the libcs
def findLibcVersion(symbol0, address0, symbol1, address1):
    offset = address0 - address1

    print "Offset:   " + hex(offset)
    print "Symbol0:  " + symbol0
    print "Symbol1:  " + symbol1
    print "Address0: " + hex(address0)
    print "Address1: " + hex(address1)

    files =  os.listdir(installDirectory + "symbols/")
    for i in files:
        libcOffset = lookLibcOffset(symbol0, symbol1, i)
        if libcOffset == offset:
            print "Possible libc: " + i

