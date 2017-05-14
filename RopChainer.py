#!/user/bin/env python
import re

class RopChainer(object):
    def __init__(self, gadgets):
        #gadgets.reverse()
        self.__gadgets = gadgets

    # find gadget can make syscall, accept pattern is (nop ;)* int 0x80
    def searchSyscall(self, pattern="int 0x80"):
        gadgets = []
        for g in self.__gadgets:
            codes = g["gadgets"].split(" ; ")
            if codes[-1] == pattern:
                if len(codes)==1:
                    gadgets.append({"vaddr": g["vaddr"]})
                else:
                    canUse = True
                    for c in codes[:-1]:
                        if c!="nop":
                            canUse = False
                            break
                    if canUse:
                        gadgets.append({"vaddr": g["vaddr"]})
        return gadgets

    def searchSingleGadgets(self, pattern):
        gadgets = []

        for g in self.__gadgets:
            codes = g["gadgets"].split(" ; ")

            if len(codes) != 2 or codes[-1] != "ret":
                continue

            if re.search(pattern, codes[-2]):
                    #print "0x%08x : %s" % (g["vaddr"], g["gadgets"])
                    gadgets += [ { "vaddr": g["vaddr"], "gadgets": g["gadgets"]} ]

        return gadgets

    def searchMultiGadgets(self, opcode, reg="e[abcd]x"):
        pattern = opcode + " " + reg
        gadgets = []

        for g in self.__gadgets:
            codes = g["gadgets"].split(" ; ")

            if codes[-1] != "ret" or len(codes) <= 2:
                continue

            all = True
            for c in codes[:-1]:
                if re.search(pattern, c) is None:
                    all = False
                    break

            if all:
                #print "0x%08x : %s" % (g["vaddr"], g["gadgets"])
                gadgets += [ { "vaddr": g["vaddr"], "gadgets":g["gadgets"] } ]

        return gadgets

    # make a generator to put /bin/sh in stack
    def searchShellGadgets(self):
        pattern = "mov dword ptr \[(?P<dst>((eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)))\], (?P<src>((eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)))$"

        for g in self.__gadgets:
            codes = g["gadgets"].split(" ; ")
            # check whether with ret instruction
            check = codes[-1]
            if check!="ret":
                continue
            code = codes[0]
            p = re.search(pattern, code)
            if p:
                find = True
                for check in codes[1:-1]:
                    if check.split()[0]=="pop" or check.split()[0] == "ret":
                        find = False
                        break

                if find:
                    yield [g, p.group("dst"), p.group("src")]
        return
