#!/user/bin/env python
import re

class RopChainer(object):
    def __init__(self, gadgets):
        #gadgets.reverse()
        self.__gadgets = gadgets

    def searchSyscall(self, pattern="int 0x80"):
        gadgets = []
        for g in self.__gadgets:
            codes = g["gadgets"].split(" ; ")
            if codes[-1] == "int 0x80":
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

