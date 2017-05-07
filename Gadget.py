import binascii
import sys
import re
from capstone import *
from ELF import *

class Gadget(object):
    def __init__(self, target_file, rop_length = 10):
        self.__Rawbinary = self.__get_binary(target_file)
        self.__gadgets = self.setGadgets()
        self.__length = rop_length

        self.setGadgets()

    def __get_binary(self, target):
        try:
            f = open(target, "rb")
            self.__Rawbinary = f.read()
            f.close()
        except IOError:
            self.__Rawbinary = None
            print "[-] Can't open the file"
            sys.exit(0)

        self.__parseFileFormat()

    def __parseFileFormat(self):
        if self.__Rawbinary[:4] == binascii.unhexlify(b"7f454c46"):
            self.__binary = ELF(self.__Rawbinary)
        else:
            self.__binary = None
            print "[-] Not support file format"

    def setGadgets(self):
        """
            [   PATTERN     ,PATTERN_SIZE,     CODE_SIZE]
            [       0       ,       1   ,       2       ]
            [return pattern, pattern_size, min code size]
        """
        if self.__binary.Format == "ELF":
            self.__gadgets = [
                   [b"\xc3", 1, 1],             # ret(near)
                   [b"\xcb", 1, 1],             # ret(far)
                   #[b"\xc2{\x00-\xff}", 3, 1],  # ret imm16(near)
                   #[b"\xca{\x00-\xff}", 3, 1],  # ret imm16(far)
                   [b"\x0f\x05", 2, 1],         # syscall
                   [b"\xcd\x80", 2, 1],         # int 0x80
                   ]
        else:
            print "[-] Not support file format"
            sys.exit(0)

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getDataSections(self):
        return self.__binary.getDataSections()

    def findGadgets(self):
        decoder = Cs(self.__binary.Arch, self.__binary.ArchMode)
        PATTERN = 0
        PATTERN_SIZE = 1
        CODE_SIZE = 2
        depth = self.__length
        rets = []
        checkDuplicate = set()  # use to record whether the gadgets is exist

        for section in self.getExecSections():
            code = section["codes"]
            vaddr = section["vaddr"]
            for gad in self.__gadgets:
                gadgets = [ p.start() for p in re.finditer(gad[PATTERN], code)]
                for pos in gadgets:
                    for deep in xrange(depth):
                        if (vaddr+pos-gad[CODE_SIZE]*deep) % gad[CODE_SIZE] == 0:
                             newCode = decoder.disasm(code[pos-gad[CODE_SIZE]*deep:pos+gad[PATTERN_SIZE]], 0)
                             ret = ""
                             for line in newCode:
                                 ret += (line.mnemonic+" "+line.op_str+" ; ").replace("  ", " ")

                             if vaddr+pos-deep*gad[PATTERN_SIZE] in checkDuplicate:
                                 continue

                             if  re.search(gad[PATTERN], line.bytes) is not None and len(ret)>0:
                                 start = vaddr+pos-deep*gad[PATTERN_SIZE]
                                 checkDuplicate.add(vaddr)
                                 rets += [{
                                         "vaddr" : start,
                                         "gadgets" : ret[:-3],
                                         "bytes" : code[pos-deep*gad[CODE_SIZE]:pos+gad[PATTERN_SIZE]],
                                         }]

        rets.sort(key=lambda l: len(l["bytes"]))
        return rets


    def showGadgets(self):
        gadgets = self.findGadgets()
        for g in gadgets:
            print "0x%08x:\t%s" % (g["vaddr"], g["gadgets"])
        print "total:", len(gadgets)

    def getGadgets(self):
        return self.findGadgets()
