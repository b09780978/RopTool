#!/usr/bin/env python
import sys
from ctypes import *
import argparse

parser = argparse.ArgumentParser(description="ELF parser tool is use to parse ELF 32 bit file")

parser.add_argument("target", nargs="?", type=str, help="Target is the ELF 32 file want to parse.")

args = parser.parse_args()

if args.target == None:
    parser.print_help()
    sys.exit(1)

try:
    f = open(args.target, "rb")
    binary = f.read()
except IOError:
    binary = None
f.close()

# define elf file header(32bit)
# from https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
class ELF32_Little(LittleEndianStructure):
    _fields_ = [
            ("e_ident", c_ubyte * 16),
            ("e_type", c_ushort),
            ("e_machine", c_ushort),
            ("e_version", c_uint),
            ("e_entry",  c_uint),
            ("e_phoff", c_uint),
            ("e_shoff", c_uint),
            ("e_flags", c_uint),
            ("e_ehsize", c_ushort),
            ("e_phentsize", c_ushort),
            ("e_phnum", c_ushort),
            ("e_shentsize", c_ushort),
            ("e_shnum", c_ushort),
            ("e_shstrndx", c_ushort),
            ]

class ELF32_Big(BigEndianStructure):
    _fields_ = [
            ("e_ident", c_ubyte * 16),
            ("e_type", c_ushort),
            ("e_machine", c_ushort),
            ("e_version", c_uint),
            ("e_entry",  c_uint),
            ("e_phoff", c_uint),
            ("e_shoff", c_uint),
            ("e_flags", c_uint),
            ("e_ehsize", c_ushort),
            ("e_phentsize", c_ushort),
            ("e_phnum", c_ushort),
            ("e_shentsize", c_ushort),
            ("e_shnum", c_ushort),
            ("e_shstrndx", c_ushort),
            ]

if binary is None:
    print "[+] Read file fail!"
    sys.exit(1)


class ELFFlags(object):
    ELF_CLASS        =  0x4
    ELF_DATA         =  0x5
    ELF_MACHINE      = 0x12
    EI_CLASS_32      =  0x1
    EI_CLASS_64      =  0x2
    EI_DATA_Little   =  0x1
    EI_DATA_Big      =  0x2
    EI_MACHINE_x86   =  0x3
    EI_MACHINE_MIPS  =  0x8
    EI_MACHINE_ARM   = 0x28
    EI_MACHINE_IA64  = 0x32
    EI_MACHINE_x8664 = 0x3E


class ELF(object):
    def __init__(self, binary):
        self.__binary = bytearray(binary)
        self.__parseHeader()

    def __parseHeader(self):
        self.__parse_e_ident()
        self.__setArch()
        print "Arch is %s" % self.Arch

    def __parse_e_ident(self):

        # check whether is ELF file
        e_ident = self.__binary[:16]
        if e_ident[1:4] != "ELF":
            return False

        # check is 32 bit or 64 bit
        if e_ident[ELFFlags.ELF_CLASS] == ELFFlags.EI_CLASS_32:
            #print "This is 32 bit ELF file"
            self.__Header = ELF32_Little.from_buffer_copy(self.__binary)

        elif e_ident[ELFFlags.ELF_CLASS] == ELFFlags.EI_CLASS_64:
            print "This is 64 bit ELF file"

        # choose how to parse binary
        # 32 bit little endian
        if e_ident[ELFFlags.ELF_CLASS] == ELFFlags.EI_CLASS_32 \
            and e_ident[ELFFlags.ELF_DATA] == ELFFlags.EI_DATA_Little:
            self.__Header = ELF32_Little.from_buffer_copy(self.__binary)
            print "32 bit little endian ELF file"

        # 32 bit big endian
        elif e_ident[ELFFlags.ELF_CLASS] == ELFFlags.EI_CLASS_32 \
            and e_ident[ELFFlags.ELF_DATA] == ELFFlags.EI_DATA_Big:
            self._Header = ELF32_Big.from_buffer_copy(self.__binary)
            print "32 bit endian ELF file"

    def __setArch(self):
        machine_code = self.__Header.e_machine
        arch = {
                  0x3  :   "x86",   
                  0x8  :   "MIPS",  
                  0x28 :   "ARM",   
                  0x32 :   "IA64",  
                  0x3E :   "x86-64"
                }
        self.__Arch = arch.setdefault(machine_code, "unknow")
        #print "Arch is %s" %  self.__Arch
    
    @property
    def Arch(self):
        return self.__Arch

elf = ELF(binary)
