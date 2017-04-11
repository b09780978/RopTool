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
    ELF_CLASS = 0x4
    ELF_CLASS_32 = 0x1
    ELF_CLASS_64 = 0x2

class ELF(object):
    def __init__(self, binary):
        self.__binary = bytearray(binary)
        self.parseHeader()

    def parseHeader(self):
        self.e_ident = self.__binary[:16]
        if self.e_ident[ELFFlags.ELF_CLASS] == ELFFlags.ELF_CLASS_32:
            self.__Header = ELF32_Little.from_buffer_copy(self.__binary)
            print self.__Header.e_ident[:-1]
            print len(self.__Header.e_ident)

elf = ELF(binary)
