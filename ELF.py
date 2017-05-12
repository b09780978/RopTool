#!/usr/bin/env python
import sys
from ctypes import *
from capstone import *

"""define format of Header"""

# define ELF file header(32bit)
# from https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
class ELF32_Little_FH(LittleEndianStructure):
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

class ELF32_Big_FH(BigEndianStructure):
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

# define ELF program header(32bit)

class ELF32_Little_PH(LittleEndianStructure):
    _fields_ = [
            ("p_type", c_uint),
            ("p_offset", c_uint),
            ("p_vaddr", c_uint),
            ("p_paddr", c_uint),
            ("p_filesz", c_uint),
            ("p_memsz", c_uint),
            ("p_flags", c_uint),
            ("p_align", c_uint)
            ]

class ELF32_Big_PH(BigEndianStructure):
    _fields_ = [
            ("p_type", c_uint),
            ("p_offset", c_uint),
            ("p_vaddr", c_uint),
            ("p_paddr", c_uint),
            ("p_filesz", c_uint),
            ("p_memsz", c_uint),
            ("p_flags", c_uint),
            ("p_align", c_uint)
            ]

# define ELF segment Header(32bit)

class ELF32_Little_SH(LittleEndianStructure):
    _fields_ = [
            ("sh_name", c_uint),
            ("sh_type", c_uint),
            ("sh_flags", c_uint),
            ("sh_addr", c_uint),
            ("sh_offset", c_uint),
            ("sh_size", c_uint),
            ("sh_link", c_uint),
            ("sh_info", c_uint),
            ("sh_addralign", c_uint),
            ("sh_entsize", c_uint)
            ]

class ELF32_Big_SH(BigEndianStructure):
    _fields_ = [
            ("sh_name", c_uint),
            ("sh_type", c_uint),
            ("sh_flags", c_uint),
            ("sh_addr", c_uint),
            ("sh_offset", c_uint),
            ("sh_size", c_uint),
            ("sh_link", c_uint),
            ("sh_info", c_uint),
            ("sh_addralign", c_uint),
            ("sh_entsize", c_uint)
            ]

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
        self.__format = "ELF"
        self.__binary = bytearray(binary)
        self.__parseHeader()

    def __parseHeader(self):
        self.__parseFileHeader()
        self.__parseProgramHeader()
        self.__parseSectionHeader()

        """check the information from header"""
        #print "Endian is %s" % self.Endian
        #print "EntryPoint is %s" % hex(self.EntryPoint)
        #print "ArchMode is %d" % self.ArchMode

    #parse File Header, Program Header, Section Header
    def __parseFileHeader(self):

        self.Endian = e_ident[ELFFlags.ELF_DATA]
        self.ArchMode = e_ident[ELFFlags.ELF_CLASS]

        # check is 32 bit or 64 bit
        if self.ArchMode == 32:
            self.__Header = ELF32_Little_FH.from_buffer_copy(self.__binary)

        elif self.ArchMode == CS_MODE_64:
            print "This is 64 bit ELF file"
            self.__Header = None

        # choose how to parse binary
        # 32 bit little endian
        if self.ArchMode == CS_MODE_32:
            if self.Endian == "little":
                self.__Header = ELF32_Little_FH.from_buffer_copy(self.__binary)

        # 32 bit big endian
            elif self.Endian == "Big":
                self._Header = ELF32_Big_FH.from_buffer_copy(self.__binary)

        self.Arch = self.__Header.e_machine
        self.EntryPoint = self.__Header.e_entry

    # information about flags from https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcoblk/index.html#chapter6-tbl-39
    def getExecSections(self):
        sections = []
        for section in self.__PH:
            # PF_X is 0x1 (excute)
            if section.p_flags & 0x1:
                sections.append({
                    "vaddr" : section.p_vaddr,
                    "offset" : section.p_offset,
                    "size" : section.p_memsz,
                    "codes" : bytes(self.__binary[section.p_offset:section.p_offset+section.p_memsz])
                    })
        return sections

    def getDataSections(self):
        sections = []
        for section in self.__SH:
            if not (section.sh_flags & 0x4) and (section.sh_flags & 0x2):
                sections.append({
                    "name" : section.sh_name,
                    "offset" : section.sh_offset,
                    "size" : section.sh_size,
                    "vaddr" : section.sh_addr,
                    "codes" : str(self.__binary[section.sh_offset:section.sh_offset+section.sh_size])
                    })
        return sections

    def __parseProgramHeader(self):
        self.__PH = []
        pos = self.__binary[self.__Header.e_phoff:]
        e_phentsize = self.__Header.e_phentsize
        e_phnum = self.__Header.e_phnum

        """
            e_phnum record how many program header entrys
            e_phentsize record size of each program header entry
        """

        for _ in xrange(e_phnum):
            if self.ArchMode == CS_MODE_32:
                if self.Endian == "little":
                    ph = ELF32_Little_PH.from_buffer_copy(pos)
                elif self.Endian == "big":
                    ph = ELF32_Little_PH.from_buffer_copy(pos)
                self.__PH.append(ph)
                pos = pos[e_phentsize:]

    def __parseSectionHeader(self):
        self.__SH = []
        e_shnum = self.__Header.e_shnum
        pos = self.__binary[self.__Header.e_shoff:]
        e_shentsize = self.__Header.e_shentsize

        """
            e_shnum record the numbers of section headers's entry
            e_shentize record the size of each section Header
        """

        for _ in xrange(e_shnum):
            if self.ArchMode == CS_MODE_32:
                if self.Endian == "little":
                    sh = ELF32_Little_SH.from_buffer_copy(pos)
                elif self.Endian == "big":
                    sh = ELF32_Big_SH.from_buffer_copy(pos)
            self.__SH.append(sh)
            pos = pos[e_shentsize:]

    """define some usually use attribute"""

    @property
    def Arch(self):
        return self.__Arch

    @Arch.setter
    def Arch(self, machine_code):
        arch = {
                  0x3  :   CS_ARCH_X86,
                  0x28 :   CS_ARCH_ARM,
                  0x3E :   CS_ARCH_X86
                }
        self.__Arch = arch.setdefault(machine_code)
        #print "Arch is %s" %  self.__Arch

    @property
    def EntryPoint(self):
        return self.__entryPoint

    @EntryPoint.setter
    def EntryPoint(self, entry):
        self.__entryPoint = entry

    @property
    def Endian(self):
        return self.__endian

    @Endian.setter
    def Endian(self, flag):
        self.__endian = {
                ELFFlags.EI_DATA_Big : "big",
                ELFFlags.EI_DATA_Little: "little"
               }.setdefault(flag, "unknow")

    @property
    def ArchMode(self):
        return self.__ArchMode

    @ArchMode.setter
    def ArchMode(self, code):
        self.__ArchMode = {
                ELFFlags.EI_CLASS_32 : CS_MODE_32,
                ELFFlags.EI_CLASS_64 : CS_MODE_64
                }.setdefault(code, 32)

    @property
    def Format(self):
        return self.__format
