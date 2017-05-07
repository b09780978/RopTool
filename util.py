#!/usr/bin/env python
import struct

def p32(data):
    return struct.pack("<I", data)

def pStr(word):
    if len(word)>4:
        return None
    value = 0
    for c in word[::-1]:
        value = value*16*16 + ord(c)
    #return hex(value)
    return value

