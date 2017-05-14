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
s = ScriptMaker(gadget, 1)
s.make_script()
