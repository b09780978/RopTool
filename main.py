#!/usr/bin/env python
import argparse
import sys
from gadgetsFinder import *

parser = argparse.ArgumentParser(description="RopTool is use to find rop gadgets and make rop chain")

parser.add_argument("target", nargs="?", type=str, help="Target file")

args = parser.parse_args()
target = args.target

if target is None:
    parser.print_help()
    sys.exit(0)

finder = GadgetFinder(target)
finder.showGadgets()
