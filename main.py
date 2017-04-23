import argparse
import sys
from ELF import *

parser = argparse.ArgumentParser(description="This is use to try what I do")

parser.add_argument("target", nargs="?", type=str, help="Target to execute")

args = parser.parse_args()
target = args.target

try:
    f = open(target, "rb")
    data = f.read()
    f.close()
except IOError:
    print "[-] Can't open the file"
    sys.exit(0)
