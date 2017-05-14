#!/usr/bin/env sh
# generate a script call auto.py and execute it
python main.py src32 > auto.py
python auto.py
rm auto.py
# clean all pyc file, it will influence test
rm *.pyc
