#!/usr/bin/env sh
python main.py src32 > auto.py
python auto.py
rm auto.py
