"""Manual / integration verification target.

Holds a couple of known values at stable addresses so you can exercise the real
Windows memory engine (attach / read / scan / modify) against a harmless
process you own.

Usage:
    python samples/target.py [info_file]

It prints (and optionally writes to ``info_file``) its PID and the addresses of
an int32 and a float value, then loops printing the current values so you can
watch them change when you modify them with game-modifier.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time

# Unusual sentinel values so a memory scan finds very few candidates.
INT_VALUE = 133731337   # 0x07F91B49
FLOAT_VALUE = 1234.5


def main() -> int:
    ival = ctypes.c_int32(INT_VALUE)
    fval = ctypes.c_float(FLOAT_VALUE)
    iaddr = ctypes.addressof(ival)
    faddr = ctypes.addressof(fval)

    info = (
        f"PID={os.getpid()}\n"
        f"INT_ADDR={hex(iaddr)}\n"
        f"FLOAT_ADDR={hex(faddr)}\n"
        f"INT_VALUE={ival.value}\n"
        f"FLOAT_VALUE={fval.value}\n"
    )
    sys.stdout.write(info)
    sys.stdout.flush()
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8") as fh:
            fh.write(info)

    while True:
        time.sleep(1.0)
        sys.stdout.write(f"int={ival.value} float={fval.value}\n")
        sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
