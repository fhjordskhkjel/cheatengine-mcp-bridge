"""Throwaway target process for tests/live_smoke.py (never attach this to anything but a test).

Prints one JSON line with the addresses the smoke test needs, then loops forever:
  * obj.counter is incremented every 20 ms (a data breakpoint target, and "something that changes" for snapshots)
  * kernel32!GetCurrentProcessId is called every iteration (an execute breakpoint target that is hit ~50 times/s)
Everything else in `obj` stays constant so scans and struct reads are deterministic.
"""
import ctypes
import json
import os
import sys
import time


class Obj(ctypes.Structure):
    _fields_ = [("magic", ctypes.c_uint32), ("hp", ctypes.c_int32), ("x", ctypes.c_float), ("y", ctypes.c_float),
                ("counter", ctypes.c_uint64), ("name", ctypes.c_char * 16)]


def main():
    k32 = ctypes.WinDLL("kernel32")
    obj = Obj(0xC0FFEE11, 100, 1.5, -2.25, 0, b"smoke-target")
    scratch = ctypes.create_string_buffer(0x400)             # room for the test to build a fake object in
    api = ctypes.cast(k32.GetCurrentProcessId, ctypes.c_void_p).value
    for dll in sys.argv[1:]:                                  # optional extra DLLs (e.g. msvcp140.dll for RTTI tests)
        try:
            ctypes.WinDLL(dll)
        except OSError:
            pass
    print(json.dumps({
        "pid": os.getpid(), "obj": ctypes.addressof(obj), "counter": ctypes.addressof(obj) + Obj.counter.offset,
        "scratch": ctypes.addressof(scratch), "api": api, "python_dll": "python%d%d.dll" % sys.version_info[:2],
    }), flush=True)
    while True:
        obj.counter += 1
        k32.GetCurrentProcessId()
        time.sleep(0.02)


if __name__ == "__main__":
    main()
