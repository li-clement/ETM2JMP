#!/usr/bin/env python3
"""make_test_xbe.py — synthesize a BGDA2-like XBE *header* (4KB) to
end-to-end test etm2jmp.py --xbe: section-table conversion, alignment
drift, GUARD OK/MISMATCH, BSS rejection, truncated-header input.

Layout mimics a plausible retail XBE with deliberate VA-Raw drift:
  .text  VA 0x00011000 size 0x190000  raw 0x00001000  (delta 0x10000)
  .rdata VA 0x001A1000 size 0x0C0000  raw 0x00191800  (delta 0x10800, +0x800 drift)
         raw size 0xBF000 -> last 0x1000 bytes are BSS (no file backing)
  .data  VA 0x00261000 size 0x0D0000  raw 0x00252000  (delta 0x0F000, -0x1000 drift)
"""
import struct, sys

def build(path, timedate=0x3FAFECB9):
    data = bytearray(4096)
    data[0:4] = b"XBEH"
    struct.pack_into("<I", data, 0x104, 0x00010000)   # base
    struct.pack_into("<I", data, 0x114, timedate)     # timedate
    struct.pack_into("<I", data, 0x11C, 3)            # nsections
    struct.pack_into("<I", data, 0x120, 0x00010400)   # section hdrs VA
    # names at file 0x500 (VA 0x10500)
    names = {".text": 0x10500, ".rdata": 0x10508, ".data": 0x10512}
    for n, va in names.items():
        off = va - 0x10000
        data[off:off+len(n)+1] = n.encode() + b"\x00"
    secs = [
        # flags, VA, VSize, RawAddr, RawSize, nameVA
        (0x00000004, 0x00011000, 0x00190000, 0x00001000, 0x00190000, names[".text"]),
        (0x00000005, 0x001A1000, 0x000C0000, 0x00191800, 0x000BF000, names[".rdata"]),
        (0x00000005, 0x00261000, 0x000D0000, 0x00252000, 0x000D0000, names[".data"]),
    ]
    for i, (fl, va, vsz, raw, rawsz, nva) in enumerate(secs):
        off = 0x400 + i * 56
        struct.pack_into("<IIIII", data, off, fl, va, vsz, raw, rawsz)
        struct.pack_into("<I", data, off + 0x14, nva)
    open(path, "wb").write(bytes(data))
    print(f"wrote {path} ({len(data)} bytes, timedate=0x{timedate:08X})")

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "test_xbe_header.bin")
    build("test_xbe_wrongver.bin", timedate=0x11111111)
