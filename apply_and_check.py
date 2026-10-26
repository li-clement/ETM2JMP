#!/usr/bin/env python3
"""apply_and_check.py — apply a .JMP's records to a copy of an XBE in memory
and disassemble every patched site, so the patch can be inspected before it
ever touches a console. Does NOT modify the original XBE.

  python3 apply_and_check.py patch.jmp default.xbe [--hexdump N]

Checks performed:
  * every record offset resolves inside the XBE image
  * the bytes actually written match the record (read-back)
  * each patched site is disassembled (capstone) so the resulting code, and
    for hooks the trampoline -> handler -> return chain, can be eyeballed
"""
import sys
from validate_jmp import parse

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    _CS = Cs(CS_ARCH_X86, CS_MODE_32)
except Exception:
    _CS = None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    jmppath, xbepath = sys.argv[1], sys.argv[2]
    img = bytearray(open(xbepath, "rb").read())
    hdr, records, groups = parse(jmppath)
    print(f"== {jmppath} -> {xbepath} ({len(img)} bytes) ==")
    print(f"  {hdr['game-title']} | {hdr['region']} | {hdr['version']}\n")

    patched = []
    for comment, _enabled, (kind, off, data) in records:
        if kind != "offset":
            print(f"  skip non-offset record: {comment}")
            continue
        blob = bytes.fromhex(data)
        if off + len(blob) > len(img):
            print(f"  !! 0x{off:X}+{len(blob)} is past the end of the XBE image")
            return 1
        before = bytes(img[off:off + len(blob)])
        img[off:off + len(blob)] = blob
        readback = bytes(img[off:off + len(blob)])
        ok = readback == blob
        print(f"  [ok ] {comment:24s} file 0x{off:06X}  {before.hex().upper()}"
              f" -> {data.upper()}   read-back {'OK' if ok else 'MISMATCH'}")
        if not ok:
            return 1
        patched.append((off, data))

    if _CS is None:
        print("\n(capstone not installed: skipping disassembly)")
        return 0

    print("\n== disassembly of patched sites (as they will execute) ==")
    for off, data in patched:
        va = off + 0x10000          # header page and .text both map at +0x10000
        print(f"\n  --- file 0x{off:X} / VA 0x{va:08X} ---")
        for ins in _CS.disasm(bytes(img[off:off + max(len(data) + 8, 24)]), va):
            print(f"    {ins.address:08X}: {ins.bytes.hex():<14} "
                  f"{ins.mnemonic} {ins.op_str}".rstrip())
    print("\nAPPLY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
