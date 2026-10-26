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

def build_sh4_like(path, site_bytes=b"\xf3\x0f\x11\x86\x11\x22\x33\x44"):
    """A bigger synthetic XBE that actually COVERS the SH4 hook site, so the
    --hook-approx VERIFIED branch is testable (the 4KB header above cannot:
    the site sits at file 0x11CB67, far past 4KB).
    .text VA 0x00011000 / raw 0x00001000 (delta 0x10000), timedate 0x40E173E9.
    """
    site_va = 0x0012CB67
    raw_len = 0x00200000
    data = bytearray(0x1000 + raw_len)
    data[0:4] = b"XBEH"
    struct.pack_into("<I", data, 0x104, 0x00010000)
    struct.pack_into("<I", data, 0x114, 0x40E173E9)
    struct.pack_into("<I", data, 0x11C, 1)
    struct.pack_into("<I", data, 0x120, 0x00010400)
    off = 0x10500 - 0x10000
    data[off:off + 6] = b".text\x00"
    struct.pack_into("<IIIII", data, 0x400, 0x00000004, 0x00011000, raw_len, 0x00001000, raw_len)
    struct.pack_into("<I", data, 0x400 + 0x14, 0x10500)
    site_off = site_va - 0x00010000
    data[site_off:site_off + len(site_bytes)] = site_bytes
    open(path, "wb").write(bytes(data))
    print(f"wrote {path} ({len(data)} bytes, site 0x{site_va:X} = {site_bytes.hex()})")

def build_sh4_nocave(path):
    """Negative test for --hook-cave: .text is EXECUTABLE but has NO trailing
    zero run, and the only zero padding sits in a WRITEABLE, NON-executable
    .data section. Code placed there is loaded as data and never runs, so the
    tool must REFUSE rather than emit a cave record."""
    raw_text, raw_data = 0x00200000, 0x00010000
    data = bytearray(0x1000 + raw_text + raw_data)
    data[0:4] = b"XBEH"
    struct.pack_into("<I", data, 0x104, 0x00010000)
    struct.pack_into("<I", data, 0x114, 0x40E173E9)
    struct.pack_into("<I", data, 0x11C, 2)
    struct.pack_into("<I", data, 0x120, 0x00010400)
    data[0x500:0x506] = b".text\x00"
    data[0x508:0x50E] = b".data\x00"
    struct.pack_into("<IIIII", data, 0x400, 0x00000004,        # EXECUTABLE
                     0x00011000, raw_text, 0x00001000, raw_text)
    struct.pack_into("<I", data, 0x400 + 0x14, 0x10500)
    struct.pack_into("<IIIII", data, 0x400 + 56, 0x00000001,   # WRITEABLE only
                     0x00211000, raw_data, 0x00001000 + raw_text, raw_data)
    struct.pack_into("<I", data, 0x400 + 56 + 0x14, 0x10508)
    for i in range(0x1000, 0x1000 + raw_text):                 # no zero run in .text
        if data[i] == 0:
            data[i] = 0xFF
    site_off = 0x0012CB67 - 0x00010000
    data[site_off:site_off + 8] = bytes.fromhex("f30f1186e84fcb00")
    open(path, "wb").write(bytes(data))
    print(f"wrote {path} ({len(data)} bytes, executable padding: none)")

def build_bgda2_bss(path):
    """Negative test: .text is declared big enough to CONTAIN the BGDA2 write
    VAs, but its RAW size is short, so those VAs land in .bss (virtual only,
    no file backing). A static .JMP cannot express them -> the tool must
    report and skip them, not crash."""
    data = bytearray(4096)
    data[0:4] = b"XBEH"
    struct.pack_into("<I", data, 0x104, 0x00010000)
    struct.pack_into("<I", data, 0x114, 0x3FAFECB9)
    struct.pack_into("<I", data, 0x11C, 1)
    struct.pack_into("<I", data, 0x120, 0x00010400)
    data[0x500:0x506] = b".text\x00"
    struct.pack_into("<IIIII", data, 0x400, 0x00000004,
                     0x00011000, 0x00190000, 0x00001000, 0x00010000)  # rawsz tiny
    struct.pack_into("<I", data, 0x400 + 0x14, 0x10500)
    open(path, "wb").write(bytes(data))
    print(f"wrote {path} (.text virtual 0x190000 but raw only 0x10000 -> .bss)")

if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "test_xbe_header.bin")
    build("test_xbe_wrongver.bin", timedate=0x11111111)
    build_bgda2_bss("test_xbe_bss.bin")
    build_sh4_like("test_xbe_sh4.bin", site_bytes=bytes.fromhex("f30f118611223344"))
    build_sh4_like("test_xbe_sh4_nofit.bin", site_bytes=bytes.fromhex("9090909090909090"))
    # falsification case: site ALREADY stores to [esi+0xCB4FE8], i.e. the same
    # displacement the handler uses -> redirect would be a silent no-op
    build_sh4_like("test_xbe_sh4_same.bin", site_bytes=bytes.fromhex("f30f1186e84fcb00"))
    build_sh4_nocave("test_xbe_sh4_nocave.bin")


