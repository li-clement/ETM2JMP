#!/usr/bin/env python3
"""
etm2jmp.py v2 — Convert Xbox .ETM trainers (Evox/Xored Trainer Engine) to
.JMP patches (Jay's Magic Patcher format, used by XPSemu / xemu patch UI).

v2 CORRECTION (important): ETM `mov edi, imm32` targets are RUNTIME VIRTUAL
ADDRESSES, not raw XBE file offsets. Retail XBEs load at base 0x00010000
(xboxdevwiki: header+0x104 "Base Address ... typically 0x00010000"). The ETM
entry prologue proves it:

    mov edi, 0x00010114
    cmp [edi], 0x3FAFECB9     ; header+0x114 = TimeDate (UNIX timestamp)
    jne ret                   ; version guard against the in-memory XBE header

So a VA must be converted to a file offset before writing a .JMP record:

  exact:   --xbe default.xbe  -> walk the XBE section table
           (SectionHeader: +0x04 VirtualAddress, +0x08 VirtualSize,
            +0x0C RawAddress, +0x10 RawSize, entry size 56 bytes;
            table VA at header+0x120, count at header+0x11C,
            table file offset = tableVA - base).
           Also verifies the ETM TimeDate guard against the XBE.
  blind:   file_offset = VA - 0x00010000   (valid for sections whose
           VA-Raw delta equals the image base, e.g. .text; WARN otherwise)

ETM header (little-endian, 35 bytes):
  +0x00 u32 size | +0x04 u16 ver | +0x06 u32 hdr_end(0x23)
  +0x0A u32 option-toggle array ptr | +0x0E u32 string ptr list
  +0x12 u32 title-id list | +0x16 u32 entry | +0x1A/+0x1E reserved
  +0x22 u8 enabled

Code pattern per option (engine runs this code inside the game process;
ebp = ETM load base, so [ebp+disp] addresses the ETM's own flag bytes):

    cmp cs:byte [ebp+flagdisp], 0   ; 2E 80 BD disp32 imm8
    je skip                         ; 74 xx / 0F 84 rel32
    mov edi, <game VA>              ; BF imm32
    mov al, <val>                   ; B0 imm8
    stosb                           ; AA  (write [edi], edi+=1)
    ; also supported: B8/AB stosd, 66 B8/66 AB stosw,
    ;                 C6 07 / C7 07 direct writes, 47 inc edi
skip:

.JMP format (per jayxbox tool_apply-magic-patch.html):
  line0 magic, lines1-6 system/game-title/region/version/author/notes,
  then '#comment' labels the NEXT record; identical comments group under one
  checkbox; '[-]' in comment = default disabled; record: OFFSET:HEX.

Usage:
  python3 etm2jmp.py file.etm [--jmp OUT.jmp] [--report OUT.md] [--disasm]
                      [--xbe default.xbe] [--raw-va] [--game-title NAME]
"""

import argparse
import os
import struct
from collections import OrderedDict

XBE_BASE_TYPICAL = 0x00010000

# ---------------------------------------------------------------- ETM parse

class ETM:
    def __init__(self, data: bytes, name: str = ""):
        self.data = data
        self.name = name
        if len(data) < 0x23:
            raise ValueError("file too small to be an ETM")
        (self.file_size, self.version, self.header_end,
         self.option_ptr, self.string_ptr, self.title_ptr,
         self.start_ptr, self.res1, self.res2) = struct.unpack_from(
            "<IH7I", data, 0)
        self.enabled = data[0x22]
        self.title_ids = []
        off = self.title_ptr
        while off + 4 <= len(data):
            tid = struct.unpack_from("<I", data, off)[0]
            if tid == 0:
                break
            self.title_ids.append(tid)
            off += 4
        n_opts = self.string_ptr - self.option_ptr
        self.options = [data[self.option_ptr + i] for i in range(n_opts)]
        self.strings = []
        off = self.string_ptr
        while off + 4 <= len(data):
            ptr = struct.unpack_from("<I", data, off)[0]
            if ptr == 0:
                break
            self.strings.append(self._cstr(ptr))
            off += 4
        self.trainer_title = self.strings[0] if self.strings else ""
        self.description = self.strings[1] if len(self.strings) > 1 else ""
        self.option_names = self.strings[2:]

    def _cstr(self, off):
        end = self.data.find(b"\x00", off)
        return self.data[off:end].decode("latin-1")


# ------------------------------------------------------- code disasm/extract

class Extractor:
    """Walk the entry code; attribute byte writes to option flags.
    All target addresses are game VAs."""

    def __init__(self, etm: ETM):
        self.d = etm.data
        self.etm = etm
        self.log = []
        self.writes = OrderedDict((i, []) for i in range(len(etm.options)))
        self.writes[None] = []
        self.guard = None          # (va, value) from entry prologue

    def u32(self, off):
        return struct.unpack_from("<I", self.d, off)[0]

    def run(self):
        d = self.d
        i = self.etm.start_ptr
        cur_flag = None
        edi = None
        eax = None                 # al/ax are the low parts of eax
        last_mov_edi = None
        while i < len(d):
            b = d[i]
            # cmp cs:byte [ebp+disp32], imm8  (2E 80 BD disp32 imm8)
            if b == 0x2E and i + 8 <= len(d) and d[i+1] == 0x80 and (d[i+2] & 0xC7) in (0x05, 0x85):
                disp = self.u32(i + 3)
                imm = d[i + 7]
                idx = disp - self.etm.option_ptr
                if 0 <= idx < len(self.etm.options):
                    cur_flag = idx
                    self.log.append((i, f"cmp cs:byte [ebp+0x{disp:X}], {imm}  ; option {idx+1}"))
                else:
                    self.log.append((i, f"cmp cs:byte [ebp+0x{disp:X}], {imm}  ; (unknown flag)"))
                i += 8
                continue
            if b == 0xFC:
                self.log.append((i, "cld")); i += 1; continue
            if b == 0xC3:
                self.log.append((i, "ret")); break
            if b == 0xBF:
                edi = self.u32(i + 1)
                last_mov_edi = i
                self.log.append((i, f"mov edi, 0x{edi:08X}  ; game VA")); i += 5; continue
            if b == 0xB0:
                eax = (eax & 0xFFFFFF00) | d[i + 1] if eax is not None else d[i + 1]
                self.log.append((i, f"mov al, 0x{d[i+1]:02X}")); i += 2; continue
            if b == 0xB8:
                eax = self.u32(i + 1)
                self.log.append((i, f"mov eax, 0x{eax:08X}")); i += 5; continue
            if b == 0x66 and i + 3 <= len(d) and d[i+1] == 0xB8:
                eax = (eax & 0xFFFF0000) | struct.unpack_from("<H", d, i+2)[0] if eax is not None else struct.unpack_from("<H", d, i+2)[0]
                self.log.append((i, f"mov ax, 0x{struct.unpack_from('<H', d, i+2)[0]:04X}")); i += 4; continue
            if b == 0xAA:  # stosb
                if edi is None or eax is None:
                    raise ValueError(f"stosb at 0x{i:X} without edi/eax")
                self.log.append((i, f"stosb  -> [0x{edi:08X}] = 0x{eax & 0xFF:02X}"))
                self.writes[cur_flag].append((edi, bytes([eax & 0xFF])))
                edi += 1
                i += 1
                continue
            if b == 0xAB:  # stosd
                if edi is None or eax is None:
                    raise ValueError(f"stosd at 0x{i:X} without edi/eax")
                self.log.append((i, f"stosd  -> [0x{edi:08X}] = 0x{eax:08X}"))
                self.writes[cur_flag].append((edi, struct.pack("<I", eax)))
                edi += 4
                i += 1
                continue
            if b == 0x66 and i + 1 < len(d) and d[i+1] == 0xAB:  # stosw
                if edi is None or eax is None:
                    raise ValueError(f"stosw at 0x{i:X} without edi/eax")
                self.log.append((i, f"stosw  -> [0x{edi:08X}] = 0x{eax & 0xFFFF:04X}"))
                self.writes[cur_flag].append((edi, struct.pack("<H", eax & 0xFFFF)))
                edi += 2
                i += 2
                continue
            if b == 0xC6 and i + 2 < len(d) and d[i+1] == 0x07:  # mov byte [edi], imm8
                self.log.append((i, f"mov byte [0x{edi:08X}], 0x{d[i+2]:02X}"))
                self.writes[cur_flag].append((edi, bytes([d[i+2]])))
                i += 3; continue
            if b == 0xC7 and i + 5 < len(d) and d[i+1] == 0x07:  # mov dword [edi], imm32
                v = self.u32(i + 2)
                self.log.append((i, f"mov dword [0x{edi:08X}], 0x{v:08X}"))
                self.writes[cur_flag].append((edi, struct.pack("<I", v)))
                i += 6; continue
            if b == 0x47:
                self.log.append((i, "inc edi")); edi += 1; i += 1; continue
            if b == 0x4F:
                self.log.append((i, "dec edi")); edi -= 1; i += 1; continue
            if b in (0x74, 0x75, 0xEB):
                rel = d[i+1] - 256 if d[i+1] > 127 else d[i+1]
                self.log.append((i, f"j{'z' if b==0x74 else 'nz' if b==0x75 else 'mp'} 0x{i+2+rel:X}"))
                i += 2; continue
            if b == 0x0F and i + 6 <= len(d) and d[i+1] in (0x84, 0x85):
                rel = struct.unpack_from("<i", d, i + 2)[0]
                self.log.append((i, f"j{'z' if d[i+1]==0x84 else 'nz'} 0x{i+6+rel:X}"))
                i += 6; continue
            if b == 0x81 and i + 6 <= len(d):
                modrm = d[i+1]; op = (modrm >> 3) & 7
                ops = ['add','or','adc','sbb','and','sub','xor','cmp']
                v = self.u32(i+2)
                self.log.append((i, f"{ops[op]} [edi], 0x{v:08X}"))
                if ops[op] == 'cmp' and last_mov_edi is not None and self.guard is None:
                    self.guard = (edi, v)   # version guard (TimeDate check)
                i += 6; continue
            if b == 0x83 and i + 3 <= len(d):
                modrm = d[i+1]; op = (modrm >> 3) & 7
                ops = ['add','or','adc','sbb','and','sub','xor','cmp']
                self.log.append((i, f"{ops[op]} [edi], 0x{d[i+2]:02X}"))
                i += 3; continue
            self.log.append((i, f"db 0x{b:02X}  ; unhandled"))
            i += 1
        return self.writes


def merge_runs(pairs):
    """[(addr, bytes),...] -> [(addr, bytes)] merging consecutive addrs."""
    runs = []
    for addr, data in pairs:
        if runs and addr == runs[-1][0] + len(runs[-1][1]):
            runs[-1][1] = runs[-1][1] + data
        else:
            runs.append([addr, bytes(data)])
    return [(a, d) for a, d in runs]


# ------------------------------------------------------------- XBE mapping

class XbeMapper:
    """Exact VA -> file offset via the XBE section table."""
    def __init__(self, path):
        self.data = open(path, "rb").read()
        if self.data[:4] != b"XBEH":
            raise ValueError(f"{path}: not an XBE (magic {self.data[:4]!r}, expected b'XBEH')")
        self.base = struct.unpack_from("<I", self.data, 0x104)[0]
        self.timedate = struct.unpack_from("<I", self.data, 0x114)[0]
        nsec = struct.unpack_from("<I", self.data, 0x11C)[0]
        sec_va = struct.unpack_from("<I", self.data, 0x120)[0]
        sec_off = sec_va - self.base
        self.sections = []
        for i in range(nsec):
            off = sec_off + i * 56
            flags, va, vsz, raw, rawsz = struct.unpack_from("<IIIII", self.data, off)
            name = self._name(struct.unpack_from("<I", self.data, off + 0x14)[0])
            self.sections.append((name, va, vsz, raw, rawsz, flags))

    def _name(self, name_va):
        if name_va < self.base:
            return "?"
        off = name_va - self.base
        if off >= len(self.data):
            return "?"
        end = self.data.find(b"\x00", off)
        if end < 0:
            end = len(self.data)
        return self.data[off:end].decode("latin-1", "replace")

    def va_to_off(self, va):
        for name, vaddr, vsz, raw, rawsz, _ in self.sections:
            if vaddr <= va < vaddr + vsz:
                delta = va - vaddr
                if delta < rawsz:
                    return raw + delta, name
                raise ValueError(f"VA 0x{va:X} in {name} BSS (no file backing)")
        raise ValueError(f"VA 0x{va:X} not in any section")

    def report(self):
        out = [f"XBE base=0x{self.base:08X} timedate=0x{self.timedate:08X} "
               f"({__import__('datetime').datetime.utcfromtimestamp(self.timedate)}) sections={len(self.sections)}"]
        for name, va, vsz, raw, rawsz, _ in self.sections:
            out.append(f"  {name:8s} VA=0x{va:08X}+0x{vsz:08X} raw=0x{raw:08X}+0x{rawsz:08X} delta=0x{va-raw:08X}")
        return "\n".join(out)


# --------------------------------------------------------------- JMP output

TITLE_ID_NAMES = {0x4950000A: "IP-010"}

def region_guess(etm: ETM) -> str:
    t = etm.trainer_title.upper()
    if "PAL" in t: return "PAL"
    if "JPN" in t or "JAP" in t: return "JPN"
    if "NTSC" in t or "USA" in t: return "NTSC"
    return "Global"


def build_jmp(etm, runs_by_option, game_title=None, extra_notes=""):
    tid = etm.title_ids[0] if etm.title_ids else 0
    tid_s = f"{tid:08X}"
    name = TITLE_ID_NAMES.get(tid, "")
    version = f"{tid_s} ({name})" if name else tid_s
    title = game_title or etm.trainer_title.split("+")[0].strip() or "Unknown Game"
    author = etm.description.replace("\n", " ").strip() or "ETM Converter"
    notes = (f"Converted from ETM '{etm.trainer_title}' (source: {etm.name}). "
             f"Static XBE byte patches.{extra_notes}")
    lines = [
        "#Jay's Magic Patcher (www.jayxbox.com)",
        "system=Xbox",
        f"game-title={title}",
        f"region={region_guess(etm)}",
        f"version={version}",
        f"author={author}",
        f"notes={notes}",
        "",
    ]
    for opt_idx, runs in runs_by_option.items():
        if not runs:
            continue
        label = (etm.option_names[opt_idx] if isinstance(opt_idx, int)
                 and opt_idx < len(etm.option_names) else f"Option {opt_idx}")
        label = label.replace("\n", " ").strip()
        for addr, data in runs:
            lines.append(f"#[-] {label}")
            lines.append(f"{addr:X}:{data.hex().upper()}")
    lines.append("")
    return "\n".join(lines)


# -------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Convert .ETM trainers to .JMP patches")
    ap.add_argument("etm", help="input .etm file")
    ap.add_argument("--jmp", help="output .jmp path (default: <name>.jmp)")
    ap.add_argument("--report", help="also write a markdown analysis report")
    ap.add_argument("--disasm", action="store_true", help="print disassembly")
    ap.add_argument("--xbe", help="target default.xbe for EXACT VA->offset "
                                  "mapping + TimeDate guard verification")
    ap.add_argument("--raw-va", action="store_true",
                    help="NO conversion: emit ETM immediates verbatim (debug only)")
    ap.add_argument("--game-title", help="override game-title header field")
    args = ap.parse_args()

    raw = open(args.etm, "rb").read()
    etm = ETM(raw, os.path.basename(args.etm))
    ex = Extractor(etm)
    ex.run()

    print(f"== {os.path.basename(args.etm)} ==")
    print(f"  trainer   : {etm.trainer_title}")
    print(f"  author    : {etm.description!r}")
    print(f"  title IDs : {', '.join(f'{t:08X}' for t in etm.title_ids)}")
    print(f"  options   : {len(etm.options)}")

    # address model
    mapper = None
    mode = "RAW-VA (no conversion — debug only!)"
    if args.xbe:
        mapper = XbeMapper(args.xbe)
        mode = f"EXACT via XBE section table ({args.xbe})"
        print("\n  " + mapper.report().replace("\n", "\n  "))
        if ex.guard:
            gva, gval = ex.guard
            if gva - mapper.base == 0x114 and gval == mapper.timedate:
                print(f"  GUARD OK: ETM checks TimeDate 0x{gval:08X} "
                      f"== this XBE's TimeDate -> trainer matches this build")
            else:
                print(f"  GUARD MISMATCH: ETM expects [0x{gva:X}]=0x{gval:08X}, "
                      f"XBE has base 0x{mapper.base:08X} timedate 0x{mapper.timedate:08X} "
                      f"-> WRONG XBE VERSION")
    elif not args.raw_va:
        mode = (f"HEURISTIC: file = VA - 0x{XBE_BASE_TYPICAL:08X} "
                f"(assumes VA-Raw delta == image base for every patched "
                f"section; verify with --xbe!)")
    print(f"  guard     : {('VA 0x%08X == 0x%08X' % ex.guard) if ex.guard else 'none'}")
    print(f"  addr mode : {mode}")

    runs_by_option = OrderedDict()
    va_report = OrderedDict()
    secs_by_option = OrderedDict()
    for opt_idx, pairs in ex.writes.items():
        if opt_idx is None:
            continue
        merged = merge_runs(pairs)
        conv = []
        secs = []
        for va, data in merged:
            if mapper:
                off, sec = mapper.va_to_off(va)
            elif args.raw_va:
                off, sec = va, "?"
            else:
                off, sec = va - XBE_BASE_TYPICAL, "?"
            conv.append((off, data))
            secs.append(sec)
        runs_by_option[opt_idx] = conv
        secs_by_option[opt_idx] = secs
        va_report[opt_idx] = list(zip([a for a, _ in merged], [d for _, d in merged]))

    total = 0
    for opt_idx, runs in runs_by_option.items():
        name = etm.option_names[opt_idx] if opt_idx < len(etm.option_names) else "?"
        nb = sum(len(d) for _, d in runs)
        total += nb
        recs = "; ".join(f"{a:X}:{d.hex().upper()}" for a, d in runs)
        sec_tag = ""
        if mapper:
            uniq = sorted(set(secs_by_option[opt_idx]))
            sec_tag = f"  [{','.join(uniq)}]"
        print(f"  [{opt_idx+1:2d}] {name}  ({nb} bytes){sec_tag}")
        print(f"        {recs}")
    print(f"  total patched bytes: {total}")

    if args.disasm:
        print("\n== disassembly ==")
        for off, txt in ex.log:
            print(f"  {off:04X}: {txt}")

    jmp_path = args.jmp or (os.path.splitext(args.etm)[0] + ".jmp")
    extra = ""
    if args.xbe:
        extra = " Offsets mapped exactly via XBE section table; TimeDate guard verified."
    elif not args.raw_va:
        extra = " Offsets = ETM VA - 0x10000 (heuristic; verify against your XBE with --xbe)."
    open(jmp_path, "w").write(build_jmp(etm, runs_by_option, args.game_title, extra))
    print(f"\nwrote {jmp_path}")

    if args.report:
        with open(args.report, "w") as f:
            f.write(f"# ETM analysis: {os.path.basename(args.etm)}\n\n")
            f.write(f"- Trainer: **{etm.trainer_title}**\n")
            f.write(f"- Author line: `{etm.description}`\n")
            f.write(f"- Title ID: `{' '.join(f'{t:08X}' for t in etm.title_ids)}`\n")
            f.write(f"- Version guard: `[{ex.guard[0]:08X}] == {ex.guard[1]:08X}` "
                    f"(XBE header TimeDate at base+0x114)\n" if ex.guard else "")
            f.write(f"- Options: {len(etm.options)}\n")
            f.write(f"- Address mode: {mode}\n\n")
            f.write("| # | Option | ETM VA -> .JMP file offset : bytes |\n")
            f.write("|---|--------|------------------------------------|\n")
            for opt_idx in runs_by_option:
                name = etm.option_names[opt_idx] if opt_idx < len(etm.option_names) else "?"
                recs = "<br>".join(
                    f"`{va:X}`→`{off:X}` `{d.hex().upper()}`"
                    for (va, _), (off, d) in zip(va_report[opt_idx], runs_by_option[opt_idx]))
                f.write(f"| {opt_idx+1} | {name} | {recs} |\n")
        print(f"wrote {args.report}")


if __name__ == "__main__":
    main()
