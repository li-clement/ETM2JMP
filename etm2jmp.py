#!/usr/bin/env python3
"""
etm2jmp.py v3 — Convert Xbox .ETM trainers (Evox/Xored Trainer Engine) to
.JMP patches (Jay's Magic Patcher format, used by XPSemu / xemu patch UI).

Header + string model verified byte-for-byte by running jayxbox's OWN ETM
Analyzer parser (https://www.jayxbox.com/Misc/etm-trainer.php, tool body at
/tools/tool_etm-trainer.html) against every sample in this repo.

  +0x00 u32 FileSize | +0x04 u16 Version | +0x06 u32 HeaderLength (0x23)
  +0x0A u32 -> OptionListToggle (1 byte per option, 0 = default disabled)
  +0x0E u32 -> stringPointerList (title, description, option1..N; null-term)
  +0x12 u32 -> titleIDList (null-term)
  +0x16 u32 -> Start/Entry point | +0x1A/+0x1E reserved | +0x22 u8 enabled

  From the reference tool: the *description* string ends at a DOUBLE null and
  inner NULs are line breaks (v3 now matches that).

Address model (v2 correction, unchanged): ETM `mov edi, imm32` targets are
RUNTIME VIRTUAL ADDRESSES; retail XBEs load at base 0x00010000.

    mov edi, 0x00010114
    cmp [edi], 0x3FAFECB9     ; header+0x114 = TimeDate -> version guard
    jne ret

  exact:  --xbe default.xbe  (walk XBE section table + verify TimeDate guard)
  blind:  file_offset = VA - 0x00010000   (heuristic; WARN)

v3 adds the hand-written idioms found in "Silent Hill 4 +3 (NTSC)" (k_away),
which the ETM-Maker `stosb` template never emits:

  66 B8 imm16        mov ax, imm16          (al = new byte, ah = expected byte)
  38 27              cmp byte [edi], ah     original-byte signature guard
  88 07 / 88 47 d8   mov byte [edi(+d)], al   conditional 1-byte write
  89 07 / 89 47 d8   mov [edi(+d)], eax       (66 prefix -> ax)
  C6 07 / C6 47 d8   mov byte [edi(+d)], imm8
  C7 07 / C7 47 d8   mov [edi(+d)], imm32     (66 prefix -> imm16)
  8D B5 d32          lea esi, [ebp+d32]     esi = pointer INTO the ETM image
  E8 rel32 / C3      call helper stub / ret back to caller
  90                 nop
  0B F6              or esi, esi
  F3 0F 11 86 d32    movss [esi+d32], xmm0  (runtime handler code)
  C6 07 68 + 89 77 01 + C6 47 05 C3
                     -> writes `push <esi>; ret` = RUNTIME HOOK trampoline

RUNTIME HOOKS: the 4 immediate bytes of that trampoline are
(ETM load address + offset), which only exist while the trainer engine has
the ETM mapped inside the game process, so they cannot be copied verbatim
into a static .JMP record. v3 instead *proves* a static equivalent when it
can: if the patched site is a single instruction whose shape the handler
mirrors (e.g. the handler re-executes the same `movss [esi+disp], xmm0` with
a redirected displacement), the equivalent is a small in-place field rewrite.
Use --hook-approx (with --xbe for verification) to emit those records; by
default hook options are reported and left out.
"""

import argparse
import os
import struct
from collections import OrderedDict

XBE_BASE_TYPICAL = 0x00010000

# XBE section header flags (verified: Cxbx-Reloaded src/common/xbe/Xbe.h)
XBE_SEC_WRITEABLE = 0x1
XBE_SEC_PRELOAD = 0x2
XBE_SEC_EXECUTABLE = 0x4

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    _CS = Cs(CS_ARCH_X86, CS_MODE_32)
except Exception:                                    # capstone is optional
    _CS = None


def disasm(blob, base=0):
    """Human-readable disassembly (capstone if present, else raw hex)."""
    if _CS is None:
        return ["(capstone not installed) " + blob.hex()]
    out = []
    for ins in _CS.disasm(blob, base):
        out.append(f"{ins.address:04X}: {ins.bytes.hex():<10} {ins.mnemonic} {ins.op_str}".rstrip())
    return out


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
        # jayxbox ETM Analyzer: description is double-null terminated,
        # single NULs inside it are line breaks.
        self.description = self._dstr(struct.unpack_from("<I", data, self.string_ptr + 4)[0]) \
            if len(self.strings) > 1 else ""
        self.option_names = self.strings[2:]

    def _cstr(self, off):
        end = self.data.find(b"\x00", off)
        return self.data[off:end].decode("latin-1")

    def _dstr(self, off):
        out, i = [], off
        while i < len(self.data):
            b = self.data[i]
            if b == 0:
                if i + 1 < len(self.data) and self.data[i + 1] == 0:
                    break
                out.append("\n")
            else:
                out.append(chr(b))
            i += 1
        return "".join(out).strip()


# ------------------------------------------------------- code disasm/extract

class Extractor:
    """Walk the entry code; attribute byte writes to option flags.
    [edi]-relative targets are game VAs; [ebp+disp] is the ETM image itself."""

    def __init__(self, etm: ETM):
        self.d = etm.data
        self.etm = etm
        self.log = []
        # writes[flag] = [(va, bytes, etm_relative)]
        self.writes = OrderedDict((i, []) for i in range(len(etm.options)))
        self.writes[None] = []
        self.guard = None          # (va, value) dword TimeDate guard
        self.byte_guards = []      # (va, expected_byte) from cmp [edi], ah
        self.hooks = []            # push/ret trampolines
        self.cur_flag = None
        self.esi = None
        self.esi_etm = False
        self.call_stack = []

    def u32(self, off):
        return struct.unpack_from("<I", self.d, off)[0]

    def _emit(self, addr, data, rel=False):
        if addr is None:
            raise ValueError(f"write of {data!r} with edi unset (option {self.cur_flag})")
        self.writes[self.cur_flag].append((addr, data, rel))

    def _edi_disp(self, modrm_off, modrm):
        """Decode a modrm that addresses EDI: [edi] / [edi+disp8] / [edi+disp32].
        Returns (disp, extra_bytes_after_modrm), else None."""
        mod = (modrm >> 6) & 3
        reg = (modrm >> 3) & 7
        rm = modrm & 7
        if rm != 7 or reg == 4:          # rm must be EDI; reg==4 means SIB
            return None
        if mod == 0:
            return 0, 0
        if mod == 1 and modrm_off + 2 <= len(self.d):
            b = self.d[modrm_off + 1]
            return (b - 256 if b > 127 else b), 1
        if mod == 2 and modrm_off + 5 <= len(self.d):
            return struct.unpack_from("<i", self.d, modrm_off + 1)[0], 4
        return None

    def run(self):
        d = self.d
        i = self.etm.start_ptr
        edi = None
        eax = None
        last_mov_edi = None
        while i < len(d):
            b = d[i]

            # ---- option flag test: cmp cs:byte [ebp+disp32], imm8
            if (b == 0x2E and i + 8 <= len(d) and d[i + 1] == 0x80
                    and (d[i + 2] & 0xC7) in (0x05, 0x85)):
                disp = self.u32(i + 3)
                imm = d[i + 7]
                idx = disp - self.etm.option_ptr
                if 0 <= idx < len(self.etm.options):
                    self.cur_flag = idx
                    self.log.append((i, f"cmp cs:byte [ebp+0x{disp:X}], {imm}  ; option {idx + 1}"))
                else:
                    self.log.append((i, f"cmp cs:byte [ebp+0x{disp:X}], {imm}  ; (unknown flag)"))
                i += 8
                continue

            # ---- 0x66 (operand-size) prefixed forms
            if b == 0x66 and i + 1 < len(d):
                nb = d[i + 1]
                if nb == 0xB8 and i + 4 <= len(d):                      # mov ax, imm16
                    v = struct.unpack_from("<H", d, i + 2)[0]
                    eax = (eax & 0xFFFF0000) | v if eax is not None else v
                    self.log.append((i, f"mov ax, 0x{v:04X}  ; al=0x{v & 0xFF:02X} ah=0x{(v >> 8) & 0xFF:02X}"))
                    i += 4
                    continue
                if nb == 0xAB:                                          # stosw
                    if edi is None or eax is None:
                        raise ValueError(f"stosw at 0x{i:X} without edi/eax")
                    self.log.append((i, f"stosw  -> [0x{edi:08X}] = 0x{eax & 0xFFFF:04X}"))
                    self._emit(edi, struct.pack("<H", eax & 0xFFFF))
                    edi += 2
                    i += 2
                    continue
                if nb == 0x89 and i + 3 <= len(d):                      # mov [edi(+d)], ax
                    m = self._edi_disp(i + 2, d[i + 2])
                    if m is not None:
                        disp, used = m
                        v = (eax or 0) & 0xFFFF
                        self._emit(edi + disp, struct.pack("<H", v))
                        self.log.append((i, f"mov word [0x{edi + disp:08X}], 0x{v:04X}"))
                        i += 3 + used
                        continue
                if nb == 0xC7 and i + 3 <= len(d):                      # mov word [edi(+d)], imm16
                    m = self._edi_disp(i + 2, d[i + 2])
                    if m is not None:
                        disp, used = m
                        v = struct.unpack_from("<H", d, i + 3 + used)[0]
                        self._emit(edi + disp, struct.pack("<H", v))
                        self.log.append((i, f"mov word [0x{edi + disp:08X}], 0x{v:04X}"))
                        i += 3 + used + 2
                        continue
                self.log.append((i, f"db 0x66  ; unhandled 66-prefixed {nb:02X}"))
                i += 1
                continue

            if b == 0xFC:
                self.log.append((i, "cld")); i += 1; continue
            if b == 0xC3:
                if self.call_stack:
                    back = self.call_stack.pop()
                    self.log.append((i, f"ret  -> back to 0x{back:X}"))
                    i = back
                    continue
                self.log.append((i, "ret")); break
            if b == 0x90:
                self.log.append((i, "nop")); i += 1; continue
            if b == 0xBF:
                edi = self.u32(i + 1)
                last_mov_edi = i
                self.log.append((i, f"mov edi, 0x{edi:08X}  ; game VA")); i += 5; continue
            if b == 0xB0:
                eax = (eax & 0xFFFFFF00) | d[i + 1] if eax is not None else d[i + 1]
                self.log.append((i, f"mov al, 0x{d[i + 1]:02X}")); i += 2; continue
            if b == 0xB8:
                eax = self.u32(i + 1)
                self.log.append((i, f"mov eax, 0x{eax:08X}")); i += 5; continue
            if b == 0xAA:                                              # stosb
                if edi is None or eax is None:
                    raise ValueError(f"stosb at 0x{i:X} without edi/eax")
                self.log.append((i, f"stosb  -> [0x{edi:08X}] = 0x{eax & 0xFF:02X}"))
                self._emit(edi, bytes([eax & 0xFF]))
                edi += 1; i += 1; continue
            if b == 0xAB:                                              # stosd
                if edi is None or eax is None:
                    raise ValueError(f"stosd at 0x{i:X} without edi/eax")
                self.log.append((i, f"stosd  -> [0x{edi:08X}] = 0x{eax:08X}"))
                self._emit(edi, struct.pack("<I", eax))
                edi += 4; i += 1; continue
            if b == 0x47:
                self.log.append((i, "inc edi")); edi += 1; i += 1; continue
            if b == 0x4F:
                self.log.append((i, "dec edi")); edi -= 1; i += 1; continue

            # ---- original-byte signature guard: cmp byte [edi], ah
            if b in (0x38, 0x3A) and i + 2 <= len(d) and d[i + 1] == 0x27:
                exp = (eax >> 8) & 0xFF if eax is not None else None
                self.byte_guards.append((edi, exp))
                self.log.append((i, f"cmp byte [0x{edi:08X}], ah = 0x{exp:02X}  ; original-byte guard"
                                    if exp is not None else
                                    f"cmp byte [0x{edi:08X}], ah  ; original-byte guard"))
                i += 2; continue

            # ---- mov byte [edi(+d)], al
            if b == 0x88 and i + 2 <= len(d):
                m = self._edi_disp(i + 1, d[i + 1])
                if m is not None:
                    disp, used = m
                    val = (eax or 0) & 0xFF
                    self._emit(edi + disp, bytes([val]))
                    self.log.append((i, f"mov byte [0x{edi + disp:08X}], al = 0x{val:02X}"))
                    i += 2 + used; continue

            # ---- mov [edi(+d)], <reg32>
            if b == 0x89 and i + 2 <= len(d):
                modrm = d[i + 1]
                m = self._edi_disp(i + 1, modrm)
                if m is not None:
                    disp, used = m
                    reg = (modrm >> 3) & 7
                    addr = edi + disp
                    if reg == 6 and self.esi_etm:
                        # mov [edi+d], esi  where esi points INTO the ETM image
                        self._emit(addr, b"\x00\x00\x00\x00", rel=True)
                        self.hooks.append({"site": edi, "handler": self.esi,
                                           "option": self.cur_flag, "instr_off": i})
                        self.log.append((i, f"mov [0x{addr:08X}], esi  ; esi = ETM image +0x{self.esi:X}"
                                            "  <-- RUNTIME POINTER"))
                    elif reg == 0:
                        self._emit(addr, struct.pack("<I", eax or 0))
                        self.log.append((i, f"mov dword [0x{addr:08X}], 0x{(eax or 0):08X}"))
                    else:
                        self.log.append((i, f"mov [0x{addr:08X}], reg#{reg}  ; unmodelled source"))
                    i += 2 + used; continue

            # ---- mov byte [edi(+d)], imm8
            if b == 0xC6 and i + 2 <= len(d):
                m = self._edi_disp(i + 1, d[i + 1])
                if m is not None:
                    disp, used = m
                    imm = d[i + 2 + used]
                    self._emit(edi + disp, bytes([imm]))
                    note = "  ; trampoline opcode 'push imm32'" if (disp == 0 and imm == 0x68) else ""
                    self.log.append((i, f"mov byte [0x{edi + disp:08X}], 0x{imm:02X}{note}"))
                    i += 2 + used + 1; continue

            # ---- mov [edi(+d)], imm32
            if b == 0xC7 and i + 2 <= len(d):
                m = self._edi_disp(i + 1, d[i + 1])
                if m is not None:
                    disp, used = m
                    v = self.u32(i + 2 + used)
                    self._emit(edi + disp, struct.pack("<I", v))
                    self.log.append((i, f"mov dword [0x{edi + disp:08X}], 0x{v:08X}"))
                    i += 2 + used + 4; continue

            # ---- lea esi, [ebp+disp32]  (pointer into the ETM image)
            if b == 0x8D and i + 6 <= len(d) and d[i + 1] == 0xB5:
                self.esi = self.u32(i + 2)
                self.esi_etm = True
                self.log.append((i, f"lea esi, [ebp+0x{self.esi:X}]  ; pointer into ETM image"))
                i += 6; continue

            # ---- or esi, esi
            if b == 0x0B and i + 2 <= len(d) and d[i + 1] == 0xF6:
                self.log.append((i, "or esi, esi")); i += 2; continue

            # ---- call rel32 / push imm32
            if b == 0xE8 and i + 5 <= len(d):
                rel = struct.unpack_from("<i", d, i + 1)[0]   # E8 is a 1-byte opcode
                tgt = i + 5 + rel
                self.log.append((i, f"call 0x{tgt:X}  ; helper stub"))
                self.call_stack.append(i + 5)
                i = tgt; continue
            if b == 0x68 and i + 5 <= len(d):
                v = self.u32(i + 1)
                self.log.append((i, f"push 0x{v:08X}"))
                i += 5; continue

            # ---- SSE stores used by runtime handlers
            if b == 0xF3 and i + 8 <= len(d) and d[i + 1] == 0x0F and d[i + 2] == 0x11 \
                    and (d[i + 3] & 0xC7) == 0x86:
                disp = self.u32(i + 4)
                self.log.append((i, f"movss [esi+0x{disp:X}], xmm0  ; runtime handler code"
                                    " (needs game register context)"))
                i += 8; continue
            if b == 0x0F and i + 7 <= len(d) and d[i + 1] == 0x11 and (d[i + 2] & 0xC7) == 0x86:
                disp = self.u32(i + 3)
                self.log.append((i, f"movups [esi+0x{disp:X}], xmm0  ; runtime handler code"))
                i += 7; continue

            # ---- jumps
            if b in (0x74, 0x75, 0xEB):
                rel = d[i + 1] - 256 if d[i + 1] > 127 else d[i + 1]
                self.log.append((i, f"j{'z' if b == 0x74 else 'nz' if b == 0x75 else 'mp'} 0x{i + 2 + rel:X}"))
                i += 2; continue
            if b == 0x0F and i + 6 <= len(d) and d[i + 1] in (0x84, 0x85):
                rel = struct.unpack_from("<i", d, i + 2)[0]
                self.log.append((i, f"j{'z' if d[i + 1] == 0x84 else 'nz'} 0x{i + 6 + rel:X}"))
                i += 6; continue

            # ---- ALU group on [edi]
            if b == 0x81 and i + 6 <= len(d):
                modrm = d[i + 1]; op = (modrm >> 3) & 7
                ops = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
                v = self.u32(i + 2)
                self.log.append((i, f"{ops[op]} [edi], 0x{v:08X}"))
                if ops[op] == 'cmp' and last_mov_edi is not None and self.guard is None:
                    self.guard = (edi, v)      # TimeDate version guard
                i += 6; continue
            if b == 0x83 and i + 3 <= len(d):
                modrm = d[i + 1]; op = (modrm >> 3) & 7
                ops = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp']
                self.log.append((i, f"{ops[op]} [edi], 0x{d[i + 2]:02X}"))
                i += 3; continue

            self.log.append((i, f"db 0x{b:02X}  ; unhandled"))
            i += 1
        return self.writes

    def analyze_hooks(self):
        """For each `push <handler>; ret` trampoline, locate the handler's
        `push <back>; ret` to learn how many bytes at the site were replaced,
        and pull out the handler's own memory store if it has one."""
        for h in self.hooks:
            off = h["handler"]
            blob = self.d[off:off + 48]
            h["blob"] = blob
            h["text"] = disasm(blob, off)
            h["back"] = None
            for j in range(len(blob) - 5):
                if blob[j] == 0x68 and blob[j + 5] == 0xC3:
                    h["back"] = struct.unpack_from("<I", blob, j + 1)[0]
                    break
            h["length"] = (h["back"] - h["site"]) if (h["back"] and h["back"] >= h["site"]) else None
            if h["back"]:
                blob = blob[:j + 6]           # stop the display at 'push <back>; ret'
                h["blob"] = blob
                h["text"] = disasm(blob, off)
            # handler's own store: movss [esi+disp], xmm0
            h["store_disp"] = None
            for j in range(len(blob) - 7):
                if blob[j] == 0xF3 and blob[j + 1] == 0x0F and blob[j + 2] == 0x11 \
                        and (blob[j + 3] & 0xC7) == 0x86:
                    h["store_disp"] = struct.unpack_from("<I", blob, j + 4)[0]
                    break


def hook_static_equivalent(h, mapper):
    """Prove a static equivalent for a push/ret trampoline.

    Shape we can prove:
      site (original)   : F3 0F 11 86 <d1>   movss [esi+d1], xmm0   (len == hook len)
      handler           : or esi,esi / je / movss [esi+d2], xmm0 / push site+len / ret
    The handler re-executes the SAME store with the destination redirected, so
    the static equivalent is rewriting the 4-byte displacement field in place:
      site+4 : <d2 little endian>
    Returns (offset_key, bytes, note) or None when it cannot be proven.
    """
    disp2 = h.get("store_disp")
    ln = h.get("length")
    if disp2 is None or ln is None:
        return None
    site = h["site"]
    if mapper is None:
        return (site + 4, struct.pack("<I", disp2),
                f"UNVERIFIED: assumes {ln} bytes at 0x{site:X} are "
                f"'F3 0F 11 86 <disp32>' (guard byte 0x?; run with --xbe)")
    try:
        off, sec = mapper.va_to_off(site)
    except ValueError as e:
        h["reject"] = str(e)
        return None
    if off + ln > len(mapper.data):
        h["reject"] = (f"XBE file is only {len(mapper.data)} bytes but the site is at "
                       f"file offset 0x{off:X} — pass the FULL default.xbe, not just "
                       f"its 4KB header")
        return None
    orig = mapper.data[off:off + ln]
    if len(orig) < ln or orig[0] != 0xF3 or orig[1:4] != b"\x0f\x11\x86":
        h["reject"] = (f"site bytes are {orig.hex()}, not 'F3 0F 11 86 <disp32>' "
                       f"-> the handler is not replaying this site's instruction")
        return None
    d1 = struct.unpack_from("<I", orig, 4)[0]
    if d1 == disp2:
        # Falsification: the site ALREADY stores to [esi+disp2], so the handler
        # is a faithful replay, not a redirect. Rewriting the displacement would
        # write the bytes that are already there = a silent no-op. The cheat's
        # mechanism must be something else -> use --hook-cave instead.
        h["reject"] = (f"site already IS 'movss [esi+0x{d1:X}], xmm0' -- identical to the "
                       f"handler's own store, so the handler is a faithful replay, NOT a "
                       f"redirect. A displacement rewrite would be a silent no-op. "
                       f"Use --hook-cave to place the handler in a code cave instead.")
        return None
    return (site + 4, struct.pack("<I", disp2),
            f"verified: {ln} bytes at 0x{site:X} are "
            f"'movss [esi+0x{d1:X}], xmm0' -> redirect to [esi+0x{disp2:X}]")


def find_cave(mapper, need, near_va=0, avoid=()):
    """Conservative code-cave search: a run of zeros at the END of a section's
    file-backed raw range, in an EXECUTABLE section only.

    XBE section flags (verified against Cxbx-Reloaded src/common/xbe/Xbe.h):
      0x1 WRITEABLE  0x2 PRELOAD  0x4 EXECUTABLE  0x8 INSERTFILE
      0x10 HEAD_PAGE_READONLY  0x20 TAIL_PAGE_READONLY
    A cave in a non-executable section would be loaded as data and never run,
    so EXECUTABLE is mandatory, not a preference.
    Returns (cave_va, section_name, flags) or None."""
    best = None
    for name, va, vsz, raw, rawsz, flags in mapper.sections:
        if not (flags & XBE_SEC_EXECUTABLE):
            continue
        end = raw + rawsz
        if end > len(mapper.data):
            continue                       # header-only XBE: cannot verify bytes
        n = 0
        while n < rawsz and mapper.data[end - 1 - n] == 0:
            n += 1
        if n < need:
            continue
        cave_va = va + rawsz - need
        if any(cave_va < b + e and b < cave_va + need for b, e in avoid):
            continue
        cand = (abs(cave_va - near_va), cave_va, name, flags)
        if best is None or cand[0] < best[0]:
            best = cand
    return (best[1], best[2], best[3]) if best else None


def merge_runs(pairs):
    """[(addr, bytes, rel),...] -> [(addr, bytes, rel)] merging consecutive."""
    runs = []
    for addr, data, rel in pairs:
        if runs and addr == runs[-1][0] + len(runs[-1][1]) and rel == runs[-1][2]:
            runs[-1][1] = runs[-1][1] + data
        else:
            runs.append([addr, bytes(data), rel])
    return [(a, d, r) for a, d, r in runs]


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

TITLE_ID_NAMES = {0x4950000A: "IP-010", 0x4B4E001F: "KN-031"}


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
        for addr, data, note in runs:
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
    ap.add_argument("--hook-approx", action="store_true",
                    help="emit a PROVEN static equivalent for runtime hooks "
                         "(strongly recommended together with --xbe)")
    ap.add_argument("--hook-cave", action="store_true",
                    help="general fallback for runtime hooks: copy the handler "
                         "into verified XBE zero-padding and point the "
                         "trampoline there (requires --xbe)")
    ap.add_argument("--game-title", help="override game-title header field")
    args = ap.parse_args()

    raw = open(args.etm, "rb").read()
    etm = ETM(raw, os.path.basename(args.etm))
    ex = Extractor(etm)
    ex.run()
    ex.analyze_hooks()

    print(f"== {os.path.basename(args.etm)} ==")
    print(f"  trainer   : {etm.trainer_title}")
    print(f"  author    : {etm.description!r}")
    print(f"  title IDs : {', '.join(f'{t:08X}' for t in etm.title_ids)}")
    print(f"  options   : {len(etm.options)}")

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
    if ex.byte_guards:
        print("  byte guards (original-byte signatures the trainer checks first):")
        for va, exp in ex.byte_guards:
            print(f"        [0x{va:08X}] == 0x{exp:02X}")
    print(f"  addr mode : {mode}")

    # An option that contains ANY ETM-relative write is a runtime hook: its
    # static-looking bytes are only half a trampoline, so suppress them all.
    hook_opts = {o for o, pairs in ex.writes.items()
                 if o is not None and any(rel for _, _, rel in pairs)}
    if ex.hooks:
        print(f"  runtime hooks: {len(ex.hooks)} (options "
              f"{', '.join(str(o + 1) for o in sorted(x for x in hook_opts if x is not None))})")
        for h in ex.hooks:
            print(f"    site VA 0x{h['site']:08X} -> handler at ETM+0x{h['handler']:X}"
                  f"{' , back to 0x%08X (%d bytes overwritten)' % (h['back'], h['length']) if h['length'] else ''}")
            for line in h["text"]:
                print(f"        {line}")

    runs_by_option = OrderedDict()
    va_report = OrderedDict()
    secs_by_option = OrderedDict()
    unmapped = []          # (opt_idx, va, reason) VAs with no file backing
    for opt_idx, pairs in ex.writes.items():
        if opt_idx is None:
            continue
        merged = merge_runs(pairs)
        conv, secs, var = [], [], []
        if opt_idx in hook_opts:
            runs_by_option[opt_idx] = conv
            secs_by_option[opt_idx] = secs
            va_report[opt_idx] = var
            continue
        for va, data, rel in merged:
            if mapper:
                try:
                    off, sec = mapper.va_to_off(va)
                except ValueError as e:
                    unmapped.append((opt_idx, va, str(e)))
                    continue
            elif args.raw_va:
                off, sec = va, "?"
            else:
                off, sec = va - XBE_BASE_TYPICAL, "?"
            conv.append((off, data, None))
            secs.append(sec)
            var.append((va, data))
        runs_by_option[opt_idx] = conv
        secs_by_option[opt_idx] = secs
        va_report[opt_idx] = var

    # optional proven static equivalents for the hooks
    approx_notes = []
    if args.hook_approx:
        for h in ex.hooks:
            if h["option"] is None or h["option"] not in runs_by_option:
                continue
            eq = hook_static_equivalent(h, mapper)
            if not eq:
                why = h.get("reject") or ("site bytes not verified (run with --xbe)"
                                          if mapper is None else "no provable static equivalent")
                print(f"  HOOK at 0x{h['site']:X}: displacement-redirect equivalent REJECTED -> {why}")
                continue
            off, data, note = eq
            try:
                if mapper:
                    foff, sec = mapper.va_to_off(off)
                else:
                    foff, sec = off - XBE_BASE_TYPICAL, "?"
            except ValueError as e:
                print(f"  HOOK at 0x{h['site']:X}: equivalent VA not file-backed ({e})")
                continue
            runs_by_option[h["option"]].append((foff, data, note))
            va_report[h["option"]].append((off, data))
            secs_by_option[h["option"]].append(sec)
            approx_notes.append(f"Option {h['option'] + 1}: hook at VA 0x{h['site']:X} "
                                f"reproduced as in-place displacement rewrite at VA 0x{off:X} ({note})")
            print(f"  HOOK at 0x{h['site']:X} -> static equivalent VA 0x{off:X} = "
                  f"{data.hex().upper()}  [{note}]")

    # general fallback: move the (fully relocatable) handler into XBE padding
    if args.hook_cave:
        if mapper is None:
            ap.error("--hook-cave needs --xbe: the cave address must be a real, "
                     "verified file-backed location in the target XBE")
        truncated = [n for n, _va, _vsz, raw, rawsz, _f in mapper.sections
                     if raw + rawsz > len(mapper.data)]
        if truncated:
            print(f"  note: XBE is truncated to {len(mapper.data)} bytes; sections not "
                  f"fully present and therefore skipped by the cave search: "
                  f"{', '.join(truncated)}")
        for h in ex.hooks:
            if h["option"] is None or h["option"] not in runs_by_option:
                continue
            blob = h["blob"]                      # handler bytes, ends at its 'ret'
            ln = h["length"] or 8
            found = find_cave(mapper, len(blob), h["site"], avoid=[(h["site"], ln)])
            if not found:
                print(f"  HOOK at 0x{h['site']:X}: no code cave of {len(blob)} bytes found "
                      f"(searched only EXECUTABLE sections, flag 0x{XBE_SEC_EXECUTABLE:02X}, "
                      f"for trailing zero padding)")
                continue
            cave_va, sec, flags = found
            s_off, s_sec = mapper.va_to_off(h["site"])
            c_off, _ = mapper.va_to_off(cave_va)
            guard = next((e for va, e in ex.byte_guards if va == h["site"]), None)
            gtxt = "" if guard is None or mapper.data[s_off] == guard \
                 else f"  !! site byte is 0x{mapper.data[s_off]:02X}, trainer expected 0x{guard:02X}"
            tramp = b"\x68" + struct.pack("<I", cave_va) + b"\xC3" + b"\x90" * (ln - 6)
            runs_by_option[h["option"]].append((c_off, bytes(blob), f"handler in {sec} padding"))
            runs_by_option[h["option"]].append((s_off, tramp, f"push 0x{cave_va:X}; ret"))
            va_report[h["option"]].append((cave_va, bytes(blob)))
            va_report[h["option"]].append((h["site"], tramp))
            secs_by_option[h["option"]].append(sec)
            secs_by_option[h["option"]].append(s_sec)
            approx_notes.append(f"Option {h['option'] + 1}: handler ({len(blob)} bytes) placed at "
                                f"VA 0x{cave_va:X} in {sec} padding; site trampoline points there")
            print(f"  HOOK at 0x{h['site']:X} -> handler {len(blob)} bytes to VA 0x{cave_va:X} "
                  f"[{sec} padding]; site := {tramp.hex().upper()}{gtxt}")

    total = 0
    for opt_idx, runs in runs_by_option.items():
        name = etm.option_names[opt_idx] if opt_idx < len(etm.option_names) else "?"
        nb = sum(len(d) for _, d, _ in runs)
        total += nb
        recs = "; ".join(f"{a:X}:{d.hex().upper()}" for a, d, _ in runs)
        sec_tag = ""
        if mapper:
            uniq = sorted(set(secs_by_option[opt_idx]))
            sec_tag = f"  [{','.join(uniq)}]"
        flag = "  (RUNTIME HOOK — see above)" if opt_idx in hook_opts and not runs else ""
        print(f"  [{opt_idx + 1:2d}] {name}  ({nb} bytes){sec_tag}{flag}")
        if recs:
            print(f"        {recs}")
    print(f"  total patched bytes: {total}")
    if unmapped:
        print(f"  !! {len(unmapped)} write target(s) have NO file backing and were SKIPPED:")
        for opt_idx, va, why in unmapped:
            nm = etm.option_names[opt_idx] if opt_idx < len(etm.option_names) else "?"
            print(f"        option {opt_idx + 1} ({nm}) VA 0x{va:08X}: {why}")
        print("        these are runtime-only addresses (.bss / heap); a static "
              ".JMP record cannot express them")

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
    if hook_opts and not (args.hook_approx or args.hook_cave):
        extra += " Runtime-hook options are NOT included (they need the ETM resident in game memory)."
    open(jmp_path, "w").write(build_jmp(etm, runs_by_option, args.game_title, extra))
    print(f"\nwrote {jmp_path}")

    if args.report:
        with open(args.report, "w") as f:
            f.write(f"# ETM analysis: {os.path.basename(args.etm)}\n\n")
            f.write(f"- Trainer: **{etm.trainer_title}**\n")
            f.write(f"- Author line: `{etm.description}`\n")
            f.write(f"- Title ID: `{' '.join(f'{t:08X}' for t in etm.title_ids)}`"
                    f"{' (' + TITLE_ID_NAMES[etm.title_ids[0]] + ')' if etm.title_ids and etm.title_ids[0] in TITLE_ID_NAMES else ''}\n")
            f.write(f"- Version guard: `[{ex.guard[0]:08X}] == {ex.guard[1]:08X}` "
                    f"(XBE header TimeDate at base+0x114)\n" if ex.guard else "")
            f.write(f"- Options: {len(etm.options)}\n")
            f.write(f"- Address mode: {mode}\n")
            f.write("- Header/string model cross-checked against jayxbox's own "
                    "[ETM Analyzer](https://www.jayxbox.com/Misc/etm-trainer.php)\n\n")
            if ex.byte_guards:
                f.write("### Original-byte signature guards\n\n")
                f.write("The trainer refuses to patch unless the byte already at the site matches:\n\n")
                f.write("| site VA | expected original byte |\n|---|---|\n")
                for va, exp in ex.byte_guards:
                    f.write(f"| `0x{va:08X}` | `0x{exp:02X}` |\n")
                f.write("\n")
            f.write("\n| # | Option | ETM VA -> .JMP file offset : bytes |\n")
            f.write("|---|--------|------------------------------------|\n")
            for opt_idx in runs_by_option:
                name = etm.option_names[opt_idx] if opt_idx < len(etm.option_names) else "?"
                recs = "<br>".join(
                    f"`{va:X}`→`{off:X}` `{d.hex().upper()}`"
                    for (va, _), (off, d, _) in zip(va_report[opt_idx], runs_by_option[opt_idx]))
                if opt_idx in hook_opts and not recs:
                    recs = "*runtime hook — not statically convertible*"
                f.write(f"| {opt_idx + 1} | {name} | {recs} |\n")
            if ex.hooks:
                f.write("\n## Runtime hooks\n\n")
                for h in ex.hooks:
                    f.write(f"- Option **{h['option'] + 1}** "
                            f"({etm.option_names[h['option']] if h['option'] is not None and h['option'] < len(etm.option_names) else '?'}): "
                            f"site VA `0x{h['site']:08X}`, handler at ETM+`0x{h['handler']:X}`, "
                            f"back `0x{h['back']:X}` ({h['length']} bytes overwritten)\n")
                    f.write("\n```asm\n")
                    f.write("\n".join(h["text"]))
                    f.write("\n```\n\n")
                    f.write("The trampoline's 4 immediate bytes are "
                            "`(ETM load address + offset)`, which only exist while the "
                            "trainer engine has the ETM mapped in the game process, so "
                            "they cannot be copied into a static `.JMP` record.\n")
            for n in approx_notes:
                f.write(f"\n> {n}\n")
        print(f"wrote {args.report}")


if __name__ == "__main__":
    main()
