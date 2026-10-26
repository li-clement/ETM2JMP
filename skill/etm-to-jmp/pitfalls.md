# Traps already paid for

Each of these cost real debugging time in the SH4/BGDA2 sessions.

## x86 decoding of ETM code

- `38 27` is `cmp [edi], AH` — in 8-bit form `reg=4` means **AH**, not ESP.
  `88 07` writes **AL** (the new byte); `ah` only carries the expected
  original byte for the signature guard.
- `E8` (call) is a 1-byte opcode: the `rel32` starts at `i+1`, not `i+2`.
- The jayxbox online ETM analyzer mis-decodes `66` prefixes, `38`, `88`,
  `C6/C7`, `E8`, and SSE (40 of 60 SH4 instructions became `db`). Trust
  capstone, not that tool, for extraction.

## XBE parsing

- Section header stride is **56** bytes, not 40/0x28 — a wrong stride yields
  one plausible entry then garbage.
- The section-name field is a **VA pointer**; dereference it (`name_va − base`
  as file offset), don't read it as inline text.
- `VirtualSize > RawSize` means BSS: a patch VA landing there has no file
  bytes to write — report and skip, never guess.
- Heuristic `file = VA − 0x10000` silently drifts on sections whose
  `VA − Raw ≠ base`. Only `--xbe` section-table mapping is trustworthy.

## Python gotchas while carving/patching

- `rb"\x86"` is a **raw** literal: bytes `5c 78 38 36` (ASCII `\x86`), not
  byte `0x86`. Build binary patterns with `bytes.fromhex("86e8...")`.
- Slicing a `bytearray` with `len(hexstring)` instead of `len(bytes)` shrinks
  the image and shifts every later offset — convert to bytes first.
- `mmap` objects: `len(mm)`, not `mm.length()`.

## Hook staticization

- A handler that replays the site's own instruction with the **same**
  displacement makes a displacement rewrite a **silent no-op**. Prove the
  site bytes differ before emitting any "equivalent" record; otherwise use
  the cave path.
- The original trainer's trampoline is 6 bytes (`68 imm C3`) over an 8-byte
  instruction, leaving 2 dead bytes; pad with `90 90` instead.
- Header padding (`sizeOfHeaders` .. first-page end) is inside the loaded
  image (image base maps file offset 0), belongs to no section, and sits
  past the section-header table — verify all three, plus that the bytes are
  actually zero, before using it as a cave. The Xbox Pentium III has no NX,
  so the header page executes.
- Cave in a non-EXECUTABLE section = loaded as data, never runs. Hard
  condition, not preference.

## Process

- Trust the guard chain end to end: ETM TimeDate check → XBE TimeDate →
  per-site original-byte signature (`cmp [edi], ah`) → read-back disassembly
  of the applied patch. A theory that survives reading the ETM bytes but
  dies on the site bytes (the SH4 "redirect" theory) must delete its
  artifacts, not just gain a warning.
