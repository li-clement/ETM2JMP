---
name: etm-to-jmp
description: Convert original-Xbox cheat trainers (.etm Evox Trainer Maker / Team Xored → .jmp Jay's Magic Patcher for xemu/XPSemu) with real-XBE verification. Use when handling .etm or .jmp files, Xbox trainer/cheat conversion, xemu game patches, or XBE byte-patch site analysis.
---

# ETM → JMP (Xbox trainer conversion)

Convert `.etm` trainers into `.jmp` static patches. The whole discipline is
**guards and proof**: every address claim must survive the XBE section table,
the TimeDate guard, and a read-back disassembly before it ships.

Tools live at the root of the `jmp_patch_converter` repo (this skill ships in
its `skill/` dir): `etm2jmp.py` (converter), `validate_jmp.py` (format
re-check), `apply_and_check.py` (apply records to an XBE copy and disassemble
every patched site), `make_test_xbe.py` (synthetic regression fixtures). If
that repo isn't checked out where you are, clone it first. Format tables and
field offsets: [formats.md](formats.md). Every trap already paid for:
[pitfalls.md](pitfalls.md).

## Pipeline

1. **Get `default.xbe`.** `extract-xiso -x game.xiso` or `7z x`; with neither
   installed, locate the first `XBEH` magic in the ISO and cut `SizeOfImage`
   (XBE header +0x10C) bytes from it. Done when the file starts with `XBEH`.
   Guard-only checks need just the first 4KB; hook work needs the full file.

2. **Guard first.**
   `python3 etm2jmp.py trainer.etm --xbe default.xbe --jmp OUT.jmp`
   Read the first line: `GUARD OK` (ETM's TimeDate check == this XBE's
   TimeDate) → same build, continue. `GUARD MISMATCH` → **stop**; the ETM's
   addresses belong to another build and every patch would be garbage. Each
   option is tagged with its section (`[.text]` …); BSS targets are reported
   and skipped rather than guessed.

3. **Runtime hooks** — options the trainer installs in-game as
   `push handler; ret`, whose handler lives in the ETM's own mapped image and
   therefore cannot be copied verbatim into a static record:
   - `--hook-approx`: emits the static equivalent only when it can **prove**
     the site's original bytes differ from the handler's replay. A `REJECTED`
     line is a normal, correct result — it means the handler is a **faithful
     replay** and a displacement rewrite would be a silent no-op.
   - `--hook-cave`: relocates the handler verbatim into verified zero padding —
     XBE **header padding** (`sizeOfHeaders` .. first-page end; classic
     header-cave, the Xbox Pentium III has no NX) preferred, EXECUTABLE-section
     tails as fallback. Refuses rather than guess.
   - When the cheat's mechanism matters, settle it against real code:
     disassemble the function around the site, resolve the store target's
     section (a BSS global?), and decode the ETM's own guard/installer bytes.

4. **Verify end-to-end before shipping.**
   `python3 validate_jmp.py OUT.jmp` then
   `python3 apply_and_check.py OUT.jmp default.xbe`. Every record must read
   back OK, and each hook chain must connect: trampoline → handler →
   `push <site+len>; ret` lands exactly on the instruction after the
   overwritten bytes.

5. **Deploy.** `.jmp` into `/data/xemu/patches/` (XPSemu: game → △ → Game
   patches). Patches apply to the loaded XBE in memory; the ISO stays untouched.

## Worked example (SH4 USA — fully verified)

TimeDate `0x40E173E9` matched the ETM guard. Inf Life site `0x12CB67` was
`movss [esi+0xCB4FE8], xmm0`; the handler replays it behind an `or esi,esi /
je` guard — a **faithful replay**, so `--hook-approx` correctly refused and
`--hook-cave` placed the 18-byte handler at VA `0x109FC` (header padding,
`sizeOfHeaders = 0x9FC`). Mechanism proven from real code: `esi == 0` writes
the global player-health float in `.data` BSS at `0x00CB4FE8`; the handler
skips exactly that store, entity writes replay untouched. The earlier
displacement-rewrite theory was falsified by the site bytes themselves —
delete such artifacts once disproven, don't leave them as traps.
