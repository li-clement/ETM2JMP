[English](README.md) | [简体中文](README.zh-CN.md)

# ETM → JMP Converter (Xored/Evox cheat trainers → Jay's Magic Patch)

Converts `.etm` files (Evox Trainer Maker / Team Xored Trainer Engine cheat
trainers) into `.jmp` files (Jay's Magic Patcher static memory patches — the
native patch format of the XPSemu / xemu patch UI).

> **v2 erratum (important)**: v1 wrongly assumed the addresses inside an ETM
> were raw XBE file offsets, mappable 1:1. Cross-checked against primary
> sources — xboxdevwiki, caustik's XBE format docs, and xemu's `xbe_header`:
> **retail XBEs load at base `0x00010000` (64KB) and ETM addresses are runtime
> virtual addresses (VA)**, which must be translated to file offsets before
> they can be written into a `.jmp`. Fixed in the current version.
>
> **v3 additions**: support for the hand-written-assembly school (`cmp [edi],ah`
> original-byte signatures, `mov [edi],al` conditional writes,
> `mov word [edi+d]`, `lea esi,[ebp+d]`, `call` subroutines), plus detection of
> **runtime hooks** — options that cannot be made static and are excluded by
> default; see below.
>
> **Format provenance**: the header/string model has been byte-for-byte
> cross-validated against jayxbox's official
> [ETM Analyzer](https://www.jayxbox.com/Misc/etm-trainer.php) parser (tool
> itself at `/tools/tool_etm-trainer.html`); all three samples agree. Note
> that the official tool only parses headers/strings — its disassembler lacks
> the `66` prefix, `38`, `88`, `C6/C7`, `E8`, SSE and more (it read 40 of the
> SH4 sample's 60 instructions as `db`) — **do not** use it to extract patches.


## Address model (core)

The version guard at the ETM code entry proves the VA model:

```asm
mov edi, 0x00010114
cmp [edi], 0x3FAFECB9   ; XBE header base+0x114 = TimeDate (UNIX timestamp)
jne ret                 ; 0x3FAFECB9 = 2003-11-14, BGDA2's compile timestamp
```

Key XBE header fields (xboxdevwiki, little-endian):

| Header offset | Field |
|---|---|
| 0x104 | Base Address (typical retail value `0x00010000`) |
| 0x114 | TimeDate (compile timestamp) |
| 0x11C | Number of Sections |
| 0x120 | Section Headers Address (VA) |

Section-header entries are 56 bytes: `+0x00 Flags, +0x04 VirtualAddress,
+0x08 VirtualSize, +0x0C RawAddress (file offset), +0x10 RawSize,
+0x14 NameAddr, +0x24 SHA1[20]`.

**VA → file offset**:
- **Exact mode (recommended)**: `--xbe default.xbe` translates through the
  section table and automatically checks whether the ETM's TimeDate guard
  matches the target XBE (GUARD OK / MISMATCH).
- **Blind heuristic (default)**: `file = VA − 0x00010000`. Holds for sections
  where `VA − Raw == image base` (typically `.text`: VA `0x11000` ↔ Raw
  `0x1000`); other sections may drift due to alignment. Output carries a
  warning — always double-check with `--xbe`.

## ETM structure (35-byte header + flat x86 code)

| Header offset | Field |
|---|---|
| 0x00 | u32 file size |
| 0x04 | u16 version |
| 0x06 | u32 header length (0x23) |
| 0x0A | u32 → option toggle array (1 byte per option) |
| 0x0E | u32 → string pointer table (title, author, option names) |
| 0x12 | u32 → Title ID list |
| 0x16 | u32 → code entry |
| 0x22 | u8 enable flag |

Each cheat option is a guarded block (the engine runs inside the game process;
`ebp` = ETM load base):

```asm
cmp cs:byte [ebp+flagdisp], 0   ; 2E 80 BD disp32 imm8
je skip
mov edi, <game VA>              ; BF imm32
mov al, <value>                 ; B0 imm8
stosb                           ; AA (write [edi], edi++)
```

The state machine also handles `B8/AB` (stosd), `66 B8/66 AB` (stosw),
`C6 07`/`C7 07` direct writes, and `47/4F` (inc/dec edi).

### v3 addition: the hand-written-assembly school (`Evox-T` / k_away)

ETM Maker's point-and-click template only emits `stosb`; veteran authors hand
wrote assembly. v3 supports:

| Instruction | Encoding | Semantics |
|---|---|---|
| `mov ax, imm16` | `66 B8` | `al` = new byte, `ah` = expected original byte |
| `cmp byte [edi], ah` | `38 27` | **original-byte signature guard** (version check) |
| `mov byte [edi], al` | `88 07` | conditional 1-byte write (`88 47 d8` = `[edi+d8]`) |
| `mov [edi+d], eax/ax` | `89 07` / `66 89 47 d8` | direct write |
| `mov word [edi+d], imm16` | `66 C7 47 d8` | direct write |
| `lea esi, [ebp+d32]` | `8D B5` | `esi` = **pointer into the ETM image itself** |
| `call rel32` / `ret` | `E8` / `C3` | enter a subroutine stub, `ret` returns to caller |

> `E8` is a 1-byte opcode; its `rel32` starts at `i+1` (not `i+2`). In
> `38 27`, `reg=4` inside a REX-less 8-bit instruction is **AH** (not ESP) —
> both were real traps we hit.

### Runtime hooks: options that cannot be made static

The triple `C6 07 68` + `89 77 01` + `C6 47 05 C3` writes `68 <imm32> C3`
(`push handler; ret`) at the game site. When `esi` comes from
`lea esi,[ebp+d]`, those 4 immediate bytes = **ETM load base + offset**, which
only exist while the cheat engine has the ETM mapped into the game process —
they **cannot** be copied verbatim into a `.jmp`. v3 will:

1. locate `push <back>; ret` inside the handler and compute the number of
   overwritten bytes;
2. print the handler disassembly;
3. **exclude the whole option by default** (even its "seemingly static" bytes —
   they are only half a trampoline);
4. `--hook-approx`: if the handler merely **replays** the site's original
   instruction with a different store displacement, the equivalent form is an
   in-place rewrite of those 4 displacement bytes. The script reads the XBE
   site bytes to **prove** the shape (`F3 0F 11 86`) before emitting anything,
   and runs a **falsification check**:
   - site is not that shape → refuse;
   - **site displacement already equals the handler's displacement** → the
     handler is a faithful replay, not a redirect, so rewriting the
     displacement would be a **silent no-op** → refuse and suggest
     `--hook-cave`;
5. `--hook-cave` (general fallback, requires `--xbe`): the handler itself is
   **fully relocatable** (`je` is rel8, `push <game VA>` is an absolute game
   address; only the trampoline immediate depends on the ETM), so the handler
   is copied verbatim into a **verified zero-filled region** inside the XBE and
   the site is pointed at it with `68 <caveVA> C3 90…` — behavior identical to
   the ETM-resident version. Padding regions, in priority order:
   - **XBE header padding (preferred; what SH4 actually uses)**: from
     `sizeOfHeaders` to the end of the first 4KB page (file `0x9FC–0x1000`) —
     inside the loaded image (image base maps file offset 0), belongs to no
     section, lies past the section-header table, and measured all-zero in the
     original file. The Xbox Pentium III has no NX bit, so the header page is
     executable — the classic header-cave technique.
   - **EXECUTABLE-section tail zero padding (fallback)**: XBE section flags
     (verified against Cxbx-Reloaded `src/common/xbe/Xbe.h`): `0x1` WRITEABLE,
     `0x2` PRELOAD, `0x4` **EXECUTABLE**, `0x8` INSERTFILE, `0x10/0x20`
     page-readable-only. A handler placed in a non-executable section is loaded
     as data and never runs — hard requirement; if neither region is found the
     tool refuses outright.



## Usage

```bash
# recommended: pass the game's default.xbe (exact translation + version check)
python3 etm2jmp.py file.etm --xbe default.xbe --jmp OUT.jmp

# no XBE sample: heuristic VA-0x10000 (output carries warnings)
python3 etm2jmp.py file.etm [--jmp OUT.jmp] [--report OUT.md] [--disasm]

# ETM with runtime hooks: try to prove a static equivalent (needs --xbe to verify)
python3 etm2jmp.py file.etm --hook-approx [--xbe default.xbe] --jmp OUT.jmp

# general fallback when it can't be proven: move the handler into XBE zero padding (requires --xbe)
python3 etm2jmp.py file.etm --hook-cave --xbe default.xbe --jmp OUT.jmp

python3 validate_jmp.py OUT.jmp     # re-validate format per jayxbox apply-tool logic
python3 apply_and_check.py OUT.jmp default.xbe
                                    # apply records to a copy of the XBE and disassemble
                                    # every site (trampoline→handler→return chain visible
                                    # to the naked eye; original file untouched)
```

### Full workflow once you have default.xbe

**Step 0: extract `default.xbe`**

```bash
extract-xiso -x game.xiso          # unpack default.xbe (7z x game.xiso also works)
```

Zero-dependency method when neither tool is installed (the path actually used
for SH4) — locate the `XBEH` magic directly in the XISO and slice out
`SizeOfImage` bytes from header field `+0x10C`:

```bash
python3 - <<'PY'
import mmap, struct
mm = mmap.mmap(open("Silent.Hill.4.[USA].iso","rb").fileno(), 0)
i = mm.find(b"XBEH")                                   # first XBEH = default.xbe
sz = struct.unpack_from("<I", mm, i + 0x10C)[0]        # SizeOfImage
open("default.xbe","wb").write(mm[i:i+sz])
print(f"extracted {sz} bytes from ISO offset 0x{i:X}")
PY
```

**Know how big a file to pass** — this is the easiest trap:

| Purpose | XBE range needed |
|---|---|
| VA→file-offset exact translation, TimeDate version check, option→section mapping | first **4KB** (header + section table) is enough |
| `--hook-approx` site-original-instruction verification | **full default.xbe** (must read the site's 8 bytes, often past 1MB) |
| `--hook-cave` executable-section padding search | **full default.xbe** (must confirm the padding really is zero) |

Pass only 4KB while doing the latter two and the tool won't guess — it says
`XBE file is only 4096 bytes … pass the FULL default.xbe`.

**Step 1: version check first**

```bash
python3 etm2jmp.py "Silent Hill 4 [plus3] (NTSC).etm" --xbe default.xbe --jmp OUT.jmp
```

Read the first line of output:

- `GUARD OK: ETM checks TimeDate 0x… == this XBE's TimeDate` → same build, continue;
- `GUARD MISMATCH: …` → **stop**. This is a different XBE version; every
  address in the ETM is wrong for it. Use the matching disc/version (patching
  anyway just crashes).

Each option is also tagged `[.text]/[.rdata]/[.data]`; for first on-hardware
tests, enable only `[.text]` options.

**Step 2: handle runtime hooks** (only for ETMs containing hooks, e.g. SH4's Inf Life)

```bash
python3 etm2jmp.py <etm> --xbe default.xbe --hook-approx --jmp OUT.jmp
```

Three outcomes, decided by the tool — no guessing:

| Output | Meaning | Next step |
|---|---|---|
| `static equivalent … [verified: …]` | site really is `movss [esi+D1]` with `D1 ≠` handler displacement → handler **redirects**; a 4-byte displacement-rewrite record was emitted | use it |
| `REJECTED → site already IS 'movss [esi+0xCB4FE8]…'` | handler is a **faithful replay**; rewriting the displacement is a no-op | go to step 3 |
| `REJECTED → site bytes are …, not 'F3 0F 11 86 …'` | site isn't that instruction at all | go to step 3 |

**Step 3: fallback — move the handler into executable-section padding**

```bash
python3 etm2jmp.py <etm> --xbe default.xbe --hook-cave --jmp OUT.jmp
```

Emits two records: the 18-byte handler in the cave + the site's
`68 <caveVA> C3 90 90`. Zero padding is searched only at the tail of
**EXECUTABLE (flag `0x4`)** sections; if none is found it refuses explicitly —
code is never placed in a non-executable section.

**Step 4: re-validate and deploy**

```bash
python3 validate_jmp.py OUT.jmp
```

**Regression tests** (no real game needed; synthetic XBEs):

```bash
python3 make_test_xbe.py     # generates 6 synthetic XBEs
```

Coverage: GUARD OK/MISMATCH, cross-section alignment-drift translation, BSS
without file backing → **report and skip** (no more stack traces), out-of-range
VA, three hook-site shapes (match / identity / mismatch), executable-section
padding vs non-executable-only padding, truncated-XBE message.


## Converted files in this repo

### Baldur's Gate - Dark Alliance 2 (Title ID `4950000A` → IP-010)

| File | Source | Options | Records |
|---|---|---|---|
| `BGDA2_infinite_trainer_usa.jmp` | `Baldurs Gate - Dark Alliance 2.etm` (+16 NTSC USA) | 16 | 32 |
| `BGDA2_infinite_trainer_ntsc.jmp` | `Baldurs Gate Dark Alliance 2 p16 ntsc.etm` (+16 NTSC) | 16 | 39 |

- Offsets corrected by `VA − 0x10000` (e.g. ETM `0x13B579` → `.jmp` `12B579`).
- The 13 options shared by the two independent ETMs are byte-for-byte identical
  (cross-validation under the same convention).
- **TODO**: once an NTSC (USA) `default.xbe` is available, run `--xbe` once to
  confirm GUARD OK (TimeDate `0x3FAFECB9`) and that every patch site lands in
  the expected section.

### Silent Hill 4: The Room (Title ID `4B4E001F` → KN-031, `by k_away / Evox-T`)

Sample `Silent Hill 4 [plus3] (NTSC).etm` (287 bytes, **SHA-256 identical** to
`Silent Hill 4 p3 ntsc.etm`). Entry at `0x40` (not the usual `0x23`);
`0x23–0x3F` hides the trampoline stub and the handler. Version guard TimeDate
`0x40E173E9` = 2004-06-29. Title ID `4B4E001F`: per xboxdevwiki's definition
(2-letter manufacturer + u16 game number, 3 decimal digits), `KN` = Konami,
`0x1F` = 31 → **KN-031** (same convention as `4950000A` → IP-010).


| # | Option | Site VA | Original-byte guard | Write | `.jmp` offset |
|---|---|---|---|---|---|
| 1 | Inf Life | `0x0012CB67` | `0xF3` | **runtime hook** | see below |
| 2 | Inf Ammo | `0x000F89EE` | `0x49` | `90` (NOP) | `E89EE` |
| 3 | Saves Never Increase | `0x0016B63A` | `0x40` | `90` (NOP) | `15B63A` |

Option 1's trampoline (the ETM installer actually writes only 6 bytes
`68 <ebp+0x2E> C3`, leaving 2 dead bytes; the static version pads to
`68 <caveVA> C3 90 90`); handler:

```asm
002E: 0B F6                    or  esi, esi
0030: 74 08                    je  0x3A
0032: F3 0F 11 86 E84FCB00     movss [esi+0xCB4FE8], xmm0
003A: 68 6FCB1200              push 0x0012CB6F     ; return to site+8
003F: C3                       ret
```

The handler **faithfully replays** the overwritten original instruction with
`movss` (the real XBE confirms the site's original 8 bytes are exactly
`F3 0F 11 86 E84FCB00`, same displacement). The mechanism is `or esi,esi /
je`: when `esi == 0` (the player's global path) the health write is
**skipped**. The site guard byte `0xF3` plus "8 bytes overwritten" exactly
equals the length of `F3 0F 11 86 disp32` — consistent. ~~The early guess that
"rewriting the 4-byte displacement redirects the write to a junk slot" was
falsified by the real XBE~~ (displacement rewrite = no-op); the only correct
static form is `--hook-cave`, see below.

Artifacts (verified against the real XBE, see below):

| File | Contents | Status |
|---|---|---|
| `Silent Hill 4 [plus3] (NTSC)_verified.jmp` | all 3 options (option 1 via header-padding cave) | ✅ end-to-end verified + **live on PS5/XPSemu** (2026-10-26) |
| `Silent Hill 4 [plus3] (NTSC).jmp` | options 2–3 only | ✅ valid (safe subset) |
| ~~`_incl_Inflife.jmp`~~ | option 1 displacement rewrite | ❌ **proven silent no-op, deleted** |

### ✅ Real-XBE verification (`Silent.Hill.4.[USA].iso` → `default.xbe`)

- **GUARD OK**: XBE TimeDate `0x40E173E9` == ETM guard (same build, compiled
  2004-06-29).
- **Redirect theory is dead**: the site `0x0012CB67`'s original 8 bytes are
  exactly `F3 0F 11 86 E84FCB00` — the displacement **already equals** the
  handler's, so `--hook-approx` correctly refuses (displacement rewrite = no-op).
- **Mechanism nailed** (real function disassembly): the function is the health
  setter writing `[esi+0xCB4FE8]`. With `esi == 0` it writes absolute
  `0x00CB4FE8` = **the global player-health variable in .data BSS** (.data VA
  `0x20FEA0`+`0xDA993C`; BSS has no file backing); `esi ≠ 0` is an
  entity-relative write. The handler's `or esi,esi / je` **skips only the
  player's health write**; all other entities replay normally → the player's
  health never updates, monsters take damage normally. The `je` *is* the
  mechanism, not a defensive check. All 8 references to `[esi+0xCB4FE8]` in
  the whole XBE sit inside the health getter/setter cluster
  `0x12CAFC–0x12CD54`.
- **Cave placement (proven safe)**: `sizeOfHeaders = 0x9FC`; file
  `0x9FC–0x1000` (1542 bytes) is all zero — inside the loaded image (image base
  maps file offset 0), belongs to no section, and lies past the section-header
  table (VA `0x10370` + 12×56 = `0x10610`). Handler placed at VA `0x109FC`.
  The Xbox Pentium III has no NX, so the header page is executable — the
  classic header-cave technique.
- **End-to-end read-back** (`apply_and_check.py`): 4 records applied to a copy
  of default.xbe → site becomes `push 0x109FC; ret; nop; nop` → handler
  replays the `movss` → `push 0x12CB6F; ret` lands exactly on the original
  `xor eax,eax` epilogue; the Inf Ammo site is a real `dec ecx` (ammo
  decrement) and the Saves site a real `inc eax` (save-counter increment) —
  NOP semantics confirmed.
- **Fidelity**: the handler in the cave is byte-identical to ETM+`0x2E`
  (including return address `0x12CB6F`). The original ETM trampoline is only 6
  bytes (`68 imm C3`, 2 dead bytes left); the static version pads to 8 bytes
  with `90 90` — same behavior, cleaner.
- ETM-resident behavior decoded (disassembled straight from ETM machine code):
  entry first checks `cmp [0x10114], 0x40E173E9` (version), then
  `mov ax,0xF390; cmp [edi],ah` (original-byte signature), then
  `lea esi,[ebp+0x2E]` + `call` — the installer writes `68 <handler> C3` at the
  site. Equivalent to the static version.

The handler is actually **18 bytes** (`0x2E–0x3F`); the `je` is `74 08`.
`make_test_xbe.py` turns these cases into regression tests
(`test_xbe_sh4*.bin`).

### ✅ Hardware verification (XPSemu / PS5, 2026-10-26)

- Deployed `Silent Hill 4 [plus3] (NTSC)_verified.jmp` (all 3 options) to
  XPSemu on PS5: **Inf Life / Inf Ammo / Saves Never Increase all work**.
- This closes the last link static read-back (`apply_and_check.py`) could not
  prove: **the header-padding cave (VA `0x109FC`) is genuinely executable
  under the real loader** — `push 0x109FC; ret` trampolines into the handler,
  the `movss` replays, `push 0x12CB6F; ret` returns exactly, no crash. The
  classic header-cave trick (Xbox Pentium III has no NX, header page
  executable) holds on xemu-family loaders.
- **Direct behavioral confirmation of the mechanism (follow-up test)**: dog
  fight at the bathroom door of Henry's apartment — dog bites deal **no damage
  to the player**, yet the dog **can be killed normally**. Both branches of the
  same health setter verified once each: `esi == 0` (player global path) write
  skipped by `je`; `esi ≠ 0` (entity path) `movss` replayed, dog health drains
  to death. The patch does not freeze enemies or block progression.


**Pitfalls** (things easy to misread when analyzing this file; all verified by
byte-level search):

- `38 27` is `cmp [edi], AH`, not `cmp [edi], AL`; `88 07` is `mov [edi], AL`,
  not `mov [edi], AH` — what gets written is `al` (the `0x90` NOP); `ah` is
  only the expected original byte.
- The sites are `0x0012CB67 / 0x000F89EE / 0x0016B63A`, not `0x0005CB67 /
  0x001389EE / 0x0015B63A`.
- The file contains **no** `BE/BF 80 03 01 00` (`mov esi/edi,0x00010380`),
  `B9 04 00 00 00` (`mov ecx,4`), or `F3 A5` (`rep movsd`) — i.e. **no** logic
  copying a cave into XBE header slack; the handler simply runs from the ETM
  image, so the trampoline immediate depends on the ETM's resident address.
- The Title ID is `4B4E001F` (`1F 00 4E 4B`), not `4B4E001B`.


## .JMP format notes (against jayxbox's `tool_apply-magic-patch.html` parser)

- First 7 lines fixed: magic + `system/game-title/region/version/author/notes`.
- `version=` contains the Title ID; `{8-hex}` triggers an XBE CRC32 check (not
  used in these files).
- `#comment` marks the following record; identical comments merge into one
  checkbox group; `[-]` = off by default (matches ETM's all-off default;
  mutually exclusive options avoid clashing).
- Only in-place `offset:HEX` overwrite records; no `APPEND:` (XPSemu doesn't
  support it). "Better Shop"'s `E9` jump target is existing game code, fully
  reproducible with static writes.

## Bundled agent skill (`skill/etm-to-jmp/`)

The whole workflow is distilled into a reusable agent skill, shipped with the
repo:

```
skill/etm-to-jmp/
├── SKILL.md      5-step pipeline (get XBE → guard first → hook handling → read-back → deploy) + SH4 worked example
├── formats.md    ETM / XBE / .JMP format tables, section-table layout, Title ID convention (loaded on demand)
└── pitfalls.md   every real trap hit: 38 27=cmp[edi],AH, 56-byte section entries, rb"\x86" raw literals,
                  faithful-replay ⇒ displacement-rewrite-is-a-no-op falsification rule… (loaded on demand)
```

Install into any machine's agent skill directory (locally: `~/.agents/skills/`):

```bash
cp -r skill/etm-to-jmp ~/.agents/skills/
```

Once installed, no need to remember skill names: mention `.etm`/`.jmp`/xemu
patches/XBE patch sites and the agent auto-loads this real-XBE-verified
pipeline. **The `skill/` directory is the single source of truth** — improve
the pipeline there, then sync back to your local skill directory.

## Deploying to XPSemu (PS5)

1. Put the `.jmp` into `/data/xemu/patches/`.
2. Select the game → **△** → Game patches → tick the cheats you want.
3. Patches are applied in place to the XBE in memory at load time; the
   original XISO is never modified.

> **Hardware verification (2026-10-26)**: `Silent Hill 4 [plus3]
> (NTSC)_verified.jmp` — all 3 options deployed via the steps above on PS5
> XPSemu **all took effect** (including Inf Life's header-cave handler). See
> the hardware-verification section above.

If a cheat does nothing or crashes: most likely the heuristic offsets don't
match your XBE's section alignment (or the XBE version is wrong) — regenerate
with `--xbe` exact mode.
