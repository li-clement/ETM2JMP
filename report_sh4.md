# ETM analysis: Silent Hill 4 [plus3] (NTSC).etm

- Trainer: **Silent Hill 4 +3 (NTSC)**
- Author line: `by k_away / Evox-T`
- Title ID: `4B4E001F` (KN-031)
- Version guard: `[00010114] == 40E173E9` (XBE header TimeDate at base+0x114)
- Options: 3
- Address mode: HEURISTIC: file = VA - 0x00010000 (assumes VA-Raw delta == image base for every patched section; verify with --xbe!)
- Header/string model cross-checked against jayxbox's own [ETM Analyzer](https://www.jayxbox.com/Misc/etm-trainer.php)

### Original-byte signature guards

The trainer refuses to patch unless the byte already at the site matches:

| site VA | expected original byte |
|---|---|
| `0x0012CB67` | `0xF3` |
| `0x000F89EE` | `0x49` |
| `0x0016B63A` | `0x40` |


| # | Option | ETM VA -> .JMP file offset : bytes |
|---|--------|------------------------------------|
| 1 | Inf Life | *runtime hook — not statically convertible* |
| 2 | Inf Ammo | `F89EE`→`E89EE` `90` |
| 3 | Saves Never Increase | `16B63A`→`15B63A` `90` |

## Runtime hooks

- Option **1** (Inf Life): site VA `0x0012CB67`, handler at ETM+`0x2E`, back `0x12CB6F` (8 bytes overwritten)

```asm
002E: 0bf6       or esi, esi
0030: 7408       je 0x3a
0032: f30f1186e84fcb00 movss dword ptr [esi + 0xcb4fe8], xmm0
003A: 686fcb1200 push 0x12cb6f
003F: c3         ret
```

The trampoline's 4 immediate bytes are `(ETM load address + offset)`, which only exist while the trainer engine has the ETM mapped in the game process, so they cannot be copied into a static `.JMP` record.

## ✅ VERIFIED against the real XBE (Silent.Hill.4.[USA].iso → default.xbe)

- XBE TimeDate `0x40E173E9` == ETM guard → **same build** (compiled 2004-06-29).
- Site `0x0012CB67` original bytes: `F3 0F 11 86 E84FCB00` = `movss [esi+0xCB4FE8], xmm0`
  — displacement **already equals** the handler's displacement → the handler is a
  faithful replay, the "redirect to a junk slot" theory is dead. `--hook-approx`
  correctly refuses; `--hook-cave` is the only correct static form.
- Mechanism (real function disassembly): the function is the health setter.
  `esi == 0` → the store targets absolute `0x00CB4FE8`, which lies in **.data BSS**
  (section `.data` VA `0x0020FEA0`+`0xDA993C`, raw `0x200000`+`0x1211D4`) = the
  global player-health float. `esi ≠ 0` → entity-relative store. The handler's
  `or esi,esi / je` skips **only the player's health write**; all other entities
  replay normally. All 8 references to `[esi+0xCB4FE8]` in the whole XBE sit in
  the getter/setter cluster `0x12CAFC–0x12CD54`.
- Cave: `sizeOfHeaders = 0x9FC`; file `0x9FC–0x1000` (1542 bytes) is all zero,
  inside the loaded image (image base maps file offset 0), belongs to no section,
  and lies past the section-header table (VA `0x10370` + 12×56 = `0x10610`).
  Handler placed at VA `0x109FC` (18 bytes, verbatim copy of ETM+`0x2E`).
- End-to-end (`apply_and_check.py`): records applied to a copy of default.xbe;
  site becomes `push 0x109FC; ret; nop; nop`; handler replays the `movss` behind
  the esi guard and returns to `0x12CB6F` (`xor eax,eax` epilogue) exactly.
  Inf Ammo site byte `0x49` = real `dec ecx` (ammo decrement), Saves site byte
  `0x40` = real `inc eax` (save counter increment) — NOP semantics confirmed.
- Fidelity: original ETM trampoline is 6 bytes (`68 imm C3`, leaving 2 dead
  bytes); the static version pads with `90 90` — same behavior, cleaner.
- ETM resident flow decoded: `cmp [0x10114],0x40E173E9` (version) →
  `mov edi,0x12CB67; mov ax,0xF390; cmp [edi],ah` (signature) →
  `lea esi,[ebp+0x2E]` → installer writes `68 <handler> C3` at the site.

**Deliverable: `Silent Hill 4 [plus3] (NTSC)_verified.jmp`** (all 3 options).
The earlier `_incl_Inflife.jmp` (displacement rewrite) is proven to be a silent
no-op on this build and was removed.
