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
