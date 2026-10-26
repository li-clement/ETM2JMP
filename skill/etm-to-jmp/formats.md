# Format reference (verified byte-level)

## ETM (Evox Trainer Maker / Team Xored) — 35-byte header + flat x86

| Header off | Field |
|---|---|
| 0x00 | u32 file size |
| 0x04 | u16 version |
| 0x06 | u32 header length (0x23) |
| 0x0A | u32 → option toggle bytes (1 per option) |
| 0x0E | u32 → string pointer table (title, author, option names) |
| 0x12 | u32 → Title ID list |
| 0x16 | u32 → code entry |
| 0x22 | u8 enabled flag |

Code runs inside the game process; `ebp` = ETM load base. Common idioms:

| Bytes | Meaning |
|---|---|
| `2E 80 BD d32 imm8` | `cmp cs:byte [ebp+d], imm8` — option toggle check |
| `BF imm32` | `mov edi, <game VA>` — patch site |
| `B0 imm8` / `AA` | `mov al, val` + `stosb` (template-generated writes) |
| `66 B8 imm16` | `mov ax`: `al` = new byte, `ah` = expected original byte |
| `38 27` | `cmp byte [edi], AH` — original-byte signature guard |
| `88 07` | `mov byte [edi], AL` — conditional write |
| `8D B5 d32` | `lea esi, [ebp+d]` — esi points **inside the ETM image** |
| `C6 07 68` + `89 77 01` + `C6 47 05 C3` | runtime trampoline installer: writes `68 <imm32> C3` (`push handler; ret`) at the site |

The installer's 4 immediate bytes are `ETM load base + offset` — they exist
only while the trainer engine maps the ETM, so they cannot be copied into a
static `.jmp` record.

## XBE header (little-endian, retail base `0x00010000`)

| Offset | Field |
|---|---|
| 0x00 | magic `XBEH` |
| 0x104 | Base Address |
| 0x108 | SizeOfHeaders (e.g. SH4: `0x9FC`) |
| 0x10C | SizeOfImage (use to carve default.xbe out of an ISO) |
| 0x114 | TimeDate — the version guard every ETM checks |
| 0x11C | Number of sections |
| 0x120 | Section headers address (VA) |

Section header entry: **56 bytes** each.
`+0x00 Flags, +0x04 VirtualAddress, +0x08 VirtualSize, +0x0C RawAddress
(file offset), +0x10 RawSize, +0x14 NameAddr (a VA pointer, not inline text),
+0x24 SHA1[20]`. Flags (per Cxbx-Reloaded `Xbe.h`): `0x1` WRITEABLE,
`0x2` PRELOAD, `0x4` **EXECUTABLE**, `0x8` INSERTFILE, `0x10`/`0x20` page
read-only. `VirtualSize > RawSize` ⇒ the tail is BSS (no file backing).

VA → file offset: only exact via the section table. The heuristic
`file = VA − 0x10000` holds only where `VA − Raw == base` (typical `.text`).

## .JMP (Jay's Magic Patcher; xemu/XPSemu patch UI)

- First 7 lines fixed: magic `#Jay's Magic Patcher (www.jayxbox.com)`, then
  `system=`, `game-title=`, `region=`, `version=`, `author=`, `notes=`.
- `version=` carries the Title ID; a `{8-hex}` token there triggers an XBE
  CRC32 check (omit unless you have the CRC).
- `#comment` labels the next record; identical comments merge into one
  checkbox group; `[-]` prefix = default-off (matches ETM semantics).
- Records are `OFFSET:HEX` in-place overwrites (file offsets, no `APPEND:` —
  XPSemu doesn't support it).

## Title ID convention

4 bytes: 2 ASCII vendor letters + u16 game number (3-digit decimal).
`4B4E001F` → `KN` Konami + `0x1F`=31 → **KN-031** (Silent Hill 4).
`4950000A` → `IP` + 10 → **IP-010** (BGDA2).
