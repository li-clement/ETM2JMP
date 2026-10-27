# ETM analysis: Baldurs Gate - Dark Alliance 2.etm

- Trainer: **Baldurs Gate Dark Alliance 2 +16 NTSC (USA)**
- Author line: `Made by _HellDasxS_`
- Title ID: `4950000A`
- Version guard: `[00010114] == 3FAFECB9` (XBE header TimeDate at base+0x114)
- Options: 16
- Address mode: HEURISTIC: file = VA - 0x00010000 (assumes VA-Raw delta == image base for every patched section; verify with --xbe!)

| # | Option | ETM VA -> .JMP file offset : bytes |
|---|--------|------------------------------------|
| 1 | Infinite Blue Potions | `13B579`→`12B579` `909090` |
| 2 | Infinite Red Bottles | `13B7EE`→`12B7EE` `909090` |
| 3 | Infinite Recalls | `C4499`→`B4499` `9090909090909090` |
| 4 | One kill level 40 | `15B0E7`→`14B0E7` `90909090` |
| 5 | Never gain XP | `15B0EE`→`14B0EE` `909090` |
| 6 | Buy give you GOLD | `154E2C`→`144E2C` `01` |
| 7 | Sell NOT take ITEM | `155142`→`145142` `90909090` |
| 8 | Infinite Skill Points | `166075`→`156075` `9090` |
| 9 | Take Skills 0 points | `166051`→`156051` `909090909090` |
| 10 | Inf Jewels in Workshop | `153F91`→`143F91` `909090`<br>`15403C`→`14403C` `909090`<br>`153EE6`→`143EE6` `909090` |
| 11 | Take money give XP | `E1E7D`→`D1E7D` `A0474900`<br>`E1E8D`→`D1E8D` `A0474900` |
| 12 | Better Shop | `15655E`→`14655E` `E96313000090`<br>`1578CE`→`1478CE` `74E31F00`<br>`1578EC`→`1478EC` `94E31F00`<br>`15790A`→`14790A` `44E31F00`<br>`157928`→`147928` `28E31F00` |
| 13 | Extreme Mode | `3275FC`→`3175FC` `11` |
| 14 | Infinite Health | `26D9FC`→`25D9FC` `01`<br>`2189E0`→`2089E0` `000000` |
| 15 | Better Borador | `21EB48`→`20EB48` `442220`<br>`21EB54`→`20EB54` `C02120`<br>`21EB3C`→`20EB3C` `00E31F`<br>`21EB30`→`20EB30` `082720`<br>`21EB7C`→`20EB7C` `0A`<br>`21EB74`→`20EB74` `0A`<br>`21EB78`→`20EB78` `65`<br>`21EB6C`→`20EB6C` `03` |
| 16 | 2 PNTS each 4 levels | `1646ED`→`1546ED` `FF4374FF437490FF8380000000FF838000000090FF8384000000FF838400000090FF4378FF4378FF437CFF437CFF83880000009090`<br>`1646BD`→`1546BD` `75` |
