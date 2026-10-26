# ETM analysis: Baldurs Gate Dark Alliance 2 p16 ntsc.etm

- Trainer: **Baldurs Gate Dark Alliance 2 +16 NTSC**
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
| 4 | 2 to DEX/CON + 1 others | `1646ED`→`1546ED` `9090`<br>`1646F2`→`1546F2` `9090`<br>`1646F7`→`1546F7` `9090`<br>`1646FF`→`1546FF` `9090`<br>`164704`→`154704` `9090`<br>`16470C`→`15470C` `9090FF43789090`<br>`164716`→`154716` `9090FF437C9090`<br>`164720`→`154720` `9090`<br>`1646BD`→`1546BD` `75` |
| 5 | One kill level 40 | `15B0E7`→`14B0E7` `90909090` |
| 6 | Never gain XP | `15B0EE`→`14B0EE` `909090` |
| 7 | Buy give you GOLD | `154E2C`→`144E2C` `01` |
| 8 | Sell NOT take ITEM | `155142`→`145142` `90909090` |
| 9 | Infinite Skill Points | `166075`→`156075` `9090` |
| 10 | Take Skills 0 points | `166051`→`156051` `909090909090` |
| 11 | Inf Jewels in Workshop | `153F91`→`143F91` `909090`<br>`15403C`→`14403C` `909090`<br>`153EE6`→`143EE6` `909090` |
| 12 | Take money give XP | `E1E7D`→`D1E7D` `A0474900`<br>`E1E8D`→`D1E8D` `A0474900` |
| 13 | Better Shop | `15655E`→`14655E` `E96313000090`<br>`1578CE`→`1478CE` `74E31F00`<br>`1578EC`→`1478EC` `94E31F00`<br>`15790A`→`14790A` `44E31F00`<br>`157928`→`147928` `28E31F00` |
| 14 | Extreme Mode | `3275FC`→`3175FC` `11` |
| 15 | Infinite Health | `26D9FC`→`25D9FC` `01`<br>`2189E0`→`2089E0` `000000` |
| 16 | Better Borador | `21EB48`→`20EB48` `442220`<br>`21EB54`→`20EB54` `C02120`<br>`21EB3C`→`20EB3C` `00E31F`<br>`21EB30`→`20EB30` `082720`<br>`21EB7C`→`20EB7C` `0A`<br>`21EB74`→`20EB74` `0A`<br>`21EB78`→`20EB78` `65`<br>`21EB6C`→`20EB6C` `03` |
