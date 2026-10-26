# ETM → JMP 转换器（Xored/Evox 金手指 → Jay's Magic Patch）

将 `.etm`（Evox Trainer Maker / Team Xored Trainer Engine 金手指）转换为
`.jmp`（Jay's Magic Patcher 静态内存补丁，XPSemu / xemu 补丁 UI 原生格式）。

> **v2 勘误（重要）**：v1 曾错误地认为 ETM 内的地址就是 XBE 文件原始偏移、
> 可 1:1 直映。经 xboxdevwiki / caustik XBE 格式文档 / xemu `xbe_header`
> 一手资料核实：**零售 XBE 加载基址是 `0x00010000`（64KB），ETM 地址是运行
> 时虚拟地址（VA）**，必须换算成文件偏移后才能写入 `.jmp`。当前版本已修正。

## 地址模型（核心）

ETM 代码入口的版本守卫直接证明了 VA 模型：

```asm
mov edi, 0x00010114
cmp [edi], 0x3FAFECB9   ; XBE 头部 base+0x114 = TimeDate（UNIX 时间戳）
jne ret                 ; 0x3FAFECB9 = 2003-11-14，BGDA2 的编译时间戳
```

XBE 头部关键字段（xboxdevwiki，小端）：

| 头部偏移 | 字段 |
|---|---|
| 0x104 | Base Address（零售游戏典型值 `0x00010000`） |
| 0x114 | TimeDate（编译时间戳） |
| 0x11C | Number of Sections |
| 0x120 | Section Headers Address（VA） |

段表条目 56 字节：`+0x00 Flags, +0x04 VirtualAddress, +0x08 VirtualSize,
+0x0C RawAddress(文件偏移), +0x10 RawSize, +0x14 NameAddr, +0x24 SHA1[20]`。

**VA → 文件偏移**：
- **精确模式（推荐）**：`--xbe default.xbe` 走段表换算，并自动校验 ETM 的
  TimeDate 守卫与目标 XBE 是否同版本（GUARD OK / MISMATCH）。
- **盲转启发式（默认）**：`file = VA − 0x00010000`。对 `VA−Raw == 基址` 的段
  （典型如 `.text`：VA `0x11000` ↔ Raw `0x1000`）成立；其他段可能因对齐漂移，
  输出会带警告，务必用 `--xbe` 复核。

## ETM 结构（35 字节头 + 扁平 x86 代码）

| 头部偏移 | 字段 |
|---|---|
| 0x00 | u32 文件大小 |
| 0x04 | u16 版本 |
| 0x06 | u32 头部长度 (0x23) |
| 0x0A | u32 → 选项开关数组（每选项 1 字节） |
| 0x0E | u32 → 字符串指针表（标题、作者、选项名） |
| 0x12 | u32 → Title ID 列表 |
| 0x16 | u32 → 代码入口 |
| 0x22 | u8 启用标志 |

每个作弊项是守卫块（引擎在游戏进程内执行，`ebp` = ETM 加载基址）：

```asm
cmp cs:byte [ebp+flagdisp], 0   ; 2E 80 BD disp32 imm8
je skip
mov edi, <游戏 VA>              ; BF imm32
mov al, <值>                    ; B0 imm8
stosb                           ; AA（写 [edi]，edi++）
```

状态机同时支持 `B8/AB`(stosd)、`66 B8/66 AB`(stosw)、`C6 07`/`C7 07` 直接写、
`47/4F`(inc/dec edi)——本例两个 ETM 未出现，但为其他 ETM 预留。

## 用法

```bash
# 推荐：提供目标游戏的 default.xbe（精确换算 + 版本校验）
python3 etm2jmp.py file.etm --xbe default.xbe --jmp OUT.jmp

# 无 XBE 样本：启发式 VA-0x10000（输出带警告）
python3 etm2jmp.py file.etm [--jmp OUT.jmp] [--report OUT.md] [--disasm]
python3 validate_jmp.py OUT.jmp     # 按 jayxbox apply 工具逻辑回验格式
```

### --xbe 精确模式（已端到端测试）

只需 XBE 的**前 4KB**（含完整头部+段表），无需整文件：

```bash
extract-xiso -x game.xiso        # 或 head -c 4096 default.xbe > xbe_head.bin
python3 etm2jmp.py file.etm --xbe xbe_head.bin --jmp OUT.jmp
```

输出会：① 打印段表（每段 `VA/raw/delta`）；② `GUARD OK/MISMATCH` 校验
ETM 的 TimeDate 守卫与 XBE 是否同版本；③ 每个选项标注所属段
`[.text]/[.rdata]/[.data]`——上机初测建议只勾 `[.text]` 项。

`make_test_xbe.py` 生成带刻意对齐漂移的合成 4KB 头部，用于回归测试该路径
（已验证：GUARD OK/MISMATCH、跨段漂移换算、BSS 无文件 backing 拒绝、
越界 VA 拒绝）。

## 本仓库已转换文件（Baldur's Gate - Dark Alliance 2, Title ID 4950000A）

| 文件 | 来源 | 选项 | 记录 |
|---|---|---|---|
| `BGDA2_infinite_trainer_usa.jmp` | `Baldurs Gate - Dark Alliance 2.etm`（+16 NTSC USA） | 16 | 32 |
| `BGDA2_infinite_trainer_ntsc.jmp` | `Baldurs Gate Dark Alliance 2 p16 ntsc.etm`（+16 NTSC） | 16 | 39 |

- 偏移已按 `VA − 0x10000` 修正（例：ETM `0x13B579` → `.jmp` `12B579`）。
- 两个独立 ETM 的 13 个共有选项记录逐字节一致（同一约定下的交叉验证）。
- **待办**：拿到 NTSC (USA) 版 `default.xbe` 后跑一次 `--xbe`，确认
  GUARD OK（TimeDate `0x3FAFECB9`）且所有补丁点落在预期段内。

## .JMP 格式要点（对照 jayxbox `tool_apply-magic-patch.html` 解析器）

- 前 7 行固定：magic + `system/game-title/region/version/author/notes`。
- `version=` 含 Title ID；`{8位HEX}` 会触发 XBE CRC32 校验（本文件未含）。
- `#注释` 标记下一条记录；相同注释归并为一个复选框组；`[-]` = 默认关闭
  （与 ETM 全默认关闭语义一致；互斥选项避免同时生效）。
- 只用 `偏移:HEX` 原地覆盖记录，不用 `APPEND:`（XPSemu 不支持）。
  "Better Shop" 的 `E9` 跳转目标是游戏已有代码，纯静态写入可复现。

## 部署到 XPSemu（PS5）

1. 把 `.jmp` 放入 `/data/xemu/patches/`。
2. 选中游戏 → **△** → Game patches → 勾选需要的作弊项。
3. 补丁在加载时对内存中的 XBE 原地打入，不修改原盘 XISO。

若金手指无效或崩溃：大概率是启发式偏移与你 XBE 的段对齐不符（或 XBE 版本
不对），用 `--xbe` 精确模式重新生成。
