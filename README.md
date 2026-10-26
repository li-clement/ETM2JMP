# ETM → JMP 转换器（Xored/Evox 金手指 → Jay's Magic Patch）

将 `.etm`（Evox Trainer Maker / Team Xored Trainer Engine 金手指）转换为
`.jmp`（Jay's Magic Patcher 静态内存补丁，XPSemu / xemu 补丁 UI 原生格式）。

> **v2 勘误（重要）**：v1 曾错误地认为 ETM 内的地址就是 XBE 文件原始偏移、
> 可 1:1 直映。经 xboxdevwiki / caustik XBE 格式文档 / xemu `xbe_header`
> 一手资料核实：**零售 XBE 加载基址是 `0x00010000`（64KB），ETM 地址是运行
> 时虚拟地址（VA）**，必须换算成文件偏移后才能写入 `.jmp`。当前版本已修正。
>
> **v3 新增**：支持手写汇编流派（`cmp [edi],ah` 原字节特征码、`mov [edi],al`
> 条件写、`mov word [edi+d]`、`lea esi,[ebp+d]`、`call` 子程序），并识别
> **运行时 Hook**——这类选项无法静态化，默认排除，见下文。
>
> **格式来源**：头部/字符串模型已用 jayxbox 官方
> [ETM Analyzer](https://www.jayxbox.com/Misc/etm-trainer.php)（工具本体
> `/tools/tool_etm-trainer.html`）的解析代码逐字节交叉验证，三个样本全部一致。
> 注意该官方工具只解析头部/字符串，其反汇编器缺 `66` 前缀、`38`、`88`、
> `C6/C7`、`E8`、SSE 等指令（SH4 样本 60 条指令里 40 条被它当成 `db`），
> **不能**用它提取补丁。


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
`47/4F`(inc/dec edi)。

### v3 新增：手写汇编流派（`Evox-T` / k_away）

ETM Maker 的傻瓜模板只发 `stosb`；老作者手写汇编，v3 已支持：

| 指令 | 编码 | 语义 |
|---|---|---|
| `mov ax, imm16` | `66 B8` | `al` = 新字节，`ah` = 期望的原字节 |
| `cmp byte [edi], ah` | `38 27` | **原字节特征码守卫**（版本校验） |
| `mov byte [edi], al` | `88 07` | 条件写 1 字节（`88 47 d8` = `[edi+d8]`） |
| `mov [edi+d], eax/ax` | `89 07` / `66 89 47 d8` | 直接写 |
| `mov word [edi+d], imm16` | `66 C7 47 d8` | 直接写 |
| `lea esi, [ebp+d32]` | `8D B5` | `esi` = **指向 ETM 镜像内部** |
| `call rel32` / `ret` | `E8` / `C3` | 进入子程序桩，`ret` 回到调用点 |

> `E8` 是 1 字节操作码，`rel32` 在 `i+1`（不是 `i+2`）；`38 27` 的 `reg=4`
> 在无 REX 的 8 位指令里是 **AH**（不是 ESP）——这两点都是实测踩过的坑。

### 运行时 Hook：不能静态化的选项

`C6 07 68` + `89 77 01` + `C6 47 05 C3` 三连 = 在游戏站点写
`68 <imm32> C3`（`push handler; ret`）。当 `esi` 来自 `lea esi,[ebp+d]` 时，
那 4 个立即数字节 = **`ETM 加载基址 + 偏移`**，只在金手指引擎把 ETM 映射进
游戏进程时存在，**无法**原样写进 `.jmp`。v3 会：

1. 定位 handler 里的 `push <back>; ret`，算出被覆盖字节数；
2. 打印 handler 反汇编；
3. **默认整项排除**（连该选项那些"看起来静态"的字节也排除——它们只是半个跳板）；
4. `--hook-approx`：若 handler 只是**重放**站点原指令而改了存储位移，则等价形式
   就是原地改写那 4 字节位移。脚本会读 XBE 站点字节**证明**形状（`F3 0F 11 86`）
   后才发，并做**反证检查**：
   - 站点不是这个形状 → 拒绝；
   - **站点位移已经等于 handler 的位移** → 说明 handler 是忠实重放而非改道，
     改写位移等于**静默空操作** → 拒绝并提示改用 `--hook-cave`；
5. `--hook-cave`（通用兜底，需 `--xbe`）：handler 本身**完全可重定位**
   （`je` 是 rel8，`push <游戏VA>` 是绝对游戏地址，只有跳板立即数依赖 ETM），
   所以把 handler 原样放进 XBE 内**已验证的零填充区**，站点写
   `68 <caveVA> C3 90…` 指过去即可，与 ETM 驻留版行为完全一致。
   填充区按优先级：
   - **XBE header padding（首选，SH4 实测用这个）**：`sizeOfHeaders` 到首个
     4KB 页尾（文件 `0x9FC–0x1000` 这类）——在加载镜像内（image base 映射
     文件偏移 0）、不属于任何段、在段表之后，且原文件里实测全零。Xbox 的
     Pentium III 没有 NX 位，header page 可执行，这是经典 header-cave 手法。
   - **EXECUTABLE 段尾零填充（回退）**：XBE 段标志（已核对 Cxbx-Reloaded
     `src/common/xbe/Xbe.h`）：`0x1` WRITEABLE、`0x2` PRELOAD、`0x4` **EXECUTABLE**、
     `0x8` INSERTFILE、`0x10/0x20` 页只读。把 handler 塞进不可执行段会被当数据
     加载、永远不运行，所以这是硬性条件；两处都找不到就直接拒绝。



## 用法

```bash
# 推荐：提供目标游戏的 default.xbe（精确换算 + 版本校验）
python3 etm2jmp.py file.etm --xbe default.xbe --jmp OUT.jmp

# 无 XBE 样本：启发式 VA-0x10000（输出带警告）
python3 etm2jmp.py file.etm [--jmp OUT.jmp] [--report OUT.md] [--disasm]

# 含运行时 Hook 的 ETM：尝试证明静态等价形式（配合 --xbe 才能验证）
python3 etm2jmp.py file.etm --hook-approx [--xbe default.xbe] --jmp OUT.jmp

# 证明不了时的通用兜底：把 handler 搬进 XBE 零填充区（必须 --xbe）
python3 etm2jmp.py file.etm --hook-cave --xbe default.xbe --jmp OUT.jmp

python3 validate_jmp.py OUT.jmp     # 按 jayxbox apply 工具逻辑回验格式
python3 apply_and_check.py OUT.jmp default.xbe
                                    # 把记录应用到 XBE 副本并反汇编每个站点
                                    # （跳板→handler→返回链肉眼可查，不动原文件）
```

### 拿到 default.xbe 之后（完整流程）

**第 0 步：取出 `default.xbe`**

```bash
extract-xiso -x game.xiso          # 解出 default.xbe（7z x game.xiso 也行）
```

两个工具都没装时的零依赖办法（SH4 实测路径）——XISO 里直接按 `XBEH` 魔数
定位、按头部 `+0x10C` 的 `SizeOfImage` 截取：

```bash
python3 - <<'PY'
import mmap, struct
mm = mmap.mmap(open("Silent.Hill.4.[USA].iso","rb").fileno(), 0)
i = mm.find(b"XBEH")                                   # 第一个 XBEH = default.xbe
sz = struct.unpack_from("<I", mm, i + 0x10C)[0]        # SizeOfImage
open("default.xbe","wb").write(mm[i:i+sz])
print(f"extracted {sz} bytes from ISO offset 0x{i:X}")
PY
```

**先分清你要传多大的文件**——这是最容易踩的坑：

| 目的 | 需要的 XBE 范围 |
|---|---|
| VA→文件偏移精确换算、TimeDate 版本校验、选项所属段 | **前 4KB**（头部+段表）就够 |
| `--hook-approx` 验证站点原指令 | **完整 default.xbe**（要读站点那 8 字节，常在 1MB 开外） |
| `--hook-cave` 找可执行段填充 | **完整 default.xbe**（要确认填充区真的是 0） |

只传 4KB 却做后两件事时，工具不会瞎猜，会直接说
`XBE file is only 4096 bytes … pass the FULL default.xbe`。

**第 1 步：先做版本校验**

```bash
python3 etm2jmp.py "Silent Hill 4 [plus3] (NTSC).etm" --xbe default.xbe --jmp OUT.jmp
```

看输出第一行结论：

- `GUARD OK: ETM checks TimeDate 0x… == this XBE's TimeDate` → 同版本，继续；
- `GUARD MISMATCH: …` → **停手**。这是另一个版本的 XBE，ETM 里的地址全不适用，
  换盘/换版本重来（补丁打上去只会崩）。

同时每个选项会标 `[.text]/[.rdata]/[.data]`；上机初测建议只勾 `[.text]` 的项。

**第 2 步：处理运行时 Hook**（只有含 Hook 的 ETM 需要，比如 SH4 的 Inf Life）

```bash
python3 etm2jmp.py <etm> --xbe default.xbe --hook-approx --jmp OUT.jmp
```

三种结果，工具自己判定，不需要你猜：

| 输出 | 含义 | 下一步 |
|---|---|---|
| `static equivalent … [verified: …]` | 站点确实是 `movss [esi+D1]` 且 `D1 ≠` handler 位移 → handler 是**改道**，已发 4 字节位移改写记录 | 直接用 |
| `REJECTED → site already IS 'movss [esi+0xCB4FE8]…'` | handler 是**忠实重放**，改写位移等于空操作 | 走第 3 步 |
| `REJECTED → site bytes are …, not 'F3 0F 11 86 …'` | 站点根本不是那条指令 | 走第 3 步 |

**第 3 步：兜底——把 handler 搬进可执行段填充区**

```bash
python3 etm2jmp.py <etm> --xbe default.xbe --hook-cave --jmp OUT.jmp
```

产出两条记录：cave 里的 18 字节 handler + 站点的 `68 <caveVA> C3 90 90`。
只在 **EXECUTABLE（flag `0x4`）** 段尾找零填充；找不到会明确拒绝，绝不会把
代码塞进不可执行段。

**第 4 步：回验并部署**

```bash
python3 validate_jmp.py OUT.jmp
```

**回归测试**（不需要真游戏，合成 XBE）：

```bash
python3 make_test_xbe.py     # 生成 6 个合成 XBE
```

覆盖：GUARD OK/MISMATCH、跨段对齐漂移换算、BSS 无文件 backing 时**报告并跳过**
（不再崩栈）、越界 VA、hook 站点三种形状（匹配 / 恒等 / 不符）、可执行段填充 vs
只有不可执行填充、XBE 截断提示。


## 本仓库已转换文件

### Baldur's Gate - Dark Alliance 2（Title ID `4950000A` → IP-010）

| 文件 | 来源 | 选项 | 记录 |
|---|---|---|---|
| `BGDA2_infinite_trainer_usa.jmp` | `Baldurs Gate - Dark Alliance 2.etm`（+16 NTSC USA） | 16 | 32 |
| `BGDA2_infinite_trainer_ntsc.jmp` | `Baldurs Gate Dark Alliance 2 p16 ntsc.etm`（+16 NTSC） | 16 | 39 |

- 偏移已按 `VA − 0x10000` 修正（例：ETM `0x13B579` → `.jmp` `12B579`）。
- 两个独立 ETM 的 13 个共有选项记录逐字节一致（同一约定下的交叉验证）。
- **待办**：拿到 NTSC (USA) 版 `default.xbe` 后跑一次 `--xbe`，确认
  GUARD OK（TimeDate `0x3FAFECB9`）且所有补丁点落在预期段内。

### Silent Hill 4: The Room（Title ID `4B4E001F` → KN-031，`by k_away / Evox-T`）

样本 `Silent Hill 4 [plus3] (NTSC).etm`（287 字节，与
`Silent Hill 4 p3 ntsc.etm` **SHA-256 完全相同**）。入口在 `0x40`（不是常规
`0x23`），`0x23–0x3F` 藏着跳板子程序和 handler。版本守卫 TimeDate
`0x40E173E9` = 2004-06-29。Title ID `4B4E001F`：按 xboxdevwiki 的定义
（厂商 2 字母 + u16 游戏号，3 位十进制），`KN` = Konami、`0x1F` = 31 →
**KN-031**（与 `4950000A` → IP-010 同一约定）。


| # | 选项 | 站点 VA | 原字节守卫 | 写入 | `.jmp` 偏移 |
|---|---|---|---|---|---|
| 1 | Inf Life | `0x0012CB67` | `0xF3` | **运行时 Hook** | 见下 |
| 2 | Inf Ammo | `0x000F89EE` | `0x49` | `90`（NOP） | `E89EE` |
| 3 | Saves Never Increase | `0x0016B63A` | `0x40` | `90`（NOP） | `15B63A` |

选项 1 的跳板（ETM 安装器实测只写 6 字节 `68 <ebp+0x2E> C3`，留 2 字节死代码；
静态版补齐为 `68 <caveVA> C3 90 90`），handler：

```asm
002E: 0B F6                    or  esi, esi
0030: 74 08                    je  0x3A
0032: F3 0F 11 86 E84FCB00     movss [esi+0xCB4FE8], xmm0
003A: 68 6FCB1200              push 0x0012CB6F     ; 跳回站点+8
003F: C3                       ret
```

handler 用 `movss` **忠实重放**了被覆盖的原指令（真 XBE 已证实站点原 8 字节
就是 `F3 0F 11 86 E84FCB00`，位移相同），机制在 `or esi,esi / je`：`esi == 0`
（主角全局路径）时**跳过**血量写。站点守卫字节 `0xF3` 加上"覆盖 8 字节"正好
等于 `F3 0F 11 86 disp32` 的长度，两者吻合。~~早期推测的"改写 4 字节位移把
写操作改道到无用槽位"已被真 XBE 证伪~~（改写位移 = 空操作），正确静态化只有
`--hook-cave`，见下。

产物（已用真 XBE 验证，见下）：

| 文件 | 内容 | 状态 |
|---|---|---|
| `Silent Hill 4 [plus3] (NTSC)_verified.jmp` | 全部 3 项（选项 1 走 header-padding cave） | ✅ 端到端验证 |
| `Silent Hill 4 [plus3] (NTSC).jmp` | 仅选项 2、3 | ✅ 有效（安全子集） |
| ~~`_incl_Inflife.jmp`~~ | 选项 1 的位移改写 | ❌ **已证伪为静默空操作，已删除** |

### ✅ 真 XBE 验证结果（`Silent.Hill.4.[USA].iso` → `default.xbe`）

- **GUARD OK**：XBE TimeDate `0x40E173E9` == ETM 守卫（同版本，2004-06-29 编译）。
- **改道说已死**：站点 `0x0012CB67` 原 8 字节就是 `F3 0F 11 86 E84FCB00`——
  位移**已等于** handler 位移，`--hook-approx` 正确拒绝（改写位移 = 空操作）。
- **机制坐实**（真函数反汇编）：该函数是血量 setter，写 `[esi+0xCB4FE8]`。
  `esi == 0` 时写到 `0x00CB4FE8` = **.data BSS 里的全局主角血量变量**
  （.data VA `0x20FEA0`+`0xDA993C`，BSS 无文件 backing）；`esi ≠ 0` 是实体
  相对写。handler 的 `or esi,esi / je` **只跳过主角的血量写**，其余实体照常
  → 主角血量永不更新、怪物正常掉血。`je` 就是机制本身，不是防御性检查。
  全 XBE 中 `[esi+0xCB4FE8]` 共 8 处引用，全部集中在 `0x12CAFC–0x12CD54`
  这组血量 getter/setter 里。
- **cave 选址（已证明安全）**：`sizeOfHeaders = 0x9FC`，文件 `0x9FC–0x1000`
  共 1542 字节全零——在加载镜像内（image base 映射文件偏移 0）、不属于任何段、
  在段表（VA `0x10370` + 12×56 = `0x10610`）之后。handler 放 VA `0x109FC`。
  Xbox 的 Pentium III 无 NX，header page 可执行，这是经典 header-cave 手法。
- **端到端回验**（`apply_and_check.py`）：4 条记录应用到 default.xbe 副本 →
  站点变 `push 0x109FC; ret; nop; nop` → handler 重放 `movss` →
  `push 0x12CB6F; ret` 精确落回原 `xor eax,eax` 序言尾；Inf Ammo 站点是真
  `dec ecx`（弹药递减）、Saves 站点是真 `inc eax`（存档计数递增），NOP 语义吻合。
- **忠实度**：cave 里的 handler 与 ETM+`0x2E` 逐字节相同（含返回地址
  `0x12CB6F`）。原 ETM 跳板只有 6 字节（`68 imm C3`，留 2 字节死代码），
  静态版用 `90 90` 补齐 8 字节，行为一致且更干净。
- ETM 驻留版行为对照（从 ETM 机器码直接反汇编）：入口先 `cmp [0x10114],
  0x40E173E9` 版本守卫，再 `mov ax,0xF390; cmp [edi],ah` 原字节守卫，然后
  `lea esi,[ebp+0x2E]` + `call` 安装器写 `68 <handler> C3`——与静态版等价。

handler 实际长度 **18 字节**（`0x2E–0x3F`），`je` 是 `74 08`。
`make_test_xbe.py` 已把这几种情形做成回归用例（`test_xbe_sh4*.bin`）。


**易错点**（分析这个文件时容易读错的地方，均已用字节级检索核实）：

- `38 27` 是 `cmp [edi], AH`，不是 `cmp [edi], AL`；`88 07` 是
  `mov [edi], AL`，不是 `mov [edi], AH`——写的是 `al`（`0x90` NOP），
  `ah` 只是期望的原字节。
- 站点是 `0x0012CB67 / 0x000F89EE / 0x0016B63A`，不是 `0x0005CB67 /
  0x001389EE / 0x0015B63A`。
- 文件里**不存在** `BE/BF 80 03 01 00`（`mov esi/edi,0x00010380`）、
  `B9 04 00 00 00`（`mov ecx,4`）、`F3 A5`（`rep movsd`）——即**没有**把
  cave 拷进 XBE 头部空白区的逻辑；handler 就留在 ETM 镜像里跑，所以跳板
  立即数依赖 ETM 驻留地址。
- Title ID 是 `4B4E001F`（`1F 00 4E 4B`），不是 `4B4E001B`。


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
