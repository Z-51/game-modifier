# 游戏修改器 CLI 插件 — 用户使用手册

> 适用版本：game-modifier 0.1.0
> 平台：Windows（本版本唯一受支持的目标平台）
> **仅用于你自己拥有的单机 / 离线游戏。**

---

## 1. 概述

### 1.1 这是什么

game-modifier 是一个面向**单机游戏内存修改**的命令行工具与 AI Agent 插件。它把「找地址 → 改数值 → 锁定数值」这套传统 Cheat Engine 流程封装成了结构化命令，既可以人工在终端里使用，也可以作为 Claude Code / Codex CLI 的插件（CLI 或 MCP 两种调用方式）让 AI 代你操作。

它的设计目标是**省 token**：附加一次拿到 `session_id` 后续复用、中文自然语言一句话直接改数值、用符号名（如 `player.gold`）代替裸指针链、模板与批处理一次调用完成多处修改、以及带稳定 `error.code` 的紧凑 JSON 输出。

### 1.2 功能概览

| 能力 | 说明 |
| --- | --- |
| 进程附加 | 按 PID / 进程名 / 可执行文件路径附加，自动检测架构与已加载模块 |
| 引擎识别 | 自动识别 Unity（Il2Cpp / Mono）、Unreal，给出后续操作建议 |
| 内存扫描 | 首次扫描 + 多轮渐进筛选（scan / scan-next），支持 12 种比较器（首扫 8 种 + 增量 4 种）；numpy 向量化、并行首扫、扫描缓存提速 |
| AOB 扫描 | `scan-aob`：`?? ` 通配符字节模式扫描，按签名定位代码 / 数据地址 |
| 布局分析 | `layout`（vtables / rtti / class / heap）逆向推断对象布局 |
| 指针反查 | `pointer-scan`：自动反查能到达目标地址的指针链（base + offsets），`--rescan` 验证已保存路径的稳定性 |
| 结构体解剖 | `dissect`：对单个或多个同类实例做字段类型启发式推断（vtable / 指针 / 整数 / 浮点 / bool），每个字段带 confidence，只读 |
| 写入代码定位 | `find-writers`：硬件断点（DR0-3）捕获写入某地址的指令 RIP，比轮询 `watch` 更精确，需管理员权限 |
| 运行时反汇编 | `disasm`：capstone 反汇编目标地址处的代码（可选按基本块切分），只读 |
| 数值监视 | `watch`：轮询读取某地址并记录每次值变化（何时变、从多少变到多少），前台 / 后台两种模式 |
| 交叉引用 | `xrefs`：借助 radare2 查询谁引用了某地址（定位写入来源），只读 |
| UE 结构内省 | `ue`（introspect / actors / fname）：探测并缓存 Unreal GObjects / FNamePool 布局，枚举 Actor，全部只读 |
| 数值读写 | 支持 int8~uint64、float、double、bool、string、string_utf16、bytes |
| 指针解析 | `Module.dll+0x1234,0x10,0x20` 形式的多级指针链解析；三种偏移语义可选：`pointer_chain`（CE 风格 deref+offset）、`field_chain`（结构体字段链 offset+deref）、`relative`（仅加法） |
| 符号表 | 把扫到的地址命名为 `player.gold` 之类的符号，会话内持久保存；`name chain` 一次遍历多级指针链并把每级中间地址注册为 `<名称>.stepN` 符号（默认临时，可 `clear-temp` 清理） |
| 宏 | `macro define/list/show/run/delete`：把重复出现的操作序列封装为带 `${param}` 参数的 YAML 宏，一次定义、多次复用 |
| 会话快照 | `session snapshot/snapshots/restore`：给会话状态（符号表、扫描摘要等）打命名快照，随时回退（恢复前自动归档当前状态） |
| 中文 NLP | `"将金币设为9999"`、`"无限弹药"` 等短语直接执行，纯词典 + 正则，无需 LLM |
| 数值冻结 | 后台进程持续回写，实现「无限 / 无敌」效果 |
| 模板 | 内置 rpg / action / strategy 三套通用模板，一条命令套用多项修改 |
| 批处理 | YAML 文件描述多步操作，一次执行 |
| 安全机制 | 默认 dry-run、写前自动备份、反作弊检测拒绝附加、地址合法性校验、写入长度上限、审计日志 |
| 逆向工具链 | 自动探测 radare2 / x64dbg / WinDbg / Il2CppDumper / UE4 Dumper 等 |
| MCP 服务器 | 以结构化工具的形式暴露全部能力（精确工具数与清单以 MCP `tools_catalog` 工具运行时返回为准；`--profile` 五档分级：default / readonly / dry-run / symbols / limited，见 5.4；`--groups core,scan,...` 可按需只注册部分工具组，节省上下文 token） |

### 1.3 限制与免责

- **仅限单机 / 离线游戏。** 检测到已知反作弊系统时工具会**直接拒绝附加**（见第 7 章）。请勿用于任何联机、竞技或有反作弊保护的游戏——这既违反游戏条款，也极易导致封号或游戏崩溃。
- 本版本仅支持 **Windows**。其他平台会返回 `E_UNSUPPORTED_OS`。
- 附加到部分游戏进程需要**管理员权限终端**。
- 内存修改本身有风险，可能导致游戏崩溃或存档损坏。**修改前请手动备份存档。**

---

## 2. 安装指南

### 2.1 环境要求

- Python **3.10 或更高**
- Windows 系统
- 建议使用**以管理员身份运行**的终端

### 2.2 基本安装

在仓库根目录执行：

```powershell
pip install -e .
```

这会安装核心依赖（`psutil`、`PyYAML`，Python 3.10 下额外安装 `tomli`）并注册两个命令行入口：

- `game-modifier` — CLI 主命令
- `game-modifier-mcp` — MCP 服务器

### 2.3 完整安装（推荐）

```powershell
pip install -e ".[all]"
```

额外安装 `r2pipe`（radare2 静态分析）、`mcp`（MCP 服务器）、`capstone`（运行时反汇编）、`pytest`（测试）。

可选依赖分组：

| 分组 | 内容 | 用途 |
| --- | --- | --- |
| `radare2` | `r2pipe>=1.8` | `analyze --deep` 静态分析、`xrefs` 交叉引用 |
| `frida` | `frida>=16.0` | 动态插桩（可选后端） |
| `mcp` | `mcp>=1.0` | 运行 `game-modifier-mcp` |
| `disasm` | `capstone>=5.0` | `disasm` 运行时反汇编（未装时该命令返回 `E_DEPENDENCY_MISSING`） |
| `speed` | `numpy>=1.26` | 扫描向量化加速（可选；未装时回落纯 Python） |
| `dev` | `pytest`, `pyflakes` | 开发与测试 |
| `all` | r2pipe + mcp + numpy + capstone + pytest | 一次装齐常用项 |

按需单独安装，例如：

```powershell
pip install -e ".[mcp]"
```

### 2.4 验证安装

```powershell
game-modifier --version
```

预期输出：

```json
{"ok": true, "command": "version", "data": {"version": "0.1.0"}}
```

查看逆向工具链探测结果（可选依赖缺失时会优雅降级，不影响核心功能）：

```powershell
game-modifier toolchain detect --format json-pretty
```

### 2.5 管理员终端

`OpenProcess` 需要足够权限。若 `attach` 返回 `E_ACCESS_DENIED`，请：

1. 右键「Windows PowerShell」→「以管理员身份运行」；
2. 重新执行 `attach`。

`attach` 返回的 `data.is_admin` 字段会告诉你当前是否处于管理员上下文。

---

## 3. 快速入门

下面是一个完整的「找金币并改成 9999」流程。假设游戏进程是 `game.exe`，当前金币为 `250`。

### 步骤 1：附加进程

```powershell
game-modifier attach --process game.exe
```

输出（节选）：

```json
{"ok": true, "command": "attach", "data": {
  "session_id": "game.exe-1a2b3c", "pid": 12345, "arch": "x64",
  "engine_detail": {"engine": "unity_il2cpp"},
  "anti_cheat": {"detected": false, "systems": [], "hits": []},
  "module_count": 87, "is_admin": true}}
```

记下 `session_id`，后续所有命令都复用它。为了方便，先存进变量：

```powershell
$S = "game.exe-1a2b3c"
```

### 步骤 2（可选）：分析引擎与工具链

```powershell
game-modifier analyze --session $S
```

`data.next_steps` 会针对识别出的引擎给出后续建议。

### 步骤 3：首次扫描当前值

```powershell
game-modifier scan --session $S --type int32 --value 250
```

```json
{"ok": true, "command": "scan", "data": {
  "type": "int32", "comparator": "exact", "count": 1873, "truncated": false,
  "addresses_hex": ["0x1f2a3b40", "..."], "sample_values": {"0x1f2a3b40": 250},
  "scanned_regions": 412, "scanned_bytes": 2147483648}}
```

候选太多是正常的，需要继续筛选。

### 步骤 4：回到游戏改变数值，然后渐进筛选

在游戏里花掉一些钱，金币变成 `180`，然后：

```powershell
game-modifier scan-next --session $S --value 180
```

重复「游戏内改变数值 → `scan-next`」直到 `count` 降到个位数（通常 2~4 轮即可）。若不知道确切新值，可以用变化类比较器：

```powershell
game-modifier scan-next --session $S --comparator decreased
```

### 步骤 5：把地址命名为符号

```powershell
game-modifier name set player.gold --session $S --base 0x1f2a3b40 --type int32 --description "金币"
```

之后所有命令都可以用 `--symbol player.gold` 引用它，不必再记地址。

### 步骤 6：先 dry-run，再确认写入

```powershell
# 不加 --confirm 只做模拟，报告 old_value / new_value，不实际写入
game-modifier modify --session $S --symbol player.gold --value 9999

# 确认无误后真正写入（自动备份原始字节）
game-modifier modify --session $S --symbol player.gold --value 9999 --confirm
```

```json
{"ok": true, "command": "modify", "data": {
  "ok": true, "address_hex": "0x1f2a3b40", "type": "int32",
  "old_value": 180, "new_value": 9999, "symbol": "player.gold",
  "freeze": false, "bytes": "0f270000",
  "applied": true, "dry_run": false, "bytes_written": 4,
  "verified_value": 9999, "backup_id": "bk-20260730-101112"}}
```

### 步骤 7：用自然语言复用符号

符号建立之后，NLP 就能自动定位它：

```powershell
game-modifier nl --session $S "将金币设为99999" --confirm
game-modifier nl --session $S "金币增加5000" --confirm
game-modifier nl --session $S "查看金币"
```

### 步骤 8：结束

```powershell
game-modifier detach $S
```

---

## 4. 命令详解

### 4.0 通用约定

**全局选项**（**必须放在子命令之前**，如 `game-modifier --format human scan ...`；放在子命令之后会被 argparse 报参数错误）：

| 选项 | 说明 |
| --- | --- |
| `--config <path>` | 指定 TOML 配置文件 |
| `--format {json,json-pretty,human}` | 输出格式，默认取配置（出厂为 `json`） |
| `--json` | `--format json` 的简写 |
| `--version` | 打印版本后退出 |

**输出格式**：每条命令在 stdout 打印**一行 JSON**：

```json
{"ok": true,  "command": "modify", "data": { ... }}
{"ok": false, "command": "modify", "error": {"code": "E_...", "message": "...", "hint": "...", "details": { ... }}}
```

若存在非致命提示，还会附带 `"warnings": ["..."]`。

**退出码**：`0` 成功；`1` 命令返回错误；`2` 未提供子命令（帮助信息打到 stderr）。

**支持的数据类型**（`--type`）：

`int8`、`uint8`、`int16`、`uint16`、`int32`、`uint32`、`int64`、`uint64`、`float`、`double`、`bool`、`string`、`string_utf16`、`bytes`

常用别名：`int`/`i32` → int32，`dword`/`u32` → uint32，`byte` → uint8，`word` → uint16，`qword` → uint64，`long` → int64，`single`/`f32` → float，`f64` → double，`str`/`utf8` → string，`wstring`/`utf16` → string_utf16，`aob`/`hex` → bytes。

**地址与偏移写法**：地址可写 `0x1f2a3b40`；偏移用逗号或空格分隔，如 `--offsets "0x10,0x20"`；基址表达式可写 `GameAssembly.dll+0x1234`、`game.exe`、或裸地址 `0x7ff6...`。

---

### 4.1 `attach` — 附加进程

```
game-modifier attach (--pid N | --process NAME | --exe PATH) [--allow-anti-cheat]
```

| 参数 | 说明 |
| --- | --- |
| `--pid` | 进程 PID（三者互斥，必选其一） |
| `--process` | 进程名，如 `game.exe`；同名多进程时会报错并列出候选，需改用 `--pid` |
| `--exe` | 可执行文件完整路径 |
| `--allow-anti-cheat` | 强制忽略反作弊拒绝（**不推荐**） |

返回 `session_id`、`pid`、`arch`、`engine_detail`、`anti_cheat`、`module_count`、`is_admin`。会话持久化在 `~/.game-modifier/sessions/` 下，跨命令、跨终端复用。

```powershell
game-modifier attach --process game.exe
game-modifier attach --pid 12345
game-modifier attach --exe "D:\Games\MyGame\game.exe"
```

---

### 4.2 `analyze` — 引擎与工具链分析

```
game-modifier analyze [--session ID] [--target PATH] [--deep]
```

| 参数 | 说明 |
| --- | --- |
| `--session` | 已附加的会话（可与 `--target` 二选一） |
| `--target` | 无会话时直接分析游戏 exe / 目录 |
| `--deep` | 若安装了 radare2，执行静态分析 |

返回 `engine`（Unity Il2Cpp / Mono / Unreal / unknown）、`toolchain.available`、`next_steps`；`--deep` 时附带 `static`（失败则为 `static_error`，不会中断命令）。

检测到引擎但缺少对应工具链时（如 `engine=unity-il2cpp` 但无 dump 产物），先按 4.14 节的「引擎 → 工具链映射」安装推荐工具再继续。

```powershell
game-modifier analyze --session $S
game-modifier analyze --session $S --deep --format json-pretty
game-modifier analyze --target "D:\Games\MyGame"
```

---

### 4.3 `scan` — 首次扫描

```
game-modifier scan --session ID [--type TYPE] [--value V] [--comparator C] [--value2 V2] [--progress]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--type` | `int32` | 数据类型 |
| `--value` | — | 目标值（`unknown` 比较器可省略） |
| `--comparator` | `exact` | 比较方式 |
| `--value2` | — | `between` 的第二个边界 |
| `--progress` | 关 | 每扫完一个内存区域向 **stderr** 打印一行进度（`regions_done/regions_total`、已扫字节数、当前命中数），不污染 stdout 的 JSON 结果 |

**并行扫描**：首次扫描默认使用 `[scan] workers`（默认 **4**）个工作线程按区域并行读取（基于 numpy 向量化；未安装 numpy 时自动退化为单线程，候选集与单线程完全一致）。

**首次扫描可用比较器**：`exact`、`not_equal`、`gt`、`gte`、`lt`、`lte`、`between`、`unknown`。

返回 `count`、`truncated`、`addresses_hex`（前 20 个样本）、`sample_values`、`scanned_regions`、`scanned_bytes`。候选集完整保存在会话中供 `scan-next` 使用；上限由配置 `scan.max_results`（默认 20000）控制，超出时 `truncated` 为 `true`。

```powershell
# 精确值
game-modifier scan --session $S --type int32 --value 250
# 浮点（如移动速度）：先用区间缩小范围
game-modifier scan --session $S --type float --comparator between --value 5.0 --value2 6.0
# 完全不知道当前值：先全量收集，再靠 scan-next 的变化比较器筛
game-modifier scan --session $S --type int32 --comparator unknown
```

> 提示：浮点数很少能精确命中，优先用 `between` / `changed` / `decreased` 这类比较器。

---

### 4.4 `scan-next` — 渐进筛选

```
game-modifier scan-next --session ID [--comparator C] [--value V] [--value2 V2]
```

在上一次扫描的候选集上继续过滤。除首次扫描的全部比较器外，额外支持 4 个**相对上一轮**的比较器：`changed`、`unchanged`、`increased`、`decreased`。

没有前置扫描时返回 `E_NEEDS_SCAN`。

```powershell
game-modifier scan-next --session $S --value 180
game-modifier scan-next --session $S --comparator decreased
game-modifier scan-next --session $S --comparator unchanged
```

---

### 4.5 `read` — 读取数值

```
game-modifier read --session ID [--symbol NAME] [--address ADDR] [--type TYPE] [--offsets OFF]
```

用符号或地址读取当前值。用 `--symbol` 时类型与偏移取符号表中的定义，可用 `--type` 覆盖。

```powershell
game-modifier read --session $S --symbol player.gold
game-modifier read --session $S --address 0x1f2a3b40 --type int32
game-modifier read --session $S --address 0x7ff612340000 --type int32 --offsets "0x10,0x28"
game-modifier read --session $S --address "0x1b0c00276c5-0x8" --type int32
```

返回 `address_hex`、`type`、`value`、`symbol`。

> **地址算术**：`--address` / `--base` 支持仅含 `+` `-` 的算术表达式（十六进制与十进制可混用，如 `0x1b0c00276c5-0x8`、`12345+0x10`），结果为负时报 `E_INVALID_ARGS`。模块语法 `game.exe+0x1A4` 不受影响。

---

### 4.6 `modify` — 写入数值

```
game-modifier modify --session ID [--symbol NAME] [--address ADDR] [--type TYPE]
                     [--value V] [--offsets OFF] [--confirm] [--freeze]
```

| 参数 | 说明 |
| --- | --- |
| `--symbol` / `--address` | 目标定位方式（二选一） |
| `--type` | 数据类型；用符号时可省略 |
| `--value` | 要写入的值；也接受 `max` / `min` 记号 |
| `--offsets` | 指针偏移链 |
| `--confirm` | **必须显式给出才会真正写入**，否则只做 dry-run |
| `--freeze` | 写入后把该目标注册为冻结项 |

**不带 `--confirm` 时**：返回 `dry_run: true`、`applied: false`、`status: "dry_run_preview"` 与双语 `hint`（提示这是预览、未实际写入），并报告 `old_value` / `new_value` / 待写入的 `bytes` 与目标区域风险 `risk`（`normal` = 可写数据段，`high` = 代码段/只读/未知区域），不修改任何内存。

**带 `--confirm` 时**：若配置 `safety.auto_backup` 为真（默认），先快照原始字节并返回 `backup_id`，然后写入并回读校验（`verified_value`），返回 `applied: true`、`status: "applied"`、`bytes_written`，同样携带 `risk` 字段。**判定写入结果以 `status` 字段为准**（`dry_run_preview` ≠ 已写入，见 7.1）。

```powershell
# 1) 先看效果
game-modifier modify --session $S --symbol player.health --value 100
# 2) 真正写入
game-modifier modify --session $S --symbol player.health --value 100 --confirm
# 3) 写入并锁定（无限生命）
game-modifier modify --session $S --symbol player.health --value max --confirm --freeze
# 4) 直接按地址改浮点
game-modifier modify --session $S --address 0x1f2a3b40 --type float --value 9.5 --confirm
# 5) --address 也支持算术表达式（仅 +/-，见 4.5 说明）
game-modifier modify --session $S --address "0x1f2a3b40+0x10" --type int32 --value 42 --confirm
```

> 目标区域不可写时会给出 warning，写入路径会尝试用 `VirtualProtectEx` 临时改权限。

---

### 4.7 `resolve` — 解析指针链

```
game-modifier resolve --session ID (--base EXPR [--offsets OFF] | --pointer FULL_PATH) [--mode MODE] [--deref-last | --no-deref-last]
```

| 参数 | 说明 |
| --- | --- |
| `--base` | 基址表达式，如 `GameAssembly.dll+0x1234`；也支持地址算术，如 `0x1b0c00276c5-0x8`（仅 `+`/`-`） |
| `--offsets` | 偏移链，如 `0x10,0x20` |
| `--pointer` | 一次性写法：`Module.dll+0x1234,0x10,0x20`（首段为基址，其余为偏移） |
| `--mode` | 偏移语义，默认 `pointer_chain`；三种模式见下表 |
| `--deref-last` / `--no-deref-last` | 仅 `field_chain` 生效：最后一步偏移后是否解引用（默认开）；`--no-deref-last` 停在值类型字段自身的地址 |

两者都不给时返回 `E_INVALID_ARGS`。返回最终地址与逐级 `trace`，便于确认哪一级指针断了（`field_chain` 的每步 trace 额外带 `op` 标注）。

**三种模式语义对照**（每步对当前地址 `addr` 做什么）：

| 模式 | 每步运算 | 适用场景 | 典型写法 |
| --- | --- | --- | --- |
| `relative` | `addr = addr + offset`（仅加法，从不解引用） | 已知绝对地址上的结构体字段偏移 | `resolve --base 0x1234 --offsets 0xC --mode relative` |
| `pointer_chain` | `addr = read(addr) + offset`（先解引用再加偏移，Cheat Engine 风格） | 指针数组 / 链表等 CE 风格指针路径 | `resolve --base "Game.dll+0x1A4" --offsets "0x10,0x28"` |
| `field_chain` | `addr = read(addr + offset)`（先加偏移再解引用） | **嵌套结构体字段链**：字段本身是指针、需逐级深入，如 `gem.__data.MainPowerData.mPowerType` | `resolve --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain` |

选错模式的典型症状：对结构体字段链用 `pointer_chain`，解引用会读到 klass / vtable 之类的无关指针而非字段值；此时改用 `field_chain` 即可。

**`field_chain` 实例**（`gem.__data.MainPowerData.mPowerType`，偏移分别为 `0x10` / `0x20` / `0x08`）：

```powershell
# 字段指向一个对象：默认最后一步也解引用，直接得到对象地址
game-modifier resolve --session $S --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain
# 字段本身是值类型（int/float）：--no-deref-last 停在字段地址，随后直接 read 取值
game-modifier resolve --session $S --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain --no-deref-last
game-modifier read --session $S --address <上一步返回的地址> --type int32
```

```powershell
game-modifier resolve --session $S --base "GameAssembly.dll+0x1234" --offsets "0x10,0x20"
game-modifier resolve --session $S --pointer "GameAssembly.dll+0x1234,0x10,0x20"
game-modifier resolve --session $S --base 0x7ff612340000 --offsets 0x28
```

---

### 4.8 `nl` — 中文/英文自然语言修改

```
game-modifier nl --session ID "<短语>" [--confirm]
```

解析是**确定性的**（词典 + 正则，不调用任何大模型），所以结果可复现、零延迟。

**支持的语义字段（16 个）**及部分触发词：

| 字段 | 默认类型 | 触发词示例 |
| --- | --- | --- |
| `gold` | int32 | 金币、金钱、钱、硬币、coin、gold、money、gil |
| `gem` | int32 | 钻石、宝石、gem、diamond、crystal |
| `health` | int32 | 生命、血量、血、生命值、hp、health |
| `mana` | int32 | 法力、魔法、蓝量、mp、mana |
| `stamina` | int32 | 体力、耐力、精力、stamina、energy、能量 |
| `move_speed` | float | 移速、移动速度、速度、movespeed、speed |
| `attack` | int32 | 攻击、攻击力、伤害、atk、damage |
| `defense` | int32 | 防御、防御力、护甲、def、armor |
| `ammo` | int32 | 弹药、子弹、弹夹、ammo、bullets、rounds |
| `level` | int32 | 等级、级别、lv、lvl、level |
| `exp` | int32 | 经验、经验值、exp、xp |
| `score` | int32 | 分数、得分、积分、score、points |
| `lives` | int32 | 生命数、命数、lives |
| `skill_points` | int32 | 技能点、sp、skill points |
| `durability` | int32 | 耐久、耐久度、durability |
| `attribute_points` | int32 | 属性点、attribute points |

**支持的动作**：

| 动作 | 触发词示例 | 行为 |
| --- | --- | --- |
| 设置 | 设为、改为、设置成、修改为、调成、置为、set to、`=` | 写入指定值 |
| 增加 | 增加、加上、添加、多给、add、increase | 读当前值后加 |
| 减少 | 减少、扣除、降低、减掉、subtract、decrease | 读当前值后减 |
| 冻结 | 无限、无敌、锁定、冻结、固定、永久、infinite、god mode | 注册冻结（配合 `freeze start`） |
| 读取 | 查看、读取、查询、显示、get、read、show | 只读不写 |
| 最大/最小 | 最大、拉满、满值、max / 清零、归零、min | 写入类型上/下限 |
| 解锁 | 解锁、全部解锁、unlock all | 游戏相关，返回 `E_NEEDS_SCAN` 并建议用模板 |

数字支持阿拉伯数字（`9999`）、全角数字（`９９９９`）、千分位（`9,999`）、小数（`9.5`）和中文数字（`九千九百九十九`）。

**字段 → 符号的映射规则**：依次尝试 `<field>`、`player.<field>`、`weapon.<field>`、`resource.<field>`，再尝试任意末段等于字段名的符号。找不到就返回 `E_NEEDS_SCAN`，其 `details.next` 会直接给出该扫什么类型、什么值，以及随后的 `name set` 命令，因此**先 `scan` + `name set`，NLP 才能生效**。

```powershell
game-modifier nl --session $S "将金币设为9999" --confirm
game-modifier nl --session $S "生命值拉满" --confirm
game-modifier nl --session $S "无限弹药" --confirm
game-modifier nl --session $S "移动速度设为8.5" --confirm
game-modifier nl --session $S "经验增加10000" --confirm
game-modifier nl --session $S "set health to 100" --confirm
game-modifier nl --session $S "查看金币"
```

返回内容包含 `intent`（识别出的 `action`/`field`/`value`/`confidence`/`matched`）加上与 `modify` 一致的结果字段。**不加 `--confirm` 同样只是 dry-run。**

---

### 4.9 `name` — 会话符号表

```
game-modifier name set <NAME> --session ID --base EXPR [--offsets OFF] [--mode {relative,pointer_chain,field_chain}] [--type TYPE] [--description TEXT] [--temp]
game-modifier name get [NAME] --session ID
game-modifier name chain <NAME> --session ID --base EXPR [--offsets OFF] [--type TYPE] [--mode {pointer_chain,field_chain}] [--persist]
game-modifier name clear-temp --session ID
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `<NAME>` | 必填 | 符号名，建议用 `player.gold`、`weapon.ammo`、`resource.wood` 这类带前缀的写法，便于 NLP 与模板自动匹配 |
| `--base` | 必填 | 基址表达式或裸地址 |
| `--offsets` | 无 | 指针偏移链 |
| `--mode` | 自动 | 偏移语义：`relative`（裸地址默认）、`pointer_chain`（模块表达式默认）或 `field_chain`（嵌套结构体字段链，语义见 4.7 对照表）；符号上保存的 mode 会在后续 read/modify 时自动使用 |
| `--type` | `int32` | 数据类型 |
| `--description` | 空 | 备注 |
| `--temp`（`set`） | 关 | 标记为**临时符号**，之后可用 `name clear-temp` 一次性清除（持久符号不受影响） |
| `--mode`（`chain`） | `pointer_chain` | 链遍历语义：`pointer_chain`（deref+offset）或 `field_chain`（offset+deref，嵌套结构体字段） |
| `--persist`（`chain`） | 关 | `name chain` 注册的中间符号默认是临时的，加 `--persist` 改为持久保存 |

`name get` 不带名字时列出全部符号。

**`name chain` — 指针链遍历 + 中间态符号化**：沿 `--base` + `--offsets` 逐级解引用，把每一级地址注册为符号：`<NAME>.step0`（基址解析结果）、`<NAME>.step1..N-1`（每次解引用）、`<NAME>`（最终地址）。默认按 CE 风格 `pointer_chain`（deref+offset）遍历；`--mode field_chain` 改为结构体字段语义（offset+deref，最后一步不解引用，`<NAME>` 直接指向字段/对象）。链在中途断裂时**已成功解析的中间符号仍会保留**（返回里报告断点），方便从断点继续排查，不必从头重来。

**`name clear-temp`**：删除会话中所有临时符号（`--temp` 注册的符号与 `name chain` 的中间符号），持久符号保留不动。

```powershell
game-modifier name set player.gold --session $S --base 0x1f2a3b40 --type int32
game-modifier name set player.health --session $S --base "GameAssembly.dll+0x2A1B08" --offsets "0x10,0x64" --type int32 --description "主角HP"
game-modifier name set gem.power --session $S --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain --type int32   # 结构体字段链符号
game-modifier name set probe.tmp --session $S --base 0x1f2a3b40 --temp   # 临时符号
game-modifier name chain mgr --session $S --base "Game.exe+0x1A4" --offsets "0x10,0x28,0x0"   # 注册 mgr.step0..step2 + mgr
game-modifier name chain gem --session $S --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain   # 结构体字段链遍历
game-modifier name chain mgr --session $S --base "Game.exe+0x1A4" --offsets "0x10,0x28,0x0" --persist   # 中间符号也持久化
game-modifier name clear-temp --session $S   # 只清理临时符号
game-modifier name get --session $S
game-modifier name get player.gold --session $S
```

---

### 4.10 `template` — 类型模板

```
game-modifier template list
game-modifier template show <NAME>
game-modifier template apply --session ID --template NAME --option OPT [--param k=v ...] [--confirm]
```

内置三套模板（用户模板可放到 `~/.game-modifier/templates/`）：

| 模板 | 适用类型 | 选项 |
| --- | --- | --- |
| `rpg` | rpg / jrpg / arpg / roguelike | `infinite_health`、`infinite_mana`、`infinite_stamina`、`set_gold`(amount)、`set_level`(amount)、`max_attributes` |
| `action` | 动作 / 射击 | `infinite_health`、`infinite_ammo`、`no_reload`、`infinite_armor`、`one_hit_kill`(amount)、`infinite_grenades` |
| `strategy` | 策略 / 模拟经营 | `infinite_money`(amount)、`infinite_resources`(amount)、`max_population`、`instant_build` |

模板以**符号名**为目标（如 `player.health`、`weapon.ammo`、`resource.wood`），所以**必须先用 `scan` + `name set` 建立对应符号**；缺失的符号会在返回结果的 `missing` 里列出，而不是让整条命令失败。

`--param` 可重复，用于填充模板里的 `${amount}` 占位符。

```powershell
game-modifier template list
game-modifier template show rpg --format json-pretty
game-modifier template apply --session $S --template rpg --option infinite_health --confirm
game-modifier template apply --session $S --template rpg --option set_gold --param amount=999999 --confirm
game-modifier template apply --session $S --template action --option infinite_ammo --confirm
game-modifier template apply --session $S --template strategy --option infinite_resources --param amount=99999 --confirm
```

---

### 4.11 `batch` — 批处理

```
game-modifier batch run --session ID <FILE> [--confirm] [--confirm-code] [--continue-on-error] [--offset N] [--limit M]
```

| 参数 | 说明 |
| --- | --- |
| `<FILE>` | YAML 批处理文件路径 |
| `--confirm` | 真正执行写入（默认只放行 `risk=normal` 的写操作，见下方「写风险分级」） |
| `--confirm-code` | 同时放行高风险写入（目标位于可执行/只读/未知区域）；不加时 confirm 只写 `risk=normal` 项，高风险项被跳过 |
| `--continue-on-error` | 遇错继续（默认遇到第一个错误就停） |
| `--offset` | 内联返回的结果窗口起点下标（默认 0，分页用） |
| `--limit` | 内联返回的最大结果条数（默认 0 = 全部；完整结果始终落盘） |

批处理文件是一个 mapping，必须包含非空的 `operations` 列表；每个操作项**只能选择一个动作键**，可选键为：`nl`、`modify`、`template`、`scan`、`scan_next`、`read`、`resolve`、`name`、`backup`。文件顶层的 `confirm: true`、`confirm_code: true` 与 `stop_on_error` 可以覆盖命令行行为。

`samples/example_batch.yaml`：

```yaml
confirm: true
stop_on_error: true
operations:
  - nl: "将金币设为777"
  - modify:
      symbol: player.move_speed
      type: float
      value: 9.0
  - read:
      symbol: player.gold
  - read:
      symbol: player.move_speed
```

各动作键接受的字段：

| 动作键 | 载荷 |
| --- | --- |
| `nl` | 字符串，或 `{text: "..."}` |
| `modify` | `symbol` / `address` / `type` / `value` / `offsets` / `freeze` |
| `template` | `template`（模板名，必填）、`option`（必填）、`params`（字典） |
| `read` | `symbol` / `address` / `type` / `offsets` |
| `resolve` | `base`（必填）、`offsets` |
| `scan` | `type`（必填）、`value`、`comparator`、`value2` |
| `scan_next` | `comparator`、`value`、`value2` |
| `name` | `name`（必填）、`base`（必填）、`offsets`、`type`、`description` |
| `backup` | `targets`（目标列表） |

```powershell
game-modifier batch run --session $S samples\example_batch.yaml --confirm
game-modifier batch run --session $S my_ops.yaml --confirm --continue-on-error
# 结果很多时：只看第 20~39 条内联结果，完整数据读 results_file
game-modifier batch run --session $S big_ops.yaml --confirm --offset 20 --limit 20
```

返回汇总：`total`、`executed`、`ok_count`、`error_count`、`stopped_early`、`results`（每步含 `index`、`action`、`ok` 或 `error`）。

**写风险分级**：执行前会对每个写步骤的目标内存区域做风险分类——可写数据段 → `risk: "normal"`；可执行段（代码段）、只读或未知区域 → `risk: "high"`（保守判定）。

- **dry-run 预览**：每步结果带 `risk` 字段，汇总里带 `risk_breakdown`（如 `{"high": 2, "normal": 5}`）；存在高风险项时汇总附带 `hint` 提醒。
- **确认执行**：默认只放行 `risk=normal` 项；高风险项被**跳过**并标记 `skipped: true` + `skipped_reason: "high_risk_requires_confirm_code"`（不算失败，汇总里附 `skipped_high_risk` 计数与 `hint`）。
- 确认可控（如有意的代码 patch）时，加 `--confirm-code`（MCP：`confirm_code: true`；YAML 顶层：`confirm_code: true`）重跑即可放行高风险项。

**结果持久化与分页**：无论结果多少，完整结果**始终**落盘到 `sessions/<id>/batch_results/<时间戳>.json`，返回中以 `results_file`（文件路径）与 `results_total`（总条数）给出；内联 `results` 窗口可用 `--offset` / `--limit` 分页（MCP `batch_run` 同名参数 `offset` / `limit`）。MCP 返回超过约 50000 字符时不再做二分截断，而是给摘要 + 前 10 条 + `results_file` 提示（`preview_note`），完整数据请直接读该文件或分页取。

---

### 4.12 `freeze` — 数值冻结

```
game-modifier freeze list  --session ID
game-modifier freeze clear --session ID
game-modifier freeze run   --session ID [--interval SEC] [--iterations N]
game-modifier freeze start --session ID [--interval SEC]
game-modifier freeze stop  --session ID
```

| 子命令 | 说明 |
| --- | --- |
| `list` | 列出已注册的冻结项 |
| `clear` | 清空冻结项 |
| `run` | 在**前台**持续回写，`--interval` 默认 `0.05` 秒，`--iterations` 默认 `0`（直到 Ctrl-C；中断时返回 `{"interrupted": true}`） |
| `start` | 在**后台进程**中执行冻结（推荐）；没有冻结项时返回 `started: false` |
| `stop` | 停止后台冻结进程 |

冻结项通过 `modify --freeze`、`nl "无限xxx"` 或模板中 `strategy: freeze` 的选项注册。

```powershell
game-modifier modify --session $S --symbol player.health --value max --confirm --freeze
game-modifier freeze list --session $S
game-modifier freeze start --session $S
# 玩一会儿……
game-modifier freeze stop --session $S
game-modifier freeze clear --session $S
```

> 注：对 `max` 的冻结会保持**当前值**而不是类型极值，这样「无限」不会因为写入超大数字而触发游戏的异常检查。
>
> 冻结回写间隔默认启用**自适应**（配置 `[freeze] adaptive = true`）：按观察到的写压在 `min_interval`（默认 0.05s）与 `max_interval`（默认 1.0s）之间自动调节，既避免高频空转也防止被游戏盖回。可用环境变量 `GAME_MODIFIER_FREEZE_ADAPTIVE=0/1` 临时开关。

---

### 4.13 `backup` — 备份与恢复

```
game-modifier backup create --session ID [--symbol NAME] [--address ADDR] [--type TYPE]
                            [--offsets OFF] [--size N] [--label TEXT]
game-modifier backup list    --session ID
game-modifier backup restore --session ID <BACKUP_ID>
```

`--size` 用于配合 `--address` 备份没有固定类型的字节范围。`safety.auto_backup` 为真时，每次 `--confirm` 写入都会自动创建备份，`backup_id` 在 `modify` 的返回里。

```powershell
game-modifier backup create --session $S --symbol player.gold --label "改之前"
game-modifier backup list --session $S
game-modifier backup restore --session $S bk-20260730-101112
```

找不到备份 ID 时返回 `E_BACKUP_NOT_FOUND`。

---

### 4.14 `toolchain` — 逆向工具探测

```
game-modifier toolchain detect
```

报告已安装的逆向工具（全部可选，缺失时优雅降级）：radare2 / rizin、x64dbg / x32dbg、WinDbg / cdb、Binary Ninja、Il2CppDumper / il2cpp-dumper-rs / Il2CppInspector、UE4 Dumper / UE4SS。缺失的工具报告 `found: false` 并附安装 `hint`。

不在 PATH 上的工具请在配置文件 `[tools]` 段落里写明确路径（见第 8 章）。

```powershell
game-modifier toolchain detect --format json-pretty
```

**检测到引擎但工具缺失时的工作流**（推荐让 AI 自动安装）：

1. **AI 推荐安装**：`toolchain detect` 报 `found: false`、命令报 `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING`，或 `analyze` 检测到引擎但缺对应转储产物时，AI 会说明缺失工具的作用并给出安装命令；
2. **安装**：经用户确认后由 AI 执行安装命令（或用户手动安装）；
3. **验证**：重跑 `toolchain detect`，确认对应工具 `found: true`；
4. **重试**：重新执行原本失败的命令（如 `il2cpp dump` / `xrefs` / `disasm`）。

**引擎 → 工具链映射**：

| 场景 | 检测信号 | 推荐安装的工具 | 安装方式 |
| --- | --- | --- | --- |
| Unity Il2Cpp 游戏 | `analyze` 报告 `engine=unity-il2cpp` 且无 dump 产物 | **il2cpp-dumper-rs**（首选，Rust 实现速度快，支持 metadata v16-v39）或 Il2CppDumper（仅 metadata ≤ 31） | GitHub release 下载二进制；配置 `[tools] il2cppdumper_rs`（或 `il2cppdumper`）路径 |
| Unreal Engine 游戏 | `analyze` 报告 `engine=unreal` 且无 offsets | **UE4SS**（首选，运行时注入 + SDK dump）或 UE4 Dumper | UE4SS release 下载；放入游戏目录或配置 `[tools] ue4ss` |
| 交叉引用 / 静态分析 | `analyze --deep` 报 `E_TOOL_NOT_FOUND`（缺 radare2）。注意：`xrefs` 缺 radare2 时**不报错**，静默切换纯 Python 兜底（`data.backend=python`）；想要静态分析结果才需要装 radare2 | **radare2** | `winget install radare2` 或官网下载；`pip install ".[radare2]"` 装 r2pipe |
| 反汇编功能 | `disasm` 报 `E_DEPENDENCY_MISSING`（缺 capstone） | **capstone** | `pip install ".[disasm]"` |

详细安装命令与 `[tools]` 配置示例见 `INSTALL_GUIDE.md` 5.2 节「工具自动安装」。

**典型场景示例（Unity Il2Cpp 游戏首次分析）**：

```powershell
game-modifier attach --process unitygame.exe      # engine = unity-il2cpp
game-modifier il2cpp dump --session $S            # → E_TOOL_NOT_FOUND，hint 推荐 il2cpp-dumper-rs
# AI 提议安装：下载 il2cpp-dumper-rs release，用户确认后执行；
# 解压到 C:\Tools\il2cpp-dumper-rs\，并在 ~/.game-modifier/config.toml 写入：
#   [tools]
#   il2cppdumper_rs = "C:/Tools/il2cpp-dumper-rs/il2cpp_dumper.exe"
game-modifier toolchain detect                    # → il2cppdumper_rs: found: true
game-modifier il2cpp dump --session $S            # → 重试成功，script.json / dump.cs 关联到会话
```

---

### 4.15 `sessions` / `session` / `detach` — 会话管理与快照

```
game-modifier sessions
game-modifier session <SESSION_ID>
game-modifier session snapshot <NAME> --session ID
game-modifier session snapshots --session ID
game-modifier session restore <NAME> --session ID
game-modifier detach  <SESSION_ID>
```

- `sessions`：列出所有已保存会话。
- `session <id>`：查看单个会话详情（PID、进程名、引擎、符号表、扫描状态、冻结项等）。
- `session snapshot <name> --session <id>`：把当前会话状态（符号表、扫描摘要、引擎判定等）存为命名快照，落盘在 `sessions/<id>/snapshots/<name>.json`。快照名只允许字母、数字、`_`、`-`、`.`。
- `session snapshots --session <id>`：列出该会话的全部快照（名称、创建时间、大小）。
- `session restore <name> --session <id>`：按名称恢复快照。**恢复前会先把当前状态自动归档为 `<name>.pre-restore.json`**，误恢复也能再退回去。快照不存在时返回 `E_INVALID_ARGS`，`details.known` 列出可用快照名。
- `detach <id>`：删除会话记录（不会终止游戏进程）。

```powershell
game-modifier sessions
game-modifier session game.exe-1a2b3c --format json-pretty
game-modifier session snapshot before-experiment --session $S
game-modifier session snapshots --session $S
game-modifier session restore before-experiment --session $S
game-modifier detach game.exe-1a2b3c
```

游戏重启后 PID 会变，旧会话的操作会返回 `E_PROCESS_EXITED`，需重新 `attach`。快照恢复的也是**会话状态**（符号表等），恢复后仍应先用 `read` / `resolve` 验证地址是否仍然有效。

---

### 4.16 `scan-aob` — AOB 模式扫描

```
game-modifier scan-aob --session ID --pattern PATTERN [--max-results N]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--pattern` | 必填 | 字节模式，空格分隔的十六进制字节，`??` 为通配符，如 `"48 8B ?? ?? 05"` |
| `--max-results` | 1000 | 返回的命中地址上限 |

按字节签名在可读内存中定位地址（Cheat Engine 的 AOB 扫描）。与值扫描不同，它不关心数值，只匹配字节序列，适合定位代码位置、结构体特征或已知签名的数据。未命中返回 `E_PATTERN_NOT_FOUND`。

```powershell
game-modifier scan-aob --session $S --pattern "48 8B ?? ?? 05"
game-modifier scan-aob --session $S --pattern "89 45 ?? 8B 45" --max-results 50
```

---

### 4.17 `layout` — 内存布局分析

```
game-modifier layout --session ID [--what {vtables,rtti,class,heap}] [--address ADDR] [--module NAME]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--what` | `vtables` | 分析类型：`vtables` / `rtti` / `class` / `heap` |
| `--address` | — | `class` 时为实例地址；`heap` 时作 vtable 过滤器 |
| `--module` | — | `vtables` 时把候选限定到指定模块 |

只读的逆向分析，结果带置信度与理由。四种模式：

- `vtables`：找指向代码段的指针簇（虚表候选）。
- `rtti`：提取 MSVC `.?AV` 类名（RTTI）。
- `class`：给出某 vtable 实例的字段布局（需 `--address`）。
- `heap`：枚举堆对象候选（对齐的指针形 slot），可按 vtable 过滤。

不支持的分析场景返回 `E_LAYOUT_UNSUPPORTED`。

```powershell
game-modifier layout --session $S --what vtables --module GameAssembly.dll
game-modifier layout --session $S --what rtti
game-modifier layout --session $S --what class --address 0x1f2a3b40
game-modifier layout --session $S --what heap
```

---

### 4.18 `pointer-scan` — 指针链反查

```
game-modifier pointer-scan --session ID --address ADDR [--max-depth N] [--max-paths N] [--rescan] [--async] [--timeout N]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--address` | 必填 | 目标地址（反查能到达它的指针链） |
| `--max-depth` | `[analysis] pointer_scan_max_depth`（默认 2） | 解引用跳数上限 |
| `--max-paths` | `[analysis] pointer_scan_max_paths`（默认 500） | 报告的路径上限 |
| `--rescan` | 关 | 不做全新扫描，改为**重新验证**上次保存的路径是否仍能到达 `--address`（路径稳定性检查） |
| `--async` | 关 | 以后台任务运行：立即返回 `job_id`，**无 30s 硬超时**，用 `job status <job_id>` 轮询进度 |
| `--timeout` | 无上限 | 仅对 `--async` 生效：墙钟秒数上限（可选的安全网） |

自动反向指针扫描：找出「base + offsets」能解引用到目标地址的指针路径，用于把易失的裸地址换成跨重启稳定的模块相对指针链。超出时间预算（`[analysis] scan_timeout`）抛 `E_SCAN_TIMEOUT`。

**路径持久化与 `--rescan`**：扫描发现的路径数量超过 500 条时会外置保存到会话的 sidecar 文件 `sessions/<id>/pointer_paths.bin`（gzip 压缩 JSONL；少量时也可能内联），会话元数据 `pointer_scan_meta` 记录条数与目标地址，返回结果只带样本。`--rescan` 会从 sidecar 加载上次路径、逐条重新解引用验证：仍然有效的保留（按深度 / 稳定性排序并回写 sidecar），失效的丢弃——适合游戏重启或场景切换后确认哪条指针链还活着。会话尚无已保存路径时 `--rescan` 返回 `E_LAYOUT_UNSUPPORTED`。

```powershell
game-modifier pointer-scan --session $S --address 0x1f2a3b40
game-modifier pointer-scan --session $S --address 0x1f2a3b40 --max-depth 3 --max-paths 100
# 游戏重启后重新 attach，验证旧路径
game-modifier pointer-scan --session $S --address 0x1f3b5c60 --rescan
# 大地图 / 深深度扫描：提交后台任务，随后轮询
game-modifier pointer-scan --session $S --address 0x1f2a3b40 --async --max-depth 4
game-modifier job status <job_id>
```

**异步模式（`--async`）**：同步版受 `[analysis] scan_timeout`（默认 30s）预算限制，超时会抛 `E_SCAN_TIMEOUT` 并丢弃全部中间成果；`--async` 把扫描放进后台任务，立即返回 `job_id`，默认不限时（`--timeout` 可设可选上限）。结果持久化到 `sessions/<id>/jobs/<job_id>.json`：无论任务最终是 `done`、`failed` 还是被取消，已完成的部分结果都会落盘，不会因超时丢失。进度字段含 `phase` / `depth`（当前解引用深度）/ `paths_found`（已发现路径数）。详见 4.26 `job` 命令组与场景 10。

> MCP 对应工具 `pointer_scan` 的可选参数 `rescan: true` 行为一致；异步用 `async_run: true`（可选 `timeout` 秒），随后用只读工具 `job_status` / `job_list` 轮询，`job_cancel` 取消。

---

### 4.19 `ue` — Unreal Engine 结构内省（只读）

```
game-modifier ue introspect --session ID [--gobjects EXPR] [--gnames EXPR]
                            [--gobjects-pattern PATTERN] [--gnames-pattern PATTERN] [--force]
game-modifier ue actors     --session ID [--gobjects EXPR] [--limit N] [--filter SUBSTR] [--class SUBSTR] [--list]
game-modifier ue fname      --session ID [--address ADDR] [--index N] [--compare-index N]
```

这三个命令**全部只读**：不写内存、不需要 `--confirm`。用途是在 Unreal 游戏里，基于 dumper 给出的 GObjects / GNames 偏移，验证内存布局、枚举 Actor 实例、解码 FName，从而跳过盲扫直接定位对象字段。

#### 4.19.1 `ue introspect` — 探测 GObjects / FNamePool 布局

| 参数 | 说明 |
| --- | --- |
| `--session` | 必填，会话 ID |
| `--gobjects` | GObjects（TUObjectArray）偏移，如 `Game.exe+0x1D2E500` 或裸地址 |
| `--gnames` | GNames（FNamePool）偏移，同上 |
| `--gobjects-pattern` | 辅助定位 GObjects 的 AOB 模式（只产出候选，不会自动采纳） |
| `--gnames-pattern` | 辅助定位 GNames 的 AOB 模式 |
| `--force` | 即使会话已有确认过的缓存布局也重新探测 |

返回假设检验报告：`resolved`（确认后的地址 / 步长 / 方言）、`hypotheses`（每个候选方言的 `confidence` 与 `evidence`）、`verdict`（`confirmed` / `failed` 等）。**verdict 为 confirmed 时会写入会话的 `introspect` 字段持久化**，之后 `ue actors` / `ue fname` 直接复用缓存，`ue introspect` 再次调用时返回 `cached: true`，除非 `--force`。

#### 4.19.2 `ue actors` — 枚举 Actor 实例

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--gobjects` | — | 显式 GObjects 偏移（临时探测，跳过缓存布局；已有缓存的 GNames 方言仍会复用） |
| `--limit` | `100` | 返回的 Actor 上限 |
| `--filter` | — | 按对象名子串过滤 |
| `--class` | — | 按类名子串过滤 |
| `--list` | 关 | 输出逐条明细列表；默认只输出按类聚合的统计视图（更省 token） |

前提是会话中已有 `ue introspect` 确认过的布局（或显式给 `--gobjects`），否则返回 `E_LAYOUT_UNSUPPORTED`。

#### 4.19.3 `ue fname` — 读取 / 解码 / 比较 FName

| 参数 | 说明 |
| --- | --- |
| `--session` | 必填，会话 ID |
| `--address` | FName 结构体地址（8 字节句柄），读出 `comparison_index` / `number`；有缓存 GNames 布局时同时解码出 `decoded` |
| `--index` | 直接解码某个名字池索引（需要已缓存的 GNames 布局） |
| `--compare-index` | 与 `--index` 搭配，按纯整数规则比较两个索引并分别解码 |

`--address` 与 `--index` 至少给一个，否则返回 `E_INVALID_ARGS`；解码索引但没有缓存 GNames 布局时返回 `E_LAYOUT_UNSUPPORTED`。

#### 示例

```powershell
# 1) 用 dumper 拿到的偏移探测并验证布局（结果缓存进会话）
game-modifier ue introspect --session $S --gobjects "Game.exe+0x1D2E500" --gnames "Game.exe+0x1C9A380"

# 2) 枚举 Actor（默认聚合视图：按类统计数量）
game-modifier ue actors --session $S --limit 100
# 按类名过滤后看明细
game-modifier ue actors --session $S --class Player --list

# 3) 读取并解码一个 FName
game-modifier ue fname --session $S --address 0x2a4c8810d40
# 解码 / 比较名字池索引
game-modifier ue fname --session $S --index 1234
game-modifier ue fname --session $S --index 1234 --compare-index 1235

# 4) 布局确认后，把 Actor 字段固化成符号，交给常规 modify / freeze
game-modifier name set player.actor --session $S --base 0x2a4c8810d40 --type int64
```

> 探测与枚举的耗时受 `[analysis] scan_timeout` 时间预算约束，超时抛 `E_SCAN_TIMEOUT`；枚举对象总量上限与分块参数见配置 `[ue]` 段（第 8 章）。

---

### 4.20 `disasm` — 运行时反汇编

```
game-modifier disasm --session ID --address ADDR [--size N] [--arch {x86,x64}] [--blocks]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--address` | 必填 | 目标地址：符号名、`0x..` 裸地址或 `模块+0x..` 表达式 |
| `--size` | `256` | 读取并反汇编的字节数 |
| `--arch` | 按进程架构自动推断（64 位 → x64，32 位 → x86） | 显式指定指令集 |
| `--blocks` | 关 | 按基本块切分（跳转 / 调用 / 返回指令处断块），而不是平铺指令列表 |

只读命令，依赖可选包 **capstone**（`pip install -e ".[disasm]"`；`.[all]` 已包含）。未安装时返回 `E_DEPENDENCY_MISSING`，`hint` 里给出安装命令。

返回字段：

- 平铺模式：`address`、`arch`、`instructions`（每条含地址 / 助记符 / 操作数）、`count`、`truncated`；
- `--blocks` 模式：`blocks`（每块含 `start` / `end`（不含）、`insn_count`、`ends_with`（终结指令助记符；流走完为 `fallthrough`，被指令数预算截断为 `truncated`））。

用途：`scan-aob` 定位到代码位置后，用它确认指令序列与代码结构，再决定改数值还是改代码。

```powershell
game-modifier disasm --session $S --address "game.exe+0x1A2B0"
game-modifier disasm --session $S --address 0x7ff612345670 --size 512 --arch x64
game-modifier disasm --session $S --address player.update_fn --blocks
```

---

### 4.21 `watch` — 数值变化监视

```
game-modifier watch run    --session ID --address ADDR [--type T] [--interval SEC] [--iterations N] [--log FILE]
game-modifier watch start  --session ID --address ADDR [--type T] [--interval SEC]
game-modifier watch stop   --session ID
game-modifier watch report --session ID [--limit N]
```

| 子命令 | 说明 |
| --- | --- |
| `run` | **前台**轮询：每 `--interval` 秒（默认 `0.1`）读一次，记录与上次不同的值；`--iterations` 默认 `100`，设 `0` 则跑到 Ctrl-C（中断时返回 `{"interrupted": true}`）；`--log` 把每条变化追加写入指定 JSONL（后台 worker 内部使用） |
| `start` | **后台进程**监视（推荐）：变化记录持续追加到 `sessions/<id>/watch.jsonl`；已有 worker 在跑时返回 `started: false` 与 `already_running_pid` |
| `stop` | 停止后台监视进程 |
| `report` | 读取后台 worker 记录的变化历史，`--limit` 默认 `50`（`0` = 全部），最新在最后 |

返回字段（`run`）：`address_hex`、`type`、`iterations`（实际轮询次数）、`initial_value`、`final_value`、`changes`（每条 `{iteration, ts, old, new}`，内存里只保留最近的条目）、`change_count`（累计变化次数）、`stable`（全程无变化）。`report` 返回 `change_count`、`returned`、`changes`。

用途：回答「这个值**什么时候**被改的」——轮询式的 find-what-changes。先监视再在游戏里触发行为（受伤 / 花钱），变化时间点可以帮助把扫描收敛到正确的地址，或配合 `disasm` / `xrefs` 进一步定位写入代码。注意它只记录**何时**变化，不能直接告诉你**哪条指令**写入——那需要 `xrefs` / 反汇编确认。

```powershell
# 前台监视 100 轮
game-modifier watch run --session $S --address 0x1f2a3b40 --type int32
# 后台监视：start → 玩一会儿 → report → stop
game-modifier watch start --session $S --address 0x1f2a3b40 --type int32 --interval 0.05
game-modifier watch report --session $S --limit 20
game-modifier watch stop --session $S
```

> MCP 对应工具：`watch_run` / `watch_report`（只读，所有 profile 都有）；`watch_start` / `watch_stop`（默认 profile）。MCP 不暴露前台阻塞式的 `watch run --iterations 0`。

---

### 4.22 `xrefs` — 交叉引用查询

```
game-modifier xrefs --session ID --address ADDR [--direction {to,from}] [--binary PATH]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--address` | 必填 | 目标地址：符号名、`0x..` 或 `模块+0x..`；运行时绝对地址会用会话模块表换算成 RVA |
| `--direction` | `to` | `to` = 谁引用了该地址（axt，用于找写入来源）；`from` = 该地址引用了什么（axf） |
| `--binary` | 会话的 exe 路径 | 指定要分析的二进制文件 |

只读命令，优先使用 **radare2 / r2pipe**（`pip install -e ".[radare2]"` 安装 r2pipe，另需系统装有 radare2；不在 PATH 时在配置 `[tools] radare2 = "..."` 写明路径）。**radare2 不可用时自动切换到纯 Python 兜底后端**：直接扫描目标进程活内存中指向目标地址的指针，返回的 `backend` 字段标注实际后端（`r2pipe` / `subprocess` / `python`）。

注意：r2 后端分析的是**磁盘上的二进制**，不是实时进程内存；Python 兜底则扫的是**活内存**，两者结果来源不同。返回 `backend`、`address`、`direction`、`xrefs`（每条引用的地址 / 类型等）、`count`、`module`、`rva`。MCP 工具 `xrefs` 另有 `aligned` 参数（默认 `true`，只报告 4/8 字节对齐的引用，显著降低噪音；`aligned=false` 返回全部命中）。

典型用法：`watch` 确认某地址会被游戏写入后，用 `xrefs --direction to` 找出引用它的代码位置，再 `disasm` 确认指令结构。

```powershell
game-modifier xrefs --session $S --address 0x1f2a3b40
game-modifier xrefs --session $S --address "game.exe+0x1A2B0" --direction from
game-modifier xrefs --session $S --address 0x7ff612345670 --binary "D:\Games\MyGame\game.exe"
```

---

### 4.23 `find-writers` — 硬件断点定位写入代码

```
game-modifier find-writers --session ID --address ADDR [--size 1|2|4|8] [--duration SEC] [--max-hits N]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--address` | 必填 | 目标地址：符号名、`0x..` 裸地址或 `模块+0x..` 表达式 |
| `--size` | `4` | 监视窗口大小，只能取 `1` / `2` / `4` / `8`（字节） |
| `--duration` | `5.0` | 采样时长（秒）；内部会钳制到安全上限，时间到或命中数达上限即提前结束 |
| `--max-hits` | `20` | 捕获的写入事件上限 |

原理：利用 CPU 调试寄存器（DR0-DR3）给目标地址下**硬件写断点**，通过调试事件捕获写入该地址的指令地址（RIP）、线程 ID 与时间戳。相比 `watch`（轮询只能回答“何时变”）和 `xrefs`（静态分析磁盘二进制），它能**实时**精确回答“哪条指令在写”。

返回字段：`session_id`、`address`、`hits`（每条含 `rip`（写入指令地址）/ `thread_id` / `ts`）、`hit_count`、`duration_sampled`、`restored`（调试寄存器是否已还原）、可能的 `warning`。

**权限与安全要求**：

- 需要**管理员终端**（`DebugActiveProcess` 权限），否则返回 `E_ACCESS_DENIED`；
- 会话检测到反作弊时**直接拒绝**（`E_ANTI_CHEAT`）——硬件断点属于调试行为，绝不能用于受保护游戏；
- 采样期间会短暂挂起目标线程以读取上下文，游戏可能出现瞬间卡顿；结束时自动还原调试寄存器并解除调试附加（所有退出路径都保证）；
- 仅支持 Windows（其他平台 `E_UNSUPPORTED_OS`）。

```powershell
# 先用 watch 确认地址会被写入，再下硬件断点抓写入指令
game-modifier find-writers --session $S --address 0x1f2a3b40 --size 4 --duration 8
game-modifier find-writers --session $S --symbol player.health --max-hits 10
# 拿到 rip 后 disasm 看写入指令
game-modifier disasm --session $S --address 0x<hits中的rip>
```

> MCP 对应工具 `find_writers`（仅默认 profile；readonly profile 不含）。

---

### 4.24 `dissect` — 结构体解剖

```
game-modifier dissect --session ID (--address ADDR | --addresses A,B,C) [--size N]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--address` | — | 单个实例地址（符号名 / `0x..` / `模块+0x..`） |
| `--addresses` | — | 逗号分隔的多个**同类实例**地址，与 `--address` 至少给一个（可同时给） |
| `--size` | `256` | 每个实例读取的字节数 |

Cheat Engine 式的结构体解剖：把每个实例的前 `--size` 字节按指针宽度切槽，跨实例分类每个槽位的类型，全部**只读**。可识别类型：`vtable`（首槽且指向可执行区域）、`ptr`（指向已知内存区域）、`int`（取值在合理整数范围）、`float`（低 32 位可解码为合理 float32）、`bool`（只出现 0/1）、`unknown`（无一致信号，含全零槽位）。

返回字段：`fields`（每个字段含 `offset` / `guessed_type` / `confidence` / `sample_values` / `reason`）、`instances_used`、`instances_skipped`（读不了的实例会被跳过而不报错）、`size_analyzed`、`session_id`。

```powershell
# 单实例解剖
game-modifier dissect --session $S --address 0x1f2a3b40
# 多实例解剖（同一类的多个对象，置信度更高）
game-modifier dissect --session $S --addresses 0x1f2a3b40,0x1f2a3c80,0x1f2a3dc0 --size 512
```

> 提示：传入多个同类实例能显著提升字段推断的 `confidence`（例如某槽位在多个实例中都指向堆内存 → 更确信是 `ptr`）。启发式结果需配合游戏行为验证（`read` / `watch`）后再用于写入。
>
> MCP 对应工具 `dissect`（只读，所有 profile 都有）。

---

### 4.25 `il2cpp` — Unity Il2Cpp 运行时解码与 RVA 反查

```
game-modifier il2cpp string --session ID --address ADDR [--max-chars N]
game-modifier il2cpp list   --session ID --address ADDR [--elem-type T] [--limit N]
game-modifier il2cpp dict   --session ID --address ADDR [--limit N]
game-modifier il2cpp lookup --session ID --rva RVA [--script-json PATH] [--tolerance T] [--force-index] [--force]
game-modifier il2cpp dump   --session ID [--out-dir DIR] [--timeout SEC] [--force]
```

五个子命令：前四个**只读**，`dump` 会调用外部 Il2CppDumper（可写 profile 才有）。`--address` 一律支持符号名 / `0x..` / 地址算术（`0x..+/-0x..`）/ `模块+0x..` 四种写法。地址给错不会崩，而是返回 `ok=false` + `reason`。

**`il2cpp string` — 解码 Il2CppString（UTF-16）**

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--address` | 必填 | Il2CppString 对象地址 |
| `--max-chars` | `4096` | 最多解码的 UTF-16 码元数，超出时 `truncated=true` |

一次调用完成“读 `+0x10` 长度 → 读 `+0x14` 起的 UTF-16LE 字符 → 解码”，替代手工拼字节。返回 `address` / `length` / `value` / `truncated`；长度可疑（地址多半不是字符串或运行时布局被魔改）时返回 `ok=false` 并给出原因。

```powershell
game-modifier il2cpp string --session $S --address 0x2a1b3c40
game-modifier il2cpp string --session $S --address "player.name_ptr+0x0" --max-chars 64
```

**`il2cpp list` — 读取 List\<T\>**

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--elem-type` | `ptr` | 元素解码类型：`ptr` / `int8` / `uint8` / `int16` / `uint16` / `int32` / `uint32` / `int64` / `uint64` / `float` / `double` |
| `--limit` | `100` | 最多返回元素数，`_size` 超过时 `truncated=true` |

沿 `_items` + `_size` 读数组并逐元素解码，返回 `size` / `max_length` / `elements` / `truncated`。`ptr` 元素输出十六进制地址字符串——指向字符串对象时可再喂给 `il2cpp string`。

```powershell
game-modifier il2cpp list --session $S --address 0x2a1b3c80 --elem-type ptr --limit 50
game-modifier il2cpp list --session $S --address 0x2a1b3c80 --elem-type int32
```

**`il2cpp dict` — 读取 Dictionary\<K,V\>**

按 24 字节步进遍历条目表，`hashCode==0` 的空槽自动跳过，返回 `entries`（每条含 `key_ptr` / `value_ptr` 十六进制指针）与 `count`。键值指向 Il2CppString 时用 `il2cpp string` 逐个解码。

```powershell
game-modifier il2cpp dict --session $S --address 0x2a1b3cc0 --limit 200
```

**`il2cpp lookup` — RVA 反查函数名**

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--rva` | 必填 | 十六进制 / 十进制，或 `+`/`-` 地址表达式（如 `0x7ff6a12b8560-0x7ff69c432ef0`，即 RIP 减模块基址） |
| `--script-json` | 会话关联的 dump | 显式指定 script.json 路径 |
| `--tolerance` | `0` | 最近函数入口容差：RVA 落在函数体内时匹配不高于它的最近函数起始地址（如 `0x100`） |
| `--force-index` | 关 | 忽略 sidecar 缓存强制重建索引 |
| `--force` | 关 | 跳过转储新鲜度（二进制指纹）检查 |

基于 Il2CppDumper 的 `script.json` 做 RVA → 方法名反查。索引**懒构建**并缓存为 gzip sidecar（`script.json.idx`），按 script.json 的文件大小 + mtime 指纹自动失效——300MB+ 的 dump 重复查询也在亚秒级。返回 `rva` / `name` / `signature` / `matched`（`exact` 精确命中 / `nearest` 容差命中 / `none` 未命中）。典型用途：把 `find-writers` 抓到的 RIP 换成可读的 IL2CPP 方法名。

**游戏更新失效检测**：`il2cpp dump` 成功时会记录游戏二进制（GameAssembly.dll，找不到时用主 exe）的指纹（大小 + mtime + 文件头 64KB sha256）到会话 artifacts。之后每次 `lookup` 都会重新比对当前二进制：不一致（游戏更新过）时结果附带非阻断的 `stale_warning`（含 `reason`：`size_changed` / `mtime_changed` / `hash_changed` / `binary_missing` 与重跑提示）——**此时旧 RVA 可能已失效，应重跑 `il2cpp dump` 而不是继续用旧结果**；`--force` 可跳过该检查。

```powershell
# find-writers 抓到 RIP=0x7ff6a12b8560，GameAssembly.dll 基址 0x7ff69c432ef0
game-modifier il2cpp lookup --session $S --rva "0x7ff6a12b8560-0x7ff69c432ef0" --tolerance 0x100
```

**`il2cpp dump` — 运行 Il2CppDumper 并关联会话**

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--out-dir` | `sessions/<id>/il2cpp_dump` | 输出目录 |
| `--timeout` | `120` | dumper 进程超时秒数 |
| `--force` | 关 | 即使现有转储指纹仍新鲜也强制重新转储 |

按 global-metadata 版本自动选择 dumper（官方 Il2CppDumper / il2cpp-dumper-rs），成功后把 `script.json` / `dump.cs` 路径写入会话的 engine artifacts——**之后 `il2cpp lookup` 无需任何额外参数**。未安装 dumper 时报 `E_TOOL_NOT_FOUND` 并给出两个 dumper 家族的安装提示（可在配置文件 `[tools]` 段设 `il2cppdumper` / `il2cppdumper_rs` 路径）。

**转储验证**：关联 artifacts 前会验证产物完整性（script.json 可 JSON 解析、含非空 `ScriptMethod`；dump.cs 存在时非空）。验证失败时不关联损坏产物，返回 `ok=false` + `errors` 明细。

**指纹与复用**：成功转储同时记录游戏二进制指纹（`artifacts.binary_fingerprint`）。已有转储且指纹仍新鲜时再次调用会直接复用（返回 `reused=true` + 提示，不重跑 dumper）；指纹不匹配（游戏更新）会自动重转储并在结果中附 `previous_stale` 原因；`--force` 无条件强制重跑。

**游戏更新后的工作流**：`analyze` 发现 `dump_stale` 提示（或 `lookup` 返回 `stale_warning`）→ `il2cpp dump --force`（或指纹陈旧时直接 `il2cpp dump` 会自动重转储）→ 重新 `il2cpp lookup`。

```powershell
game-modifier il2cpp dump --session $S
game-modifier il2cpp dump --session $S --out-dir D:\dump_out --timeout 300
```

> 布局偏移可配置：以上默认偏移按标准 il2cpp x64 运行时（Il2CppString length@0x10 / chars@0x14 等）。魔改运行时可用 Python API 层覆盖——`game_modifier.engines.unity_introspect.read_string` / `read_list` / `read_dict` 均接受 `layout=` 参数（默认值见 `DEFAULT_LAYOUT`）；CLI / MCP 暂不暴露该参数。
>
> MCP 对应工具：`il2cpp_string` / `il2cpp_list` / `il2cpp_dict` / `il2cpp_lookup`（只读，所有 profile 都有）、`il2cpp_dump`（仅默认 profile）。

---

### 4.26 `job` — 后台任务管理

```
game-modifier job status <JOB_ID> [--session ID]
game-modifier job list [--session ID]
game-modifier job cancel <JOB_ID>
```

管理 `--async` 提交的长时间只读分析任务（目前支持 `pointer-scan`）。

| 子命令 | 说明 |
| --- | --- |
| `job status <job_id>` | 查单个任务。`--session` 可选：服务器进程重启后内存注册表丢失，传入会话 ID 可从落盘结果恢复状态 |
| `job list` | 列出全部任务（可按 `--session` 过滤）：`job_id`、`kind`、`status`、进度 |
| `job cancel <job_id>` | 协作式取消：工作线程在下一个检查点停下，先把已有的部分结果落盘再把状态置为 `cancelled` |

**任务状态机**：`pending` → `running` → `done` / `failed` / `cancelled`。返回字段：

- `running`：`progress`（`phase`、`depth` 当前解引用深度、`paths_found` 已发现路径数）。
- `done`：`results_file`（`sessions/<id>/jobs/<job_id>.json`）、`paths_total`、`paths_sample`。
- `failed`：`error`（异常信息）；`cancelled`：部分结果同样已持久化到 `results_file`。

任务与结果都存在会话目录下，进程重启后仍可用 `job status <job_id> --session <id>` 读回落盘结果。

```powershell
game-modifier pointer-scan --session $S --address 0x1f2a3b40 --async --max-depth 4
# -> {"ok": true, "data": {"job_id": "a1b2c3d4", "status": "running", ...}}
game-modifier job status a1b2c3d4
# running -> 再等；done -> 拿 results_file / paths_sample
game-modifier job list --session $S
game-modifier job cancel a1b2c3d4    # 不急了就取消，部分结果保留
```

> MCP 对应工具：`job_status`（参数 `job_id` + 可选 `session`）、`job_list`（可选 `session`），均只读、所有 profile 都有；`job_cancel`（参数 `job_id`）仅默认 profile。

---

### 4.27 `macro` — 参数化宏（可复用操作序列）

```
game-modifier macro define <NAME> --session ID (--file <宏.yaml> | --inline "<YAML字符串>") [--description TEXT]
game-modifier macro list --session ID
game-modifier macro show <NAME> --session ID
game-modifier macro run <NAME> --session ID [--params k=v,k=v] [--confirm] [--stop-on-error | --no-stop-on-error]
game-modifier macro delete <NAME> --session ID
```

宏是**按会话存储**的可复用批处理：定义一次，之后只需传不同参数即可反复执行。内部走与 `batch run` 相同的执行管道（结果同样落盘 `results_file`）。

宏定义（YAML，JSON 也可）：

```yaml
params:                       # 参数声明：名称 -> {description, required, default}
  amount:
    description: 目标数值
    required: true
operations:                   # 与 batch 相同的操作序列，支持 ${param} 占位符
  - modify:
      symbol: player.gold
      type: int32
      value: ${amount}
  - read:
      symbol: player.gold
```

| 子命令 | 说明 |
| --- | --- |
| `macro define <name>` | 从 `--file`（YAML 文件）或 `--inline`（内联 YAML 字符串，二选一）定义宏；同名覆盖 |
| `macro list` | 列出会话内全部宏（名称 / 描述 / 参数 / 操作步数） |
| `macro show <name>` | 展示单个宏的完整定义 |
| `macro run <name>` | 代入 `--params key=value,key=value`（值按 YAML 标量解析，数字 / 布尔会带类型）后执行；写操作同样默认 dry-run，需 `--confirm`；默认遇错即停（`--no-stop-on-error` 继续） |
| `macro delete <name>` | 删除已存储的宏 |

占位符规则与模板一致：整个值恰好是 `${param}` 时保留参数原始类型（如整数）；嵌在字符串里则按字符串拼接。除了声明的参数，每个操作还自动可用内置占位符 `${i}`（当前操作下标）。

错误处理：声明为 `required` 的参数缺失时返回 `E_INVALID_ARGS`，`details.missing` 列出缺哪些、`hint` 给出补参示例；操作里出现无法解析的 `${...}` 占位符也返回 `E_INVALID_ARGS`。

```powershell
game-modifier macro define set_gold --session $S --file gold_macro.yaml --description "把金币设为指定值"
game-modifier macro define set_hp --session $S --inline "params: {hp: {required: true}}`noperations:`n  - modify: {symbol: player.health, type: int32, value: ${hp}}"
game-modifier macro list --session $S
game-modifier macro show set_gold --session $S
game-modifier macro run set_gold --session $S --params amount=99999          # dry-run
game-modifier macro run set_gold --session $S --params amount=99999 --confirm
game-modifier macro delete set_gold --session $S
```

> MCP 对应工具：`macro_list` / `macro_show`（只读，所有 profile 都有）；`macro_define`（参数 `definition` 为 YAML/JSON 字符串）、`macro_run`（参数 `params` 为字典）、`macro_delete` 仅在允许写入管理的 profile（default / dry-run / symbols / limited）。

---

### 4.28 `save-edit` — 存档文件编辑（含 Unity 加密存档）

```
game-modifier save-edit detect --session ID
game-modifier save-edit modify --session ID --path FILE --field FIELD --value VALUE [--key KEY] [--iv IV] [--confirm]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--session` | 必填 | 会话 ID |
| `--path` | 必填 | 存档文件路径（`detect` 输出中的 `path`） |
| `--field` | 必填 | 字段名，支持点分路径（如 `party.gold`） |
| `--value` | 必填 | 新值（自动推断 int/float/bool） |
| `--key` | — | Unity 加密存档的解密密钥（仅 `unity-encrypted` 目标需要） |
| `--iv` | — | DES-CBC 的 IV；缺省取密钥本身（常见 Unity 实现） |
| `--confirm` | false | 缺省 dry-run，加此参数才真正写入 |

存档型引擎（RPG Maker、Ren'Py 及部分 Unity 单机游戏）把玩家状态存在文件里，内存修改会被游戏覆盖；`attach` 返回 `save_edit.required=true` 时应改走本命令。

**支持的格式**：

- RPG Maker：JSON / base64 JSON（`.rmmzsave` / `.rpgsave` / `.json`），直接可改。
- Ren'Py：pickle（`.save`）仅支持 detect（`editable: false`）。
- Unity 自定义加密：`Base64( DES-CBC( JSON ) )`，常见于 `*.sav` / `*.dat`。detect 结果中标记为 `"engine": "unity-encrypted"`、`"editable": "with_key"`。

**Unity 加密存档用法**：密钥/IV 是游戏特定的，来自游戏代码逆向（il2cpp dump / 反编译中的硬编码字符串），需要用户提供：

```powershell
game-modifier save-edit detect --session $S
# data.saves[] 中出现 {"engine": "unity-encrypted", "editable": "with_key", ...}
game-modifier save-edit modify --session $S --path "D:\Games\g\player.sav" --field player.gold --value 99999 --key "MyGameKey"          # dry-run
game-modifier save-edit modify --session $S --path "D:\Games\g\player.sav" --field player.gold --value 99999 --key "MyGameKey" --confirm
```

要点：

- DES 密钥按 UTF-8 取字节并规整到 8 字节（不足补 0、过长取前 8 字节并告警）；IV 缺省等于密钥。
- 写回时按 JSON → PKCS7 填充 → DES-CBC 加密 → Base64 编码重新封装，游戏可正常读档；写入前自动生成 `.bak` 备份。
- 密钥仅在内存中使用，**不落盘**（不写入 session JSON，也不进审计记录）。
- 无密钥修改 `unity-encrypted` 存档报 `E_INVALID_ARGS`（提示补 `--key`）；密钥错误/文件损坏报 `E_SAVE_FORMAT_UNSUPPORTED`（提示核对密钥或从 `.bak` 恢复）。
- 需要可选依赖 pycryptodome：`pip install "game-modifier[crypto]"`（缺失时报 `E_DEPENDENCY_MISSING`）。

> MCP 对应工具：`save_edit_detect`（只读）与 `save_edit_modify`（追加可选 `key` / `iv` 参数，文件名参数叫 `file`）。

---

### 4.29 `scan-candidates` — 候选集分页浏览（只读）

```
game-modifier scan-candidates --session ID [--offset N] [--limit M] [--min-addr 0x..] [--max-addr 0x..]
```

扫描（`scan` / `scan-aob`）会把**完整候选集持久化**到会话文件并在返回中给出 `candidates_file` / `results_file` 与 `candidates_total`。`scan-candidates` 不重新扫描，直接对该持久化候选集分页浏览 / 按地址区间过滤，适合候选量巨大时逐页检查。对应 MCP 工具 `scan_candidates`（全 profile 只读）。`scan` / `scan_aob` 的 MCP 版本还支持 `offset` / `limit`（结果分页）、`min_addr` / `max_addr` / `region_types`（区域过滤）、`stop_on_limit`（AOB 命中上限即停）、`encoding=utf8|utf16le`（字符串扫描编码），并返回 `region_summary` / `page` 摘要——这些为 MCP 专属参数，CLI 层未暴露。

### 4.30 `il` — .NET IL 静态分析与补丁（il-tool）

依赖随包分发的 **il-tool** 子进程（C# 实现，framework-dependent 发布，运行时需 **.NET 8 运行时**；缺失时 `il *` 报 `E_TOOL_NOT_FOUND` 并提示，构建方式见 INSTALL_GUIDE 9.12）。

```powershell
game-modifier il analyze --session $S [--assembly GameAssembly.dll] [--type-filter Player] [--member-filter get_Gold]   # 程序集元数据（只读）
game-modifier il dump --session $S --method "Game.Player::get_Gold" [--type Game.Player]                                   # 单方法 IL 体（只读）
game-modifier il callers --session $S --method get_Gold [--type Player] [--max-results 50]                                  # 调用方反查（只读）
game-modifier il verify --session $S --method "Game.Player::get_Gold" --expect "ldarg.0,ldfld,mul,ret"                      # 断言方法 IL opcode 序列（只读）
game-modifier il backup --session $S [--assembly path] [--label "before patch"]                                             # 文件备份（FileBackupManager）
game-modifier il patch --session $S --op mul_before_ret --method "Game.Player::get_Gold" --value 10 --confirm               # IL 补丁（写，先自动备份）
game-modifier il restore --session $S <backup_id> --confirm                                                                 # 还原
```

`il patch` 支持四种操作：`replace_body`（整体替换方法体）、`mul_before_ret`（每个 ret 前插入乘法，`--value` 为乘数）、`insert_before_ret`、`insert_after_call`（`--target` 指定被调用方法）。默认就地改写程序集（写入前自动文件备份），`--out-assembly path` 可写到新文件。

**推荐工作流（以「金币翻倍」为例）**：

```powershell
game-modifier il analyze --session $S --member-filter get_Gold        # 1. 定位方法全名
game-modifier il callers --session $S --method get_Gold               # 2. 了解谁在调用，评估影响面
game-modifier il backup --session $S --label "before gold patch"      # 3. 先备份原程序集
game-modifier il patch --session $S --op mul_before_ret --method "Game.Player::get_Gold" --value 2 --confirm   # 4. 打补丁
game-modifier il verify --session $S --method "Game.Player::get_Gold" --expect "mul,ret"                       # 5. 验证 IL 已变
# 出问题随时：game-modifier il restore --session $S <backup_id> --confirm
```

MCP 对应工具：`il_analyze` / `il_dump` / `il_callers` / `il_verify`（只读）、`il_patch` / `il_backup` / `il_restore`（写，`il` 组）。

### 4.31 `mono` — Unity Mono 运行时读取

针对 `engine=unity-mono` 游戏的运行时对象解码，除 `mono dump` 外全部只读、全 profile 可用。

```powershell
game-modifier mono dump --session $S [--assembly Assembly-CSharp.dll] [--force]   # 转储 Mono 类型索引（指纹缓存：size/mtime/head-hash 未变则 reused=true）
game-modifier mono symbol --session $S "Player"                                   # 名称子串或 0xRVA 反查符号（只读）
game-modifier mono string --session $S --address 0x.. [--max-chars 4096] [--arch x86|x64]   # 解码 Mono 字符串（架构感知布局）
game-modifier mono list --session $S --address 0x.. [--elem-type ptr] [--limit 100]          # List<T>
game-modifier mono dict --session $S --address 0x.. [--limit 100]                            # Dictionary<K,V>
game-modifier mono static --session $S [--max-results 200]                                   # 扫 JIT 代码中的静态字段加载指令，定位静态字段值
game-modifier mono heap-scan --session $S [--vtable-addr 0x..] [--max-results 500]           # 按 vtable 在堆中找活对象实例
```

MCP 对应工具：`mono_string` / `mono_list` / `mono_dict` / `mono_static` / `mono_heap_scan` / `mono_symbol`（只读，`mono` 组）；`mono_dump` 仅可写 profile（只写缓存 sidecar，不碰游戏内存）。另：MCP `scan` 支持 `encoding=utf16le` 直接扫 UTF-16 字符串；配置 `[scan] fingerprint_mode=lenient` 可在游戏小更新后放宽候选匹配（配合 `scan_next` 的 `retain_stale`）。

### 4.32 `file` — 外部文件快照与还原（safety 组）

`backup` 管理的是**内存字节**备份；`file` 管理的是**磁盘文件**备份（存档、配置、程序集等任何外部文件），由 FileBackupManager 统一管理，存 `sessions/<id>/file_backups/<backup_id>/`（原文件副本 + sha256 + manifest，写操作进审计）。

```powershell
game-modifier file snapshot --session $S "D:\Games\g\saves\slot1.dat" --label "before edit"
game-modifier file restore --session $S <backup_id> --confirm
```

安全约束：`file restore --confirm` 时若目标游戏进程仍在运行会被拒绝（防止写回被运行中的游戏覆盖）。MCP 对应工具 `file_snapshot` / `file_restore`（`safety` 组写工具，需可写 profile；`il_backup` / `il_restore` 复用同一套 FileBackupManager）。

### 4.33 `session_notes` 与 `batch_preview`（MCP 专属）

这两个能力只在 MCP 层提供：

- **`session_notes`**（core 组）：给会话挂键值笔记，存 `sessions/<id>/notes.jsonl`。`action=get` 全 profile 只读（可按 `key` 取单条或取全部）；`action=set`（需 `key` + `value`）/ `action=delete` 需非 readonly profile（readonly 下返回 `E_PROFILE_RESTRICTED`）。适合 Agent 跨轮次记录「player.gold 已定位、值域已验证」等定位链上下文。
- **`batch_preview`**（modify 组，只读、全 profile）：对 `batch_run` 的同一份输入（`file` 或内联 `yaml`，二选一）做**写前预检**：逐项给出 risk 分级与整批 `estimated_write_bytes`，不产生任何写入。推荐 Agent 先 `batch_preview` 再决定是否 `batch_run`。`batch_run` 本身也新增了内联 `yaml` 参数（与 `file` 互斥）。

---

## 5. MCP 服务器模式

相比 CLI，MCP 模式让 AI Agent 以**结构化工具调用**的方式使用本工具，参数校验更严格、token 消耗更低。

### 5.1 安装前提

```powershell
pip install -e ".[mcp]"
```

服务器内置 **FastMCP 兼容层**：启动时依次尝试 `mcp.server.fastmcp`（mcp v1.x）→ `mcp.server` → `mcp`（v2.x 顶层导出）→ 独立 `fastmcp` 包，取第一个可用者。因此只要满足 `mcp>=1.0`（或安装了独立 `fastmcp` 包）即可运行；全部缺失时 `game-modifier-mcp` 会打印安装提示（`pip install game-modifier[mcp]`）并以退出码 1 结束。

### 5.2 Claude Code

本仓库已自带 `.mcp.json` 与插件清单，在仓库目录内启动 Claude Code 即可自动加载：

```json
{
  "mcpServers": {
    "game-modifier": {
      "command": "game-modifier-mcp",
      "args": []
    }
  }
}
```

### 5.3 Codex CLI

在 `~/.codex/config.toml` 中加入：

```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = []
```

需要指定配置文件时：

```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = ["--config", "C:/Users/you/.game-modifier/config.toml"]
```

### 5.4 MCP 暴露的工具

工具总数与逐组成员**以运行时调用 `tools_catalog` 工具返回为准**（它恒注册、列出每组当前成员与计数），下表按功能域给出结构概览：

| 分类 | 工具 |
| --- | --- |
| 会话 | `attach`、`sessions`、`session_info`、`session_survey`、`session_snapshots`（只读）、`session_snapshot`、`session_restore`（可写 profile）、`session_notes`（`get` 全 profile 只读；`set` / `delete` 需非 readonly profile，存 `sessions/<id>/notes.jsonl`）、`detach` |
| 分析 | `analyze`、`toolchain_detect`、`layout_analyze`、`heap_scan`、`pointer_scan`（可选参数 `rescan` 验证已保存路径；`async_run` + `timeout` 后台运行）、`dissect`（只读）、`disasm`、`xrefs`（`aligned` 默认 true；radare2 缺失时纯 Python 兜底，`data.backend` 标注后端） |
| 后台任务 | `job_status`、`job_list`（只读）；`job_cancel`（可写 profile） |
| UE 内省（只读） | `ue_introspect`、`ue_actors`、`ue_fname` |
| Unity Il2Cpp | `il2cpp_string`、`il2cpp_list`、`il2cpp_dict`、`il2cpp_lookup`（只读）；`il2cpp_dump`（调用外部 dumper，可写 profile） |
| .NET IL（il 组） | `il_analyze`、`il_dump`、`il_callers`、`il_verify`（只读）；`il_patch`、`il_backup`、`il_restore`（写，patch 前自动文件备份）。依赖随包分发的 il-tool 子进程（需 .NET 8 运行时，见 INSTALL_GUIDE 9.12） |
| Mono 运行时（mono 组） | `mono_string`、`mono_list`、`mono_dict`、`mono_static`、`mono_heap_scan`、`mono_symbol`（全部只读、全 profile）；`mono_dump`（可写 profile，产物指纹缓存复用） |
| 扫描 | `scan`（MCP 专属：`offset` / `limit` 分页、`min_addr` / `max_addr` / `region_types` 区域过滤、`encoding=utf8|utf16le`）、`scan_next`（`retain_stale`）、`scan_aob`（MCP 专属：分页、区域过滤、`stop_on_limit`、并行）、`scan_candidates`（只读，分页浏览已持久化候选集）。`scan` / `scan_aob` 返回 `region_summary`、`candidates_total`、`candidates_file` / `results_file`、`page` |
| 监视 | `watch_run`、`watch_report`（只读）；`watch_start`、`watch_stop`（可写 profile） |
| 写入定位 | `find_writers`（硬件写断点，会短暂挂起目标线程，需管理员；仅可写 profile） |
| 读写 | `read`、`modify`、`resolve`、`value_convert` |
| 语义 | `nl`、`name_set`（新增 `temp: true` 标记临时符号）、`name_get`、`name_chain`（遍历指针链并注册 `<名>.stepN` 中间符号，默认 `temp: true`）、`name_clear_temp`（清除全部临时符号） |
| 模板 | `template_list`、`template_show`、`template_apply` |
| 批处理 | `batch_run`（`file` 或内联 `yaml` 二选一；`offset` / `limit` 分页内联结果；完整结果始终落盘到 `results_file`）、`batch_preview`（只读预检：逐项 risk 分级 + `estimated_write_bytes`，全 profile 可用） |
| 宏 | `macro_list`、`macro_show`（只读）；`macro_define`、`macro_run`（`params` 为字典，`${param}` 代入后走批处理管道）、`macro_delete`（可写 profile） |
| 冻结 | `freeze_list`、`freeze_start`、`freeze_stop` |
| 备份 | 内存备份：`backup_create`、`backup_list`、`backup_restore`；外部文件备份（safety 组）：`file_snapshot`（sha256 + manifest + 审计，存 `sessions/<id>/file_backups/`）、`file_restore`（`confirm=true` 且游戏进程运行中时拒绝） |
| 存档 | `save_edit_detect`、`save_edit_modify` |
| 审计 | `audit_tail` |
| 产物回读 | `results_read`（只读，全 profile 含 readonly；按 `offset` / `limit` 分页回读 `sessions/<id>/` 内的落盘产物——溢出的大 dump、batch 完整结果、扫描 sidecar；越出会话目录报 `E_PATH_NOT_ALLOWED`） |
| 安全档位 | `safety_get_level`（只读，所有 profile 都注册）、`safety_set_level`（切换运行时安全档位 `normal` / `dry_run_only`，仅 default profile） |

参数与 CLI 一一对应，差异点：

- 会话参数统一叫 `session`（`attach` 除外，它接受 `pid` / `process` / `exe` / `allow_anti_cheat`）。
- `--confirm` 对应 `confirm: true`（布尔值，默认 `false`，同样默认 dry-run）。
- `resolve` 只接受 `base` + `offsets`（无 `pointer` 合并写法）。
- `template_apply` 的 `params` 是一个字典，而不是重复的 `--param`。
- `name_set` 新增 `temp: true` 参数标记临时符号；`name_chain` 的中间符号默认临时（`temp: false` 持久化，对应 CLI `--persist`），用 `name_clear_temp` 清理。
- `batch_run` 用 `stop_on_error`（默认 `true`），而 CLI 是反向的 `--continue-on-error`；另接受 `offset` / `limit` 分页内联结果窗口（CLI `--offset` / `--limit`）与 `confirm_code: true`（对应 CLI `--confirm-code`，放行高风险写入）。
- `pointer_scan` 接受 `async_run: true`（可选 `timeout` 秒）提交后台任务，返回 `job_id`；用 `job_status`（`job_id` + 可选 `session`）/ `job_list` 轮询，`job_cancel` 取消（CLI `--async` / `job status|list|cancel`）。
- 返回值与 CLI 使用**同一套 JSON 信封**（`ok` / `command` / `data` / `error`）。

> MCP 模式没有暴露 `freeze run`（前台阻塞）和 `freeze clear`，需要时请用 CLI。

**多级工具 profile（`--profile`）**：启动时可用 `--profile {default,readonly,dry-run,symbols,limited}` 选择五档之一：

| Profile | 工具数 | 允许的操作 |
| --- | --- | --- |
| `default` | 全部 | 全部工具（现有行为），含 `safety_set_level` |
| `readonly` | 只读子集 | 只读工具（不含 modify / nl / name_set / name_chain / name_clear_temp / template_apply / batch_run / freeze_start / freeze_stop / watch_start / watch_stop / find_writers / backup_create / backup_restore / file_snapshot / file_restore / save_edit_modify / il2cpp_dump / il_patch / il_backup / il_restore / mono_dump / detach / job_cancel / macro_define / macro_run / macro_delete / session_snapshot / session_restore / session_notes set/delete / safety_set_level），适合只允许读取不允许写入的部署 |
| `dry-run` | 只读+写工具 | 只读 + 写工具强制 dry-run：modify / nl / batch_run / macro_run / template_apply / save_edit_modify / watch_start / watch_stop / session_snapshot / session_restore 等照常注册，但 `confirm=true` 被服务端拒绝（`E_PROFILE_RESTRICTED`），`confirm=false` 预览透传 |
| `symbols` | 只读+符号 | 只读 + 符号管理（name_set / name_chain / name_clear_temp）+ 会话快照（session_snapshot / session_restore）+ 宏定义（macro_define / macro_delete），不写游戏内存 |
| `limited` | 只读+单步写 | symbols 基础上 + 单步写 `modify` / `nl`（仍受 `max_write_bytes` 与写风险分级约束）；batch / freeze / template 批量写不注册 |

各档位的精确工具数以 `tools_catalog` 运行时返回为准。

UE 内省三工具（`ue_introspect` / `ue_actors` / `ue_fname`）、Unity il2cpp 解码四工具（`il2cpp_string` / `il2cpp_list` / `il2cpp_dict` / `il2cpp_lookup`）、任务查询二工具（`job_status` / `job_list`）、宏查看二工具（`macro_list` / `macro_show`）、快照列表（`session_snapshots`）以及 `disasm`、`xrefs`、`dissect`、`watch_run`、`watch_report`、`safety_get_level` 本身只读，所有 profile 都包含。运行时安全档位与 profile 正交：`safety_get_level` 任何档位可查；`safety_set_level` / CLI `safety level --set` 仅 default profile 注册（见 7.7）。

**输出限流**：返回 JSON 超过约 50000 字符时会被截断成预览（列表只保留前 N 项，`data.totals` 给出原始条数，并附 `preview_note`），避免巨型扫描结果撞爆上下文窗口；`name_get` / `backup_list` / `sessions` 的列表字段超过 1000 条时也会截断。**`batch_run` 例外**：超限不做二分截断，而是返回摘要 + 前 10 条 + `results_file` 提示（完整结果始终落盘 `sessions/<id>/batch_results/<时间戳>.json`），需要全量数据时读该文件或用 `offset` / `limit` 分页重调。

### 5.5 `--groups` 按需加载工具组（省 token）

每个 MCP 工具的描述 + 参数 schema 都会在每次调用时占用上下文 token。默认启动注册全部工具组（向后兼容）；如果只用得到部分能力，可用 `--groups` 只注册需要的工具组：

```powershell
game-modifier-mcp --groups core,scan,modify          # 只注册这三组 + tools_catalog
```

11 个工具组（每组精确工具数以 `tools_catalog` 运行时返回为准，`tools_catalog` 在任何配置下都始终注册）：

| 组 | 包含工具 |
| --- | --- |
| `core` | `attach`、`analyze`、`sessions`、`session_info`、`session_survey`、`session_snapshot`、`session_snapshots`、`session_restore`、`session_notes`、`detach`、`value_convert`、`toolchain_detect`、`audit_tail`、`results_read` |
| `scan` | `scan`、`scan_next`、`scan_aob`、`scan_candidates`、`read`、`resolve`、`pointer_scan` |
| `modify` | `modify`、`nl`、`name_set`、`name_get`、`name_chain`、`name_clear_temp`、`freeze_list`、`freeze_start`、`freeze_stop`、`backup_create`、`backup_list`、`backup_restore`、`batch_run`、`batch_preview`、`template_list`、`template_show`、`template_apply`、`save_edit_detect`、`save_edit_modify` |
| `analysis` | `layout_analyze`、`heap_scan`、`disasm`、`xrefs`、`dissect`、`watch_run`、`watch_start`、`watch_stop`、`watch_report`、`find_writers` |
| `ue` | `ue_introspect`、`ue_actors`、`ue_fname` |
| `il2cpp` | `il2cpp_string`、`il2cpp_list`、`il2cpp_dict`、`il2cpp_lookup`、`il2cpp_dump` |
| `il` | `il_analyze`、`il_dump`、`il_callers`、`il_patch`、`il_verify`、`il_backup`、`il_restore`（il-tool 子进程，需 .NET 8 运行时） |
| `mono` | `mono_dump`、`mono_symbol`、`mono_string`、`mono_list`、`mono_dict`、`mono_static`、`mono_heap_scan` |
| `jobs` | `job_status`、`job_list`、`job_cancel` |
| `macros` | `macro_list`、`macro_show`、`macro_define`、`macro_run`、`macro_delete` |
| `safety` | `safety_get_level`（只读）、`safety_set_level`（切换运行时安全档位）、`file_snapshot`、`file_restore`（外部文件备份/还原） |

使用建议：

- **按游戏类型只加载需要的分组**：Unreal 游戏可用 `--groups core,scan,modify,ue,jobs`；Unity il2cpp 用 `--groups core,scan,modify,il2cpp,jobs`；存档型游戏（RPG Maker / Ren'Py）只需 `--groups core,modify`。
- `--groups` 与 `--profile readonly` 可叠加：readonly 在分组过滤之上再排除可写工具。
- 组名写错会报 `ValueError` 并列出全部合法组名；运行时也可调用 `tools_catalog` 工具查看分组清单与工具总数。

---

## 6. 常见使用场景

### 场景 1：RPG — 无限生命 + 巨额金币

```powershell
$S = (game-modifier attach --process rpg.exe | ConvertFrom-Json).data.session_id

# 找金币（当前 1200）
game-modifier scan --session $S --type int32 --value 1200
# 游戏里买点东西变成 900
game-modifier scan-next --session $S --value 900
game-modifier name set player.gold --session $S --base 0x<最终地址> --type int32

# 找生命（当前 85）
game-modifier scan --session $S --type int32 --value 85
game-modifier scan-next --session $S --comparator decreased
game-modifier name set player.health --session $S --base 0x<最终地址> --type int32

# 套用模板：一条命令锁定生命
game-modifier template apply --session $S --template rpg --option infinite_health --confirm
game-modifier freeze start --session $S

# 金币直接用中文改
game-modifier nl --session $S "将金币设为999999" --confirm
```

### 场景 2：射击游戏 — 无限弹药

```powershell
# 弹夹里 30 发，打掉几发再筛
game-modifier scan --session $S --type int32 --value 30
game-modifier scan-next --session $S --value 27
game-modifier name set weapon.ammo --session $S --base 0x<地址> --type int32

game-modifier template apply --session $S --template action --option infinite_ammo --confirm
game-modifier freeze start --session $S
```

或者一句话：

```powershell
game-modifier nl --session $S "无限弹药" --confirm
game-modifier freeze start --session $S
```

### 场景 3：修改浮点型移动速度

浮点数很难精确命中，用区间 + 变化组合：

```powershell
game-modifier scan --session $S --type float --comparator between --value 4.0 --value2 6.0
# 在游戏里切换成走路（速度下降）
game-modifier scan-next --session $S --comparator decreased
# 再切回跑步
game-modifier scan-next --session $S --comparator increased

game-modifier name set player.move_speed --session $S --base 0x<地址> --type float
game-modifier modify --session $S --symbol player.move_speed --value 12.0 --confirm
```

### 场景 4：一次性套用整套修改（批处理）

新建 `my_ops.yaml`：

```yaml
confirm: true
stop_on_error: false
operations:
  - nl: "将金币设为999999"
  - nl: "生命值拉满"
  - modify:
      symbol: player.move_speed
      type: float
      value: 10.0
  - template:
      template: rpg
      option: max_attributes
  - read:
      symbol: player.gold
  - read:
      symbol: player.health
```

```powershell
game-modifier batch run --session $S my_ops.yaml --confirm --continue-on-error
```

### 场景 5：改坏了，一键回滚

```powershell
game-modifier backup list --session $S
game-modifier backup restore --session $S bk-20260730-101112
# 同时把冻结停掉，否则会被持续回写
game-modifier freeze stop --session $S
game-modifier freeze clear --session $S
```

### 场景 6：Unity Il2Cpp 游戏 — dumper 转储 → RVA 反查 → 运行时类型解码

```powershell
$S = (game-modifier attach --process unitygame.exe | ConvertFrom-Json).data.session_id
game-modifier analyze --session $S --deep --format json-pretty

# 1) 一键跑 Il2CppDumper（按 metadata 版本自动选 dumper），script.json / dump.cs 自动关联会话；
#    同时记录游戏二进制指纹，已有新鲜转储时会直接复用（--force 强制重转储）
game-modifier il2cpp dump --session $S

# 游戏更新后：analyze 会提示 dump_stale（或 lookup 返回 stale_warning）——
# 旧 RVA 可能失效，重跑转储再查询：
game-modifier analyze --session $S
game-modifier il2cpp dump --session $S --force

# 2) RVA 反查：例如把 find-writers 抓到的 RIP 换成函数名（RVA = RIP - GameAssembly.dll 基址）
game-modifier il2cpp lookup --session $S --rva "0x7ff6a12b8560-0x7ff69c432ef0" --tolerance 0x100

# 3) 运行时类型解码：字符串 / List / Dictionary 一步到位，无需手工拼 UTF-16
game-modifier il2cpp string --session $S --address 0x2a1b3c40
game-modifier il2cpp list --session $S --address 0x2a1b3c80 --elem-type ptr
game-modifier il2cpp dict --session $S --address 0x2a1b3cc0

# 4) 按 dump.cs 里的字段偏移直接建立符号，跳过盲扫
game-modifier name set player.gold --session $S --base "GameAssembly.dll+0x2A1B08" --offsets "0x18,0x40" --type int32
game-modifier read --session $S --symbol player.gold
```

> 完整命令参数见 4.25；`il2cpp dump` 需要安装 Il2CppDumper / il2cpp-dumper-rs（`toolchain detect` 可查，未装报 `E_TOOL_NOT_FOUND`）。

### 场景 7：Unreal 游戏 — dumper 出偏移 → 验证布局 → 枚举 Actor → 固化符号

UE 游戏的对象都由 GObjects（UObject 数组）统一管理，用 UE dumper（UE4 Dumper / UE4SS 等）拿到 GObjects / GNames 偏移后，可以跳过盲扫：

```powershell
$S = (game-modifier attach --process ue_game.exe | ConvertFrom-Json).data.session_id

# 1) dumper 给出偏移，用 ue introspect 验证布局（confirmed 后缓存进会话）
game-modifier ue introspect --session $S --gobjects "ue_game.exe+0x1D2E500" --gnames "ue_game.exe+0x1C9A380"

# 2) 枚举 Actor，找到目标实例（默认聚合视图，按需加 --class / --list）
game-modifier ue actors --session $S --limit 200
game-modifier ue actors --session $S --class PlayerController --list

# 3) 从 Actor 实例出发按类布局（layout --what class）找到字段地址，用 ue fname 校验字段名
game-modifier ue fname --session $S --address 0x<fname字段地址>

# 4) name set 固化符号，之后用常规 modify / freeze / nl
game-modifier name set player.actor --session $S --base "ue_game.exe+0x1D2E500" --type int64
game-modifier modify --session $S --address 0x<字段地址> --type float --value 9999 --confirm
```

> 若 `ue actors` / `ue fname` 报 `E_LAYOUT_UNSUPPORTED`，说明会话里还没有确认过的布局：先跑 `ue introspect`（或给 `ue actors` 显式传 `--gobjects`）。

### 场景 8：定位写入代码 — watch 定时间 → find-writers 定指令 → disasm 看代码

想知道「到底哪条指令在改我的生命值」，三步走：

```powershell
# 1) watch 轮询确认地址确实会被写入、记录变化时间点（何时变）
game-modifier watch run --session $S --address 0x1f2a3b40 --type int32 --iterations 200
# （在游戏里触发受伤 / 回血，确认 change_count > 0）

# 2) find-writers 下硬件写断点，实时抓写入指令的 RIP（哪条指令在写；需管理员终端）
game-modifier find-writers --session $S --address 0x1f2a3b40 --size 4 --duration 8
# → data.hits[].rip 就是写入指令地址

# 3) disasm 反汇编 RIP 处代码，确认指令结构，再决定改数值、改分支还是 NOP
game-modifier disasm --session $S --address 0x<hits中的rip> --blocks
```

要点：

- `watch` 只能回答“何时变”，`find-writers` 才能回答“哪条指令写”；没有管理员权限时（`E_ACCESS_DENIED`）可退而用 `xrefs --direction to` 做静态分析。
- `find-writers` 采样期间游戏会短暂卡顿（挂起线程读上下文），采样时长建议 3~10 秒并在采样窗口内主动触发写入行为。
- 会话检测到反作弊时 `find-writers` 会直接拒绝（`E_ANTI_CHEAT`），此时请停手。

### 场景 9：解剖未知对象结构（dissect）

通过 `layout --what heap` 或 `ue actors` 找到若干同类实例后，用 `dissect` 推断字段布局：

```powershell
# 多个实例一起解剖，字段 confidence 更高
game-modifier dissect --session $S --addresses 0x1f2a3b40,0x1f2a3c80,0x1f2a3dc0 --size 256
# 对高 confidence 的字段用 read / watch 验证语义，再 name set 固化
game-modifier read --session $S --address 0x1f2a3b40 --offsets "0x64" --type int32
game-modifier name set player.health --session $S --base 0x1f2a3b40 --offsets "0x64" --type int32
```

---

### 场景 10：长时间扫描工作流（async 提交 → 轮询 → 取结果）

深度指针反查（`--max-depth ≥ 3`）或大内存进程常超过同步 30s 预算，改用后台任务：

```powershell
# 1) 提交：立即返回 job_id，不阻塞、无硬超时
game-modifier pointer-scan --session $S --address 0x1f2a3b40 --async --max-depth 4

# 2) 轮询：progress 里看 depth / paths_found 判断进展
game-modifier job status <job_id>
#   太慢又不想等了：job cancel <job_id>（部分结果仍落盘）

# 3) 取结果：done 后从 results_file / paths_sample 拿指针链
game-modifier job status <job_id>          # data.results_file = sessions/<id>/jobs/<job_id>.json
# 之后照常 resolve / name set 固化最优路径
```

同理，大批量 `batch run` 的结果始终落盘：返回里拿 `results_file` 读完整数据，或用 `--offset` / `--limit` 分页看内联窗口，不依赖被限流的输出。

---

## 7. 安全机制

### 7.1 dry-run（默认开启）

所有写入操作**默认只模拟**。`modify` / `nl` / `template apply` / `batch run` 必须显式传 `--confirm`（MCP：`confirm=true`）才会真正写内存。dry-run 返回 `dry_run: true`、`applied: false`，并给出将要写入的 `bytes` 与 `old_value` / `new_value`，便于先核对再执行。

**结果判定看 `status` 字段**：dry-run 额外返回 `status: "dry_run_preview"` 与双语 `hint`（“这是预览，未实际写入。确认后重跑加 --confirm 执行写入。(Re-run with confirm=true / CLI --confirm to apply.)”）；确认写入成功返回 `status: "applied"`。两者都携带目标区域的 `risk` 字段（见 7.8）。`dry_run_preview` 一定未写入，`applied` 一定已写入——程序化判断时不要只看 `ok`。

即使把配置里的 `safety.dry_run` 设为 `false`，**确认标志依然是必需的**——这是硬编码的安全约束。

### 7.2 自动备份与恢复

`safety.auto_backup = true`（默认）时，每次真实写入前都会快照原始字节，返回的 `backup_id` 可用于回滚：

```powershell
game-modifier backup list --session $S
game-modifier backup restore --session $S <backup_id>
```

备份文件位于 `~/.game-modifier/sessions/<session_id>/backups/`。

### 7.3 反作弊检测

`attach` 时会扫描目标进程的已加载模块名**以及系统中其他运行进程名**，命中以下任一系统（共 16 种）即返回 `E_ANTI_CHEAT` 并拒绝附加：

| 反作弊系统 | 匹配特征（不区分大小写的子串） |
| --- | --- |
| EasyAntiCheat | easyanticheat、eac_launcher、easyanticheat_eos |
| BattlEye | beservice、beclient、bedaisy、battleye |
| Riot Vanguard | vgc、vgk、vanguard |
| nProtect GameGuard | gameguard、gamemon、npggnt、npgg |
| XIGNCODE3 | xigncode、x3.xem、xhunter |
| Denuvo Anti-Cheat | denuvoanti、denuvo-anti |
| PunkBuster | pnkbstr、punkbuster |
| mhyprot (miHoYo) | mhyprot |
| FACEIT | faceit |
| FairFight | fairfight |
| Ricochet (COD) | ricochet |
| TenSafe/ACE (Tencent) | tensafe、acebase、acepro、tss、tenprotect |
| NEACProtect (NetEase) | neacprotect、neac |
| HackShield | hackshield、hsupdate |
| Anti-Cheat Expert | anti-cheat-expert、anti_cheat_expert |
| VAC | vacmodule |

错误的 `details` 会给出 `systems` 与逐条 `hits`（含匹配位置 `module` / `process`）。

**遇到 `E_ANTI_CHEAT` 请停手。** 虽然存在 `--allow-anti-cheat` 与 `safety.block_anti_cheat = false` 两个绕过口子，但用于联机游戏会导致封号，且本工具明确不支持该用途。常见误报情形是后台开着另一款带反作弊的游戏——先把它关掉再重试。

### 7.4 地址与数值校验

每次读写前都会：

1. 拒绝 `<= 0` 的地址（`E_INVALID_ADDRESS`）；
2. 用 `VirtualQueryEx` 确认地址落在**已提交的映射区域**内，且 `[address, address+size)` 不跨越区域边界；
3. 确认区域可读；
4. `safety.require_writable_region = true` 时要求可写，否则返回 `E_ADDRESS_NOT_WRITABLE`（写入路径会尝试用 `VirtualProtectEx` 临时改权限，并附带 warning）；
5. 按类型校验数值范围，越界返回 `E_VALUE_OUT_OF_RANGE`（`details` 含该类型的 `min` / `max`）；
6. 写入后回读校验，结果放在 `verified_value`。

此外：

7. 单次写入长度受 `safety.max_write_bytes`（默认 4096 字节）限制，超限直接拒绝，避免误写一大段内存。
8. 每次确认写入都会追加一条记录到会话审计日志 `sessions/<id>/audit.jsonl`（含操作、目标、backup_id、时间戳），可用 MCP 的 `audit_tail` 工具回看。

### 7.5 使用建议

- 修改前手动备份游戏存档。
- 先小幅修改验证地址是否正确，再改成目标值。
- 冻结用后即停（`freeze stop`），避免后台进程持续写入已经失效的地址。
- 关掉所有联机游戏再使用本工具。

### 7.6 MCP 多级工具 profile

`--profile` 五档的完整工具对照见 5.4，这里从权限视角看每档允许的操作：

| 操作 | default | limited | symbols | dry-run | readonly |
| --- | :-: | :-: | :-: | :-: | :-: |
| 读取 / 扫描 / 分析 / 引擎内省 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 符号管理（name_set / name_chain / name_clear_temp） | ✅ | ✅ | ✅ | ✅ | ❌ |
| 会话快照（session_snapshot / session_restore） | ✅ | ✅ | ✅ | ✅ | ❌ |
| 宏定义（macro_define / macro_delete） | ✅ | ✅ | ✅ | ✅ | ❌ |
| 单步写（modify / nl，需 confirm） | ✅ | ✅ | ❌ | 仅预览 | ❌ |
| 批量写（batch_run / macro_run / template_apply / save_edit_modify） | ✅ | ❌ | ❌ | 仅预览 | ❌ |
| 冻结 / watch 后台 / find_writers / 备份写 / il2cpp_dump / detach / job_cancel | ✅ | ❌ | ❌ | ❌ | ❌ |
| 运行时安全档位切换（safety_set_level） | ✅ | ❌ | ❌ | ❌ | ❌ |

> `dry-run` 档的写工具照常注册，但 `confirm=true` 被服务端拒绝（`E_PROFILE_RESTRICTED`），适合“AI 可预览、不可写入”的部署；`symbols` 适合只整理符号表的场景；`limited` 允许单步写但不注册 batch / freeze / template 批量写入口。

### 7.7 运行时安全档位（safety level）

除启动时的静态 profile 外，还有一个正交的**运行时安全档位**（进程级生效，**不落盘**，进程重启后恢复 `normal`）：

| 档位 | 行为 |
| --- | --- |
| `normal`（默认） | 标准 confirm 门：默认 dry-run，`--confirm` 放行 |
| `dry_run_only` | `modify` / `nl` / `batch run` / `macro run` 的 confirm 写入在入口处被拒绝（`E_PROFILE_RESTRICTED`）；`confirm=false` 预览不受影响 |

```powershell
# 查看当前档位
game-modifier safety level
# → {"ok": true, "data": {"level": "normal", "source": "default"}}

# 切到“只允许预览”档位
game-modifier safety level --set dry_run_only
# 恢复
game-modifier safety level --set normal
```

MCP 对应工具：`safety_get_level`（只读，所有 profile 都注册）/ `safety_set_level`（仅 default profile）。把会话交给低信任 agent 操作前，可先切 `dry_run_only`，结束后恢复。

### 7.8 批量写风险分级

`batch run`（及走批处理管道的 `macro run`）在执行前会对每个写步骤的目标区域做风险分类（`_classify_write_risk`）：

- 可写数据段 → `risk: "normal"`；
- 可执行段（代码段）→ `risk: "high"`（代码 patch，危险）；
- 只读 / 无法确定的区域 → `risk: "high"`（保守判定，可能触发保护或崩溃）。

行为规则（单步 `modify` 只报告 `risk` 不拦截，拦截只发生在批量入口）：

- **dry-run 预览**：汇总里带 `risk_breakdown`（如 `{"high": 2, "normal": 5}`），存在高风险项时附 `hint`；
- **确认执行**：默认只放行 `risk=normal` 项；高风险项被跳过并标记 `skipped_reason: "high_risk_requires_confirm_code"`，汇总里附 `skipped_high_risk` 计数；
- 有意的代码 patch 场景，确认预览结果无误后加 `--confirm-code`（MCP / YAML：`confirm_code: true`）重跑放行高风险项。

---

## 8. 配置文件

### 8.1 加载层级

后者覆盖前者：

1. 包内默认 `game_modifier/data/default.toml`
2. `~/.game-modifier/config.toml`（存在则加载）
3. 环境变量 `$GAME_MODIFIER_CONFIG` 指向的文件（存在则加载）
4. 命令行 `--config <path>`（文件不存在会直接报错）

合并是**深度合并**，只需写要覆盖的键。仓库里的 `config/default.toml` 是一份带注释的参考副本，可直接复制：

```powershell
mkdir "$env:USERPROFILE\.game-modifier" -Force
Copy-Item "config\default.toml" "$env:USERPROFILE\.game-modifier\config.toml"
```

### 8.2 常用配置项

```toml
[safety]
dry_run = true                  # 未加 --confirm 时模拟写入
block_anti_cheat = true         # 检测到反作弊则拒绝附加（建议保持 true）
auto_backup = true              # 写前快照原始字节
require_writable_region = true  # 拒绝写入非可写区域
max_write_bytes = 4096          # 单次写入字节上限，超限拒绝

[scan]
max_results = 20000             # 首次扫描保留的候选上限
chunk_size = 4194304            # 每次读取的块大小（字节）
max_region_bytes = 0            # 跳过超过该大小的区域，0 = 不限制
alignment = 1                   # 扫描对齐，4 = 只看 4 字节对齐地址（更快）
candidates_sidecar_threshold = 5000  # 候选数超过该值时落盘到二进制 sidecar
workers = 4                     # 首次扫描并行工作线程数（需 numpy，否则自动退化为单线程）

[analysis]
pointer_scan_max_depth = 2      # pointer-scan 解引用跳数上限
pointer_scan_max_paths = 500    # pointer-scan 报告路径上限
scan_timeout = 30               # 单次扫描时间预算（秒）

[freeze]
adaptive = true                 # 自适应调节冻结回写间隔
min_interval = 0.05             # 自适应下限（秒）
max_interval = 1.0              # 自适应上限（秒）

[output]
format = "json"                 # json | json-pretty | human

[paths]
home = ""                       # 留空则为 ~/.game-modifier
sessions_dir = ""
user_templates_dir = ""

[tools]
radare2 = ""                    # 留空自动探测；不在 PATH 时写完整路径
rizin = ""
x64dbg = ""
x32dbg = ""
cdb = ""
windbg = ""
binaryninja = ""
il2cppdumper = ""
il2cppinspector = ""
ue4dumper = ""
ue4ss = ""

[tools.search_dirs]
extra = []                      # 自动探测时额外搜索的目录

[ue]
item_stride = 24                # FUObjectItem 步长（字节），探测确认前使用的假定值
objects_per_chunk = 65536       # 每个 TUObjectArray 分块的条目数
max_chunks = 512                # 最多遍历的 GObjects 分块数
probe_items = 64                # 验证步长时采样的条目数
max_objects = 100000            # ue actors 枚举时检查的对象总量上限
batch_gap = 256                 # 分组合并读取时相邻地址间允许的最大空隙（字节）
```

### 8.3 调优提示

- 扫描太慢：把 `scan.alignment` 设为 `4`（多数 int32/float 字段都是 4 字节对齐），并适当调小 `scan.max_region_bytes`。
- 候选太多被截断（`truncated: true`）：提高 `scan.max_results`，或改用更精确的初始值。
- 人工使用：把 `output.format` 设成 `json-pretty` 或 `human`。

### 8.4 目录布局

```
~/.game-modifier/
├── config.toml              # 用户配置
├── sessions/                # 会话与扫描状态、符号表、冻结项
│   └── <session_id>/
│       ├── backups/         # 原始字节备份
│       ├── batch_results/   # batch run 完整结果（<时间戳>.json，始终落盘）
│       └── jobs/            # 后台任务结果（<job_id>.json，--async 扫描）
└── templates/               # 用户自定义模板（YAML）
```

---

## 9. 错误代码参考

所有失败都返回 `{"ok": false, "command": "...", "error": {"code": "E_...", "message": "...", "hint": "...", "details": {...}}}`，可以直接按 `code` 分支处理。

### 9.0 关键错误码的可执行 hint 示例

所有关键错误码现在都在 `hint` 字段里带**可执行的下一步指令**。遇到错误时优先按 `hint` 行动；具体上下文（如具体地址、符号名）给出的 `hint` 会优先于下表默认值。

| 代码 | `hint` 示例（默认值） |
| --- | --- |
| `E_INVALID_ADDRESS` | 支持格式: 十六进制 `0x7ff...`、十进制、符号名（`name set` 定义）、`模块名+0x偏移`、算术表达式 `0x100-0x8`。用 `session info` 查看已定义符号与模块列表。 |
| `E_SCAN_TIMEOUT` | 缩小扫描范围后重试: 用 `scan-next` 渐进过滤；降低 `max_results`；指针定位改用 `pointer-scan --async` 后台执行（无30s硬超时）并用 `job status` 轮询。 |
| `E_PROCESS_EXITED` | 目标进程已退出。重新 `attach` 后重跑定位链；若使用符号表，模块基址变化会自动适应。 |
| `E_NEEDS_SCAN` | 先执行首扫: `scan --session <id> --type int32 --value <当前值>`，改变数值后用 `scan-next` 缩小候选。 |
| `E_SYMBOL_NOT_FOUND` | 用 `name set <name> --session <id> --base <addr或模块+偏移> --type int32` 创建；`name get` 查看现有符号。 |
| `E_LAYOUT_UNSUPPORTED` | UE: 先运行 `ue introspect --gobjects <偏移>` 探测；il2cpp: 先运行 `il2cpp dump` 生成 script.json。 |
| `E_ANTI_CHEAT` | 检测到反作弊。仅限单机/离线游戏，立即停止操作，不要尝试绕过；改用存档编辑（`save-edit`）。 |
| `E_TOOL_NOT_FOUND` | 运行 `toolchain detect` 查看缺失项，安装对应工具，或在 config `[tools]` 段显式配置路径。 |
| `E_DEPENDENCY_MISSING` | 按需安装分组: `pip install game-modifier[all]`（全部）或 `game-modifier[disasm]`（仅 capstone）。 |
| `E_PATTERN_NOT_FOUND` | AOB 无命中。检查模式字节（用 `disasm` 确认）、通配符 `??` 使用；游戏版本更新会导致特征码失效。 |
| `E_SAVE_FORMAT_UNSUPPORTED` | 存档格式暂不支持（压缩 / Ren'Py pickle），或 Unity 加密存档密钥错误/文件损坏。当前支持 RPG Maker (`rmmzsave`) 明文存档与 Unity `Base64(DES-CBC(JSON))`（需 `--key`）；密钥错误时核对密钥后重试，其余不要对同一存档重试。 |
| `E_PROFILE_RESTRICTED` | 当前安全档位禁止确认写入。改用 confirm=false（status=preview 预览），或通过 safety_set_level(level='normal') / --profile default 恢复写权限。 |

> `hint` 是既有字段，本次只是**填充内容**——错误码值、信封结构均未变化。


### 进程 / 会话

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_PROCESS_NOT_FOUND` | 找不到指定 PID / 进程名 / exe | 确认游戏在运行；进程名要带 `.exe` |
| `E_ACCESS_DENIED` | 打开进程被拒 | 用**管理员终端**重试 |
| `E_SESSION_NOT_FOUND` | 会话 ID 不存在 | `game-modifier sessions` 查看现有会话 |
| `E_PROCESS_EXITED` | 进程已退出（PID 失效） | 重新 `attach`，符号需重建 |

### 安全 / 守卫

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_ANTI_CHEAT` | 检测到反作弊系统 | **停止操作**；关闭后台的联机游戏再试 |
| `E_NOT_CONFIRMED` | 需要确认才能写入 | 加 `--confirm` |
| `E_DRY_RUN` | 提示性质，非硬失败 | 加 `--confirm` 真正执行 |
| `E_PROFILE_RESTRICTED` | 当前 profile / 运行时安全档位禁止确认写入（dry-run profile 服务端拒绝，或运行时档位为 `dry_run_only`） | **不要重试**；改用 `confirm=false` 预览，或换更高 profile（`--profile default` / `limited`）/ `safety level --set normal` 恢复写权限（见 7.6 / 7.7） |

### 内存

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_INVALID_ADDRESS` | 地址非法 / 未映射 / 跨区域 | 重新扫描；指针链可能已失效 |
| `E_ADDRESS_NOT_WRITABLE` | 目标区域不可写 | 确认地址正确；或把 `require_writable_region` 设为 false 让写入走 `VirtualProtectEx` |
| `E_READ_FAILED` | 读取失败 | 地址已失效，重新解析 / 扫描 |
| `E_WRITE_FAILED` | 写入失败 | 检查权限与地址有效性 |
| `E_INVALID_TYPE` | 类型名未知或值无法解析成该类型 | 参见 4.0 的类型表，`details.supported` 列出全部合法值 |
| `E_VALUE_OUT_OF_RANGE` | 数值超出类型范围 | 换更大的类型（如 int32 → int64）或改小数值 |
| `E_INVALID_POINTER` | 指针链解析失败 | 用 `resolve` 看 `trace`，定位断在哪一级 |

### 解析

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_NEEDS_SCAN` | 字段还没有对应地址 / 无前置扫描 | 按 `details.next` 先 `scan`，再 `name set` |
| `E_SYMBOL_NOT_FOUND` | 符号表里没有该名字 | `name get` 查看已有符号，或先 `name set` |
| `E_NLP_UNRESOLVED` | 无法从短语推导出动作 | 参考 `details.hint_supported_fields`，改用「将金币设为9999」这类句式 |

### 工具 / 引擎

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_TOOL_NOT_FOUND` | 依赖的外部逆向工具不存在（如 `xrefs` 缺 radare2 / r2pipe） | `toolchain detect` 查看；在 `[tools]` 里写明路径；`xrefs` 场景按 `hint` 安装 radare2 与 r2pipe |
| `E_TOOL_FAILED` | 外部工具执行失败 | 检查该工具能否单独运行 |
| `E_ENGINE_UNKNOWN` | 未识别出游戏引擎 | 走通用 `scan` 路线即可 |

### 模板 / 批处理 / 备份

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_TEMPLATE_NOT_FOUND` | 模板或选项不存在 | `template list` / `template show <name>` |
| `E_TEMPLATE_INVALID` | 模板 YAML 格式错误 | 检查 `options` / `targets` 结构 |
| `E_BATCH_ERROR` | 批处理文件缺失或格式非法 | 必须有非空 `operations`，每项只含一个动作键 |
| `E_BACKUP_NOT_FOUND` | 备份 ID 不存在 | `backup list` 查看可用 ID |

### 扫描 / 分析

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_PATTERN_NOT_FOUND` | AOB 字节模式未命中任何地址 | 检查 / 放宽模式（多加 `??` 通配），或确认目标模块已加载 |
| `E_LAYOUT_UNSUPPORTED` | 当前场景不支持该布局分析 | 回落到通用 `scan`；或换一种 `--what`。若来自 `ue actors` / `ue fname`：会话还没有确认过的 UE 布局，先跑 `ue introspect`（或给 `ue actors` 显式传 `--gobjects`） |
| `E_SCAN_TIMEOUT` | 扫描超出时间预算 | 缩小范围、降低 `--max-depth`；或调高 `[analysis] scan_timeout`；长时间指针反查改用 `pointer-scan --async` 后台任务（无硬超时，部分结果落盘） |
| `E_SCAN_CACHE_STALE` | 区域布局变化导致扫描缓存失效 | 重新执行一次全新 `scan`，不要继续 `scan-next` |

### 通用

| 代码 | 含义 | 处理方式 |
| --- | --- | --- |
| `E_UNSUPPORTED_OS` | 非 Windows 平台 | 本版本仅支持 Windows |
| `E_INVALID_ARGS` | 参数缺失 / 冲突 / 配置错误 | 看 `message`；如同名多进程需改用 `--pid` |
| `E_DEPENDENCY_MISSING` | 缺少 Python 可选依赖（如 `disasm` 缺 capstone） | 按 `hint` 安装对应分组，如 `pip install -e ".[disasm]"`，或 `pip install -e ".[all]"` |
| `E_INTERNAL` | 未预期的内部错误 | 请附带完整 JSON 反馈 |

---

## 10. FAQ

**Q：为什么 `modify` 显示成功但游戏里没变化？**
A：先确认加了 `--confirm`——否则只是 dry-run（返回里 `dry_run: true`）。若已确认写入且 `verified_value` 正确，说明写对了地址但游戏用的是**另一个地址**（常见于显示值 vs 真实值分离，或数值被每帧重算）。解决办法：重新扫描筛掉「只是显示副本」的候选，或用 `--freeze` 持续回写。

**Q：扫描出几千个候选，怎么缩小？**
A：这是正常的。回到游戏里让数值发生变化，然后反复 `scan-next`。不知道确切新值时用 `changed` / `increased` / `decreased`。通常 2~4 轮能降到个位数。

**Q：`attach` 报 `E_ACCESS_DENIED` 怎么办？**
A：以管理员身份重开终端。`attach` 返回的 `is_admin` 可用来确认当前权限。

**Q：游戏重启后符号还能用吗？**
A：不能直接用。PID 变了需重新 `attach`；基于**裸地址**的符号会失效（ASLR），基于**模块+偏移**的符号（如 `GameAssembly.dll+0x1234`）通常仍然有效，因为模块基址每次都会重新解析。因此建议尽量用模块相对表达式建立符号。

**Q：`nl "将金币设为9999"` 报 `E_NEEDS_SCAN`？**
A：NLP 只做语义解析，不会自动找地址。你需要先 `scan` 找到金币地址，再 `name set player.gold ...`。错误的 `details.next` 已经把该扫的类型/值和随后的 `name set` 命令写好了，照着执行即可。

**Q：符号该怎么命名？**
A：用 `player.` / `weapon.` / `resource.` 前缀 + 字段名（如 `player.gold`、`weapon.ammo`、`resource.wood`）。这样 NLP 的字段映射和内置模板都能自动命中；否则模板会把它列进 `missing`。

**Q：`--freeze` 之后数值还是掉，为什么？**
A：`--freeze` 只是**注册**冻结项，还需要启动执行器：`game-modifier freeze start --session <id>`。用 `freeze list` 确认注册成功，`freeze stop` 结束。

**Q：能改浮点数（速度、坐标）吗？**
A：可以，`--type float` 或 `double`。但精确匹配几乎不可能命中，请用 `--comparator between` 划范围，再配合 `increased` / `decreased` 筛。

**Q：能用于联机游戏吗？**
A：不能，也不应该。检测到反作弊会返回 `E_ANTI_CHEAT` 并拒绝附加。本工具只面向你自己拥有的单机 / 离线游戏。

**Q：CLI 和 MCP 该选哪个？**
A：人工操作或任何能跑 shell 的场景用 CLI；让 AI Agent 驱动时优先用 MCP——参数是结构化的，校验更严，token 更省。两者共用同一套服务层与 JSON 信封，行为一致。

**Q：`bytes` / `aob` 类型怎么传值？**
A：十六进制字符串，支持多种写法：`"0f270000"`、`"0F 27 00 00"`、`"0f,27,00,00"`。

**Q：怎么让输出更易读？**
A：加 `--format json-pretty`（缩进 JSON）或 `--format human`（带 `[OK]` / `[ERROR]` 前缀的紧凑渲染）。也可以在配置里把 `output.format` 改掉。

**Q：能自定义模板吗？**
A：可以。把 YAML 放到 `~/.game-modifier/templates/`，格式参考 `src/game_modifier/templates/builtin/rpg.yaml`：顶层 `name` / `description` / `game_types` / `options`，每个选项含 `label`、`description`、可选 `params`，以及 `targets` 列表（`symbol`、`type`、`value`、`strategy: set|freeze`）。`value` 支持 `max` / `min` 和 `${参数名}` 占位符。

---

## 11. Token 效率最佳实践

面向 AI Agent 集成场景（也适用于人工高频使用）：把上下文与往返次数压到最低。

1. **临时符号与链中间态复用**：探索性地址用 `name set --temp` 注册；多级指针链用 `name chain` 一次遍历并把每级注册为 `<名>.stepN`——链断裂时中间态仍保留，可从断点继续而不必从头重扫；探索完用 `name clear-temp` 一次清空，不污染正式符号表。
2. **宏封装重复模式**：同一套操作会执行多次（只是数值不同）时，`macro define` 定义一次带 `${param}` 的宏，之后 `macro run --params k=v` 一条命令完成，不用每轮重传整段 YAML。
3. **MCP `--groups` 精简 schema**：每个工具的描述 + 参数 schema 都占上下文；按游戏类型只加载需要的分组（如 UE：`--groups core,scan,modify,ue,jobs`），用 `tools_catalog` 查分组清单。见 5.5 节。
4. **快照回退**：长流程（批量实验、多轮调试）开始前 `session snapshot <name>` 打个点；符号表被改乱或想回到某个状态时 `session restore <name>`，恢复前当前状态自动归档为 `.pre-restore`，不会丢。
5. **既有的基本盘**：attach 一次复用 `session_id`；用符号名代替裸地址；多处修改用 `batch run` / `template apply` 一次完成；输出默认紧凑 JSON，只读需要的字段。

---

## 注意事项

1. **法律与道德**：仅对你**合法拥有**的单机 / 离线游戏使用。不得用于联机、竞技游戏，不得破坏他人游戏体验，不得用于商业作弊服务。
2. **数据安全**：内存修改可能导致崩溃或存档损坏。修改前**手动备份存档**，工具的自动备份只覆盖被写入的内存字节，不包含游戏存档文件。
3. **反作弊红线**：`E_ANTI_CHEAT` 意味着停止，而不是去找绕过方法。
4. **权限**：附加进程通常需要管理员终端。
5. **确认机制**：写入必须显式 `--confirm`；这是有意的设计，请不要靠脚本无条件加上它。
6. **平台**：本版本仅支持 Windows。

---

*文档对应 game-modifier 0.1.0。命令与参数以 `src/game_modifier/cli.py` 中的实际定义为准；执行 `game-modifier <命令> --help` 可查看内置帮助。*
