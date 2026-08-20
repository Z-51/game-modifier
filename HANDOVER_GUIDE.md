# 游戏修改器 CLI 插件 — 项目交接文档

> 面向接手本项目的开发者 / AI Agent。阅读本文后应能独立完成环境搭建、理解架构、定位模块、运行测试并继续开发。

---

## 1. 项目概述

| 项目 | 值 |
| --- | --- |
| 包名 | `game-modifier` |
| 版本 | `0.1.0`（`pyproject.toml` 与 `src/game_modifier/__init__.py` 中的 `__version__` 双处声明，需同步修改） |
| 描述 | Token-efficient single-player game memory modifier plugin for Claude Code and Codex CLI |
| 许可证 | MIT |
| 目标平台 | Windows（本版本唯一受支持的内存后端） |
| 源码规模 | 66 个 Python 文件（`src/game_modifier`，含 `analysis/`、`engines/ue_introspect` 等子包；精确数字以 `scripts/refresh_metrics.py` 输出为准） |
| 测试规模 | 66 个测试文件（含 conftest 共 67 个），858 collected / 857 passed / 1 skipped |
| 覆盖率 | 核心模块（errors / session / output / pointers / processor / guard / aob / analysis）达 85%~100%；精确值以 `pytest --cov` 实测为准 |
| 规模指标 | **以 `scripts/refresh_metrics.py` 输出为准**（源文件/测试/工具/错误码等数字，代码变化后重跑替换，勿手改） |

### 用途

本项目是一个**单机游戏内存修改工具**，专门设计为供编码 Agent（Claude Code、Codex CLI）调用，核心设计目标是 **token 效率**：

- **会话复用**：`attach` 一次，后续命令只传 `session_id`，不必重复传进程/模块映射表。
- **符号地址表**：Agent 引用 `player.gold` 而不是原始指针链。
- **确定性中文 NLP**：传一句 `将金币设为9999`，无需 Agent 推理或生成代码。
- **结构化 JSON 输出**：每个命令输出单行 JSON，带稳定的 `error.code`，Agent 可直接分支而不需解析自然语言。
- **模板与批处理**：一次调用完成多处修改。

### 使用边界（重要）

仅用于**单机 / 离线**游戏。检测到已知反作弊系统时工具会拒绝附加（`E_ANTI_CHEAT`）。这是硬性安全契约，任何改动都不应削弱它。

---

## 2. 技术栈

### 运行时

- **Python 3.10+**（`requires-python = ">=3.10"`）
- `psutil>=5.9` — 进程/模块枚举（必需依赖；`memory/process.py` 内另有纯 ctypes Toolhelp 兜底，但 psutil 是受支持路径）
- `PyYAML>=6.0` — 模板与批处理文件解析
- `tomli>=2.0`（仅 Python < 3.11）— TOML 配置解析；3.11+ 使用标准库 `tomllib`

### 可选依赖组（缺失时优雅降级）

| extra | 内容 | 用途 |
| --- | --- | --- |
| `radare2` | `r2pipe>=1.8` | 静态分析（`analyze --deep`） |
| `frida` | `frida>=16.0` | 动态插桩（预留） |
| `mcp` | `mcp>=1.0` | MCP 服务器 |
| `speed` | `numpy>=1.26` | 扫描向量化加速（可选，未装时回落纯 Python） |
| `dev` | `pytest>=7.0`, `pyflakes>=3.0` | 测试与静态检查 |
| `all` | r2pipe + mcp + numpy + pytest | 一次装齐 |

### 构建与入口

- 构建后端：`setuptools>=64` + `wheel`，`src/` 布局（`package-dir = {"" = "src"}`）
- 包数据：`templates/builtin/*.yaml`、`data/*.toml`
- 控制台入口点：
  - `game-modifier` → `game_modifier.cli:main`
  - `game-modifier-mcp` → `game_modifier.mcp_server:main`
- pytest 配置内嵌于 `pyproject.toml`（`testpaths = ["tests"]`, `addopts = "-q"`）

### 平台约束

Windows 内存后端通过 `ctypes` 直接调用 kernel32（`OpenProcess` / `ReadProcessMemory` / `WriteProcessMemory` / `VirtualQueryEx` / `VirtualProtectEx`）。非 Windows 平台 `get_backend()` 抛 `UnsupportedOSError`（`E_UNSUPPORTED_OS`），Linux/macOS 后端为规划项。附加进程通常需要**管理员终端**。

---

## 3. 架构设计

### 3.1 分层架构

```
┌─────────────────────────────────────────────────────┐
│  表现层                                              │
│  CLI (cli.py)            MCP Server (mcp_server.py) │
│  argparse 子命令          结构化工具调用               │
│  → output.py Result envelope（json/json-pretty/human）│
├─────────────────────────────────────────────────────┤
│  服务层                                              │
│  ModifierService (service.py, 4,521 行)               │
│  唯一编排点：会话 + 后端 + 安全 + NLP + 引擎 + 工具链    │
│              + 模板 + 批处理                          │
├─────────────────────────────────────────────────────┤
│  核心层                                              │
│  memory │ engines │ toolchain │ safety │ nlp        │
│  templates │ batch │ analysis（布局分析/指针反查）     │
├─────────────────────────────────────────────────────┤
│  基础设施                                            │
│  session.py  config.py  errors.py  output.py        │
├─────────────────────────────────────────────────────┤
│  平台层                                              │
│  MemoryBackend (ABC, memory/base.py)                │
│    └── WindowsMemoryBackend (memory/windows.py)     │
│    └── FakeBackend (tests/conftest.py，测试替身)      │
└─────────────────────────────────────────────────────┘
```

**关键设计约束**：CLI 与 MCP 都是 `ModifierService` 的薄包装，任何新功能都必须先落在 `service.py`，再分别在两个表现层暴露，否则两条路径行为会漂移。

### 3.2 数据流：attach → scan → name set → modify

```
① attach --process game.exe
   cli.dispatch → service.attach()
     ├─ procmod._resolve_pid()      按 pid / name / exe 定位进程
     ├─ get_backend().open(pid)      打开句柄，枚举模块
     ├─ safety.detect_anti_cheat()   ❗命中且 block_anti_cheat=True → E_ANTI_CHEAT，终止
     ├─ engines.detect()             识别 Unity/Unreal/unknown
     └─ SessionStore.save()          写 ~/.game-modifier/sessions/<id>.json
   ← {"session_id": "game-a1b2c3d4", "engine": ..., "module_count": ...}

② scan --session <id> --type int32 --value 100
   service.scan() → scanner.first_scan(backend, ...)
     遍历可读区域 → 分块读取 → 比较器过滤 → 截断到 max_results
   ScanState{type, comparator, addresses, values} 落盘进 session
   ← {"count": 1423, "addresses": [...], "truncated": false}

③ scan-next --session <id> --value 80        （在游戏里改变数值后）
   service.scan_next() → scanner.next_scan(仅重读上一轮候选地址)
   支持 changed / unchanged / increased / decreased（依赖上一轮 values）
   ← 候选集收敛到 1~2 个

④ name set player.gold --base 0x7FF... --type int32
   service.name_set() → Symbol 写入 session.symbols

⑤ modify --symbol player.gold --value 9999 [--confirm] [--freeze]
   service.modify() → _modify_on()
     ├─ _resolve_target()   符号 → base_expr + offsets → pointers.resolve_pointer()
     ├─ validate_address()  区域存在性 / 可写性检查
     ├─ 读旧值（old_value，同时用于备份与 freeze-at-current）
     ├─ _resolve_value()    数字 / MAX / MIN token → 具体值
     ├─ ❗无 --confirm → dry_run=True 直接返回，不写内存
     ├─ BackupManager.create()   auto_backup=True 时先备份原始字节
     ├─ backend.write() → 回读验证（verified_value）
     └─ --freeze → session.freezes 注册；freeze start 起后台进程持续回写
   ← {"applied": true, "old_value": 100, "new_value": 9999, "backup_id": "..."}
```

**自然语言快捷路径**：`nl --session <id> "将金币设为9999" --confirm`
→ `nlp.parse()` 得到 `Intent{action=set, field=gold, value=9999, value_type=int32}`
→ `_map_field_to_symbol()` 在符号表中查找 `gold` / `player.gold` / `weapon.gold` / `resource.gold` 或叶名匹配
→ 命中则复用 `_modify_on()`；未命中抛 `NeedsScanError`，并在 `details.next` 里**直接给出下一步的 scan 参数与 name set 命令**（这是省 token 的关键设计）。

---

## 4. 核心模块详解

### 4.1 `memory` — 内存访问核心

| 文件 | 职责 |
| --- | --- |
| `base.py` (177行) | 抽象契约层 |
| `windows.py` (217语句) | Windows ctypes 实现 |
| `scanner.py` (422语句) | 值扫描引擎（numpy 向量化 + 并行首扫 + 批量读） |
| `aob.py` (86语句) | AOB 字节模式扫描（`??` 通配符） |
| `pointers.py` (137行) | 指针链解析 |
| `types.py` (195行) | 类型系统 |
| `process.py` | 进程发现 |

#### `base.py`

定义四个核心抽象，是整个项目的**契约中心**：

- `MemoryRegion` — dataclass：`base/size/protect/state/type` + `readable/writable/executable`；`end` 属性、`contains(addr, len)`、`to_dict()`
- `ModuleInfo` — `name/base/size/path` + `end`、`to_dict()`
- `ProcessInfo` — `pid/name/exe_path/arch/modules`；`pointer_size` 按 arch 返回 4 或 8
- `MemoryBackend(ABC)` — 抽象方法 `open / close / is_alive / read / write / regions / query`；已实现的便利方法 `modules()`、`find_module()`（支持 `GameAssembly` 匹配 `GameAssembly.dll`）、`pointer_size`、`readable_regions()`、上下文管理器协议
- `get_backend()` — 平台工厂：Windows 返回 `WindowsMemoryBackend`，否则抛 `UnsupportedOSError`

> 保持接口抽象的收益：scanner、pointers、safety 与测试共享同一份契约，测试里的 `FakeBackend` 可以无缝替换真实进程。

#### `windows.py`

- `OpenProcess` 权限位组合（`PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION`）
- `ReadProcessMemory` / `WriteProcessMemory` 封装，失败抛 `ReadFailedError` / `WriteFailedError`
- `VirtualQueryEx` 遍历 `MEMORY_BASIC_INFORMATION` 构造 `MemoryRegion` 列表
- 写入只读区域时用 `VirtualProtectEx` 临时改保护位再恢复（`modify` 会带 warning 提示这一行为）
- `IsWow64Process` 判断 x86/x64 → 决定指针宽度

#### `scanner.py`

- **首次扫描比较器（8 种）**：`exact, not_equal, gt, gte, lt, lte, between, unknown`
- **增量扫描额外比较器（4 种）**：`changed, unchanged, increased, decreased`（依赖 session 中保存的上一轮 `values`）
- `first_scan()`：遍历 `readable_regions()`，按 `chunk_size`（默认 4 MiB）分块读取，`alignment` 控制步长，`max_region_bytes` 可限制单区域扫描量，`max_results`（默认 20000）截断并置 `truncated=True`
- 变长类型（`string` / `bytes`）只支持 `exact`，走 `_scan_bytes()` 字节子串搜索
- `next_scan()`：只重读候选地址，速度与候选数线性相关；采用**批量读**（一次 `ReadProcessMemory` 读入连续候选块再切片）减少系统调用次数
- **性能加速**：数值定长类型命中 **numpy 向量化**比较路径（`[speed]` extra，未装时回落纯 Python）；`first_scan` 可用 **workers 并行**分区扫描（受 GIL 限制，仅 numpy 路径真正受益）
- **扫描缓存 sidecar**：候选数超过 `[scan] candidates_sidecar_threshold`（默认 5000）时落盘到二进制 sidecar（`sessions/<id>/scan_candidates.bin`），避免巨大候选集撞大 session JSON；若两轮扫描间区域布局变化，`next_scan` 报 `E_SCAN_CACHE_STALE`
- 返回 `ScanResult`（`type/comparator/count/truncated/addresses/values`），由 service 转成 `ScanState` 持久化

#### `pointers.py`

- 基址表达式语法：`module+offset`（如 `GameAssembly.dll+0x1234`）、纯十六进制地址、模块名
- `parse_int()` 智能识别十进制/十六进制（`_looks_hex` 启发式）
- `parse_offsets()` 支持逗号或空白分隔
- `resolve_pointer()` 遵循 **Cheat Engine 约定**：`addr = base; for o in offsets: addr = read_pointer(addr) + o`，最后一个 offset 相加但不解引用；空 offsets 表示 base 本身即值地址
- 每一级解引用失败抛 `InvalidPointerError` / `InvalidAddressError`，返回中带完整的中间步骤便于 Agent 诊断

#### `types.py`

- **14 种规范类型**：`int8 uint8 int16 uint16 int32 uint32 int64 uint64 float double bool string string_utf16 bytes`
- **33 种友好别名**：`byte/word/dword/qword/short/long/int/uint/single/f32/f64/str/wstring/aob/hex/...`
- 全部小端（匹配 x86/x64 游戏进程）
- `resolve_type()` 归一化（去空格/连字符/下划线，对两个 string 变体特殊处理）
- `encode_value` / `decode_value` / `type_size` / `value_range`；越界抛 `ValueOutOfRangeError`，未知类型抛 `InvalidTypeError` 且 `details.supported` 列出全部可用类型

#### `process.py`

- `list_processes()` / `find_by_name()` / `find_by_exe()` / `process_exists()` / `is_admin()`
- 优先 psutil，缺失时回落到 ctypes Toolhelp 快照（`CreateToolhelp32Snapshot`）
- `attach` 遇到同名多进程会返回 `E_INVALID_ARGS` 并列出候选，要求显式 `--pid`

### 4.2 `engines` — 游戏引擎识别与适配

#### `detect.py`

引擎标识常量：`UNITY_IL2CPP = "unity-il2cpp"`、`UNITY_MONO = "unity-mono"`、`UNREAL = "unreal"`、`UNKNOWN = "unknown"`。

**三层检测策略**：

1. `detect_from_modules(modules)` — 匹配已加载模块名（`GameAssembly.dll` → Il2Cpp，`mono-2.0-bdwgc.dll` → Mono，UE 相关 DLL → Unreal）
2. 文件系统探测 — 从 exe 路径推断同级目录结构（`*_Data/il2cpp_data`、`global-metadata.dat`、`Engine/Binaries`、`*.pak` 等）
3. **置信度合并** — 两路结果加权融合，输出 `{engine, confidence, evidence, artifacts}`；`artifacts` 给出后续 dumper 需要的文件路径

#### `unity.py`

Il2Cpp / Mono 支持：定位 `GameAssembly.dll` + `global-metadata.dat`，驱动 Il2CppDumper / Il2CppInspector 产出字段偏移与方法 RVA，解析 dump 结果供 `name set` 使用。

#### `unreal.py`

UE4 / UE5 支持：识别 `Engine/Binaries` 布局，引导 UE4 Dumper / UE4SS 导出 GObjects / GNames，再用 `resolve` 解析地址。

> ⚠️ `engines/__init__.py` 显式 `from . import unity` / `from . import unreal` 并列入 `__all__`，避免子模块名被同名符号遮蔽（详见 §11）。

### 4.3 `toolchain` — 逆向工具链集成

#### `registry.py`

`ToolSpec` dataclass（`name/config_key/executables/default_dirs/version_args/kind/install_hint`）描述 **14 种工具**（radare2 / rizin / x64dbg / x32dbg / cdb / windbg / binaryninja / il2cppdumper / il2cppdumper_rs / il2cppinspector / ue4dumper / ue4ss / dotnet / il_tool）：

| 工具 | kind | 用途 |
| --- | --- | --- |
| radare2 / rizin | cli | 静态分析（`analyze --deep`） |
| x64dbg / x32dbg | gui | 调试器脚本生成 |
| cdb / windbg | debugger | 进程检查 |
| binaryninja | gui | 静态分析（需 headless API） |
| il2cppdumper / il2cppinspector | dumper | Unity Il2Cpp 字段偏移 |
| ue4dumper / ue4ss | dumper | Unreal GObjects/GNames |

**三级查找顺序**（`find_tool()`）：
1. 配置显式路径 `[tools].<config_key>`（`~/.game-modifier/config.toml`）
2. `PATH`（`shutil.which`）
3. `default_dirs` + 用户配置的 `[tools.search_dirs].extra`（同时尝试 `exe` 与 `exe.exe`）

`_query_version()` 带 8 秒超时读取版本首行；`detect_all()` 返回 `{tools: {...}, available: [...]}`。全部工具**可选**，缺失时相关功能优雅降级（返回 `E_TOOL_NOT_FOUND` + `install_hint`）。

#### 适配器

- `radare2.py` — 通过 r2pipe 或子进程执行 `aaa` 系列命令，提取函数/字符串/交叉引用
- `windbg.py` — 生成 cdb 检查脚本
- `x64dbg.py` — 生成 x64dbg 脚本（断点/内存断点）
- `binaryninja.py` — headless API 分析

### 4.4 `safety` — 安全护栏

#### `guard.py`

`ANTI_CHEAT_SIGNATURES` 覆盖 **11 种反作弊系统**（对模块名与其它运行进程名做大小写不敏感子串匹配）：

EasyAntiCheat、BattlEye、Riot Vanguard、nProtect GameGuard、XIGNCODE3、Denuvo Anti-Cheat、PunkBuster、mhyprot (miHoYo)、FACEIT、FairFight、Ricochet (COD)。

`detect_anti_cheat(module_names, process_names)` → `{detected, systems, matches}`。命中且 `safety.block_anti_cheat=True` 且未传 `--allow-anti-cheat` 时，`attach` 抛 `E_ANTI_CHEAT` 并终止。

#### `backup.py`

`BackupManager(dir)`：
- `create(backend, targets, label)` — 读取目标原始字节，存为 JSON（地址 + hex 字节 + note + 时间戳 + label），返回 `{id, entries}`
- `list_backups()` — 列出全部备份记录
- `restore(backend, backup_id)` — 逐条写回原始字节；未找到抛 `E_BACKUP_NOT_FOUND`

备份目录：`~/.game-modifier/sessions/<session_id>/backups/`。`safety.auto_backup=True`（默认）时，每次 `modify --confirm` 自动备份。

#### `validation.py`

- `validate_address(backend, address, size)` — 用 `backend.query()` 确认地址落在已映射区域内，返回该 `MemoryRegion`；非法抛 `InvalidAddressError`。不可写区域不直接拒绝，而是让 service 添加 warning（因为 `VirtualProtectEx` 可能成功）
- 类型与值域校验委托给 `memory/types.py`

### 4.5 `nlp` — 确定性中文意图解析

**设计原则：纯确定性，零 LLM 调用、零随机性**。相同输入必然得到相同 `Intent`，这是 Agent 可以信任它的前提。

#### `lexicon.py`

- `FIELDS` — **16 个字段**，每项为 `(默认类型, 触发词列表)`，中英双语。例：`gold` 触发词含 `金币/金錢/金钱/钱/钱币/硬币/coin/coins/gold/money/gil`；`gem` 含 `钻石/宝石/钻/gem/diamond/crystal`。默认类型只是提示，符号表条目或显式 `--type` 优先。
- 动作词表（**顺序敏感，具体的排前面**）：
  - `SET_TERMS` — 设置为/设定为/修改为/改为/改成/调成/变成/置为/设为/set to/set/=
  - `ADD_TERMS` — 增加/加上/添加/多给/add/increase/增
  - `SUB_TERMS` — 减少/扣除/降低/减掉/减去/subtract/decrease/减
  - `FREEZE_TERMS` — 无限/无敌/锁定/冻结/固定/永久/unlimited/infinite/freeze/lock/god mode
  - `GET_TERMS` — 获取/读取/查看/查询/显示/看看/get/read/show/view
  - `UNLOCK_TERMS` — 解锁/开启所有/全部解锁/unlock all/unlock
  - `MAX_TERMS` — 最大/拉满/满值/满/max；`MIN_TERMS` — 清零/归零/最小/min/zero
- `UNLOCK_TARGET_TERMS` — 关卡 / 物品 等解锁目标分类
- **数字解析**：全角→半角映射（`０-９`、`．`、`，`）；中文数字 `_CN_DIGITS`（零〇一二两三四五六七八九）+ `_CN_UNITS`（十百千万亿）；阿拉伯数字正则支持千分位与小数

#### `processor.py`

`parse(text) -> Intent`：归一化 → 匹配动作（最长优先）→ 匹配字段 → 解析数值（含 MAX/MIN 哨兵）→ 推断类型。100% 测试覆盖。

#### `intents.py`

`Intent` 数据模型（`action / field / value / value_type / raw / confidence` + `to_dict()`），以及 `MAX` / `MIN` 哨兵常量。

> `MAX` 的语义分叉值得注意（`service._resolve_value`）：**freeze at MAX** 保留*当前值*（真正的"无限"，永不下降）；**set to MAX** 使用该类型的最大值。

### 4.6 `templates` — 分类模板

#### `loader.py`

- `list_templates(user_dir)` — 合并内置模板与用户模板目录（`~/.game-modifier/templates`），同名时用户模板覆盖
- `load_template(name, user_dir)` — YAML 加载 + schema 校验；未找到抛 `E_TEMPLATE_NOT_FOUND`，格式错误抛 `E_TEMPLATE_INVALID`
- `get_option(template, key)` → `TemplateOption{label, description, params, targets}`
- `expand_option(template, option, params)` — 参数替换后展开为目标列表 `[{symbol|address, type, value, offsets, strategy, note}]`；`strategy` 为 `set` 或 `freeze`

#### 内置模板（3 个，共 16 个选项）

| 文件 | 适用类型 |
| --- | --- |
| `builtin/rpg.yaml` | RPG（金币/经验/等级/属性点等） |
| `builtin/action.yaml` | 动作（无限弹药/无敌/无限体力等） |
| `builtin/strategy.yaml` | 策略（资源/人口/建造时间等） |

模板应用时若目标符号未映射，会进入 `missing_symbols` 并在 `hint` 中提示先 `scan` + `name set`，其余目标照常执行。

### 4.7 `batch` — 批量执行

#### `runner.py`

`STEP_KEYS` 定义 **9 种操作类型**：`nl, modify, template, scan, scan_next, read, resolve, name, backup`。

- `load_batch(path)` — 加载 YAML/JSON，校验结构；文件不存在或格式错误抛 `E_BATCH_ERROR`
- `step_action(step)` — 取步骤字典中命中的动作键
- `run(operations, execute, stop_on_error)` — 顺序执行，逐步收集结果，汇总 `{total, succeeded, failed, results}`
- 批处理文件内的 `confirm` / `stop_on_error` 字段**优先于**命令行参数（`service.batch_run`）
- 参考示例：`samples/example_batch.yaml`

### 4.8 基础设施

#### `service.py`（4,521 行，69% 覆盖）

`ModifierService` 是**唯一编排点**，公开方法：`attach, analyze, scan, scan_next, scan_aob, resolve, read, modify, freeze_list/clear/run/start/stop, nl, name_set, name_get, template_list/show/apply, batch_run, backup_create/list/restore, toolchain_detect, list_sessions, session_info, session_survey, audit_tail, layout_analyze, heap_scan, pointer_scan, save_edit_detect/modify, detach`。

内部关键私有方法：
- `_resolve_pid()` — pid/name/exe 三种定位方式
- `_open(session)` — 检查进程存活（否则 `E_PROCESS_EXITED`），打开后端并刷新模块基址
- `_resolve_target()` — 符号或地址 → 最终地址 + 类型（符号缺失抛 `E_SYMBOL_NOT_FOUND` 并列出已知符号）
- `_modify_on()` — 写入流程主干（dry-run 判定、备份、写入、回读验证、freeze 注册）
- `_resolve_value()` / `_type_max()` / `_type_min()` — MAX/MIN token 解析
- `_map_field_to_symbol()` — NLP 字段到符号的模糊匹配

**freeze 机制**：`freeze_run` 是前台循环（按 `interval` 反复写入所有冻结项）；默认启用**自适应间隔**（`[freeze] adaptive`），按写压动态调节；`freeze_start` 用 `subprocess.Popen` + `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP` 拉起后台 `python -m game_modifier freeze run`，PID 写入 `sessions/<id>/freeze.pid`；`freeze_stop` 读 PID 并 terminate（优先 psutil，回落 `os.kill`）。

**审计日志**：每次确认写入都会 best-effort 追加一条 JSONL 记录到 `sessions/<id>/audit.jsonl`（操作、目标、backup_id、时间戳），`audit_tail` 回读最近 N 条；写入失败不阻断主操作。

#### `session.py`（835 行，100% 覆盖）

- `Symbol` — `name/base_expr/offsets/type/description`
- `ScanState` — `type/comparator/count/truncated/addresses/values`，自带 `to_json` / `from_json`（`values` 的 int 键需转字符串以适配 JSON）
- `Session` — 进程身份 + 模块缓存 + 符号表 + 冻结列表 + 扫描状态 + 引擎/反作弊检测结果；`summary()` 输出精简摘要（token 友好）
- `SessionStore` — session ID 形如 `<进程名前16字符>-<uuid4前8位>`；**原子写入**：先写 `.json.tmp` 再 `replace()`，避免崩溃留下半截文件；`load()` 缺失时抛 `SessionNotFoundError` 并附 `known` 列表；`delete()` 同时清理 backups 目录

#### `config.py`（215 行）

**4 层配置合并**（后者覆盖前者，`_deep_merge` 递归合并 dict）：

1. 打包的 `data/default.toml`
2. `~/.game-modifier/config.toml`
3. `$GAME_MODIFIER_CONFIG` 指向的文件
4. CLI `--config` 显式路径（不存在则抛 `FileNotFoundError`）

`Config` 提供类型化访问器：`dry_run, block_anti_cheat, auto_backup, require_writable_region, output_format, scan_max_results(20000), scan_chunk_size(4MiB), scan_alignment(1), scan_max_region_bytes(0), tool_path(name), tool_search_dirs()`，以及路径解析 `home_dir(~/.game-modifier), sessions_dir, user_templates_dir` 与 `ensure_dirs()`。

#### `errors.py`（313 行，100% 覆盖）

- `ErrorCode(str, Enum)` — **40 个稳定错误码**，分组如下：
  - 进程/会话：`E_PROCESS_NOT_FOUND, E_ACCESS_DENIED, E_SESSION_NOT_FOUND, E_PROCESS_EXITED`
  - 安全：`E_ANTI_CHEAT, E_NOT_CONFIRMED, E_DRY_RUN`
  - 内存：`E_INVALID_ADDRESS, E_ADDRESS_NOT_WRITABLE, E_READ_FAILED, E_WRITE_FAILED, E_INVALID_TYPE, E_VALUE_OUT_OF_RANGE, E_INVALID_POINTER`
  - 解析：`E_NEEDS_SCAN, E_SYMBOL_NOT_FOUND, E_NLP_UNRESOLVED`
  - 工具/引擎：`E_TOOL_NOT_FOUND, E_TOOL_FAILED, E_ENGINE_UNKNOWN`
  - 模板/批处理：`E_TEMPLATE_NOT_FOUND, E_TEMPLATE_INVALID, E_BATCH_ERROR, E_BACKUP_NOT_FOUND`
  - 存档修改：`E_SAVE_EDIT_REQUIRED, E_SAVE_FORMAT_UNSUPPORTED`
  - 扫描/分析：`E_PATTERN_NOT_FOUND, E_LAYOUT_UNSUPPORTED, E_SCAN_TIMEOUT, E_SCAN_CACHE_STALE`
  - 通用：`E_UNSUPPORTED_OS, E_INVALID_ARGS, E_DEPENDENCY_MISSING, E_INTERNAL`
- `GameModifierError` 基类（`message` + `code` + `details` + `hint`，`to_dict()` 序列化）
- **28 个常用子类**：`ProcessNotFoundError, AccessDeniedError, SessionNotFoundError, AntiCheatError, NotConfirmedError, InvalidAddressError, InvalidTypeError, ValueOutOfRangeError, ReadFailedError, WriteFailedError, NeedsScanError, SymbolNotFoundError, NlpUnresolvedError, ToolNotFoundError, TemplateNotFoundError, BatchError, UnsupportedOSError, DependencyMissingError, InvalidArgsError`，另含 `ProfileRestrictedError, IlPatchFailedError, IlVerifyFailedError, SaveEditRequiredError, SaveFormatUnsupportedError, PatternNotFoundError, LayoutUnsupportedError, ScanTimeoutError, ScanCacheStaleError`

> **契约**：错误码一经发布不得更改字面值——Agent 依赖它做分支。新增错误只能追加。

#### `output.py`（135 行，100% 覆盖）

`Result` envelope：

```json
{"ok": true, "command": "modify", "data": {...}, "warnings": ["..."]}
{"ok": false, "command": "modify", "error": {"code": "E_...", "message": "...", "hint": "...", "details": {...}}}
```

构造器 `Result.success / failure / from_exception`，`warn()` 追加警告，`exit_code` 属性（成功 0 / 失败 1）。

`emit(result, fmt)` 支持 **3 种格式**：`json`（默认，单行，token 最省）、`json-pretty`（缩进 2）、`human`（`[OK] command` + 缩进详情）。`_default()` 兜底序列化 bytes（转 hex）、set/tuple（转 list）、带 `to_dict()` 的对象。

### 4.9 `analysis` — 内存布局分析与指针反查

**只读**启发式子系统，把原始内存变成结构；每条结果都带 `confidence`（0.0–0.95）与 `reason`，供 Agent 直接分支。对应 CLI `layout` / `pointer-scan`，MCP `layout_analyze` / `heap_scan` / `pointer_scan`。

| 文件 | 职责 |
| --- | --- |
| `alignment.py` | 指针对齐推断、`looks_like_pointer`、区间构造/命中判定 |
| `vtable.py` | 虚表候选（指向代码段的指针簇）`find_vtables` |
| `rtti.py` | MSVC `.?AV` RTTI 类名提取 `find_rtti_classes` |
| `classlayout.py` | 根据 vtable 实例推断字段布局 `infer_class_layout` |
| `heap.py` | 枚举堆对象候选（对齐指针形 slot）`scan_heap_objects` |
| `pointerscan.py` | 反向指针扫描，反查到达目标地址的路径 `find_pointer_paths` |
| `report.py` | 结果转人类可读文本 `to_text` |

`memory/aob.py` 提供 AOB 字节模式扫描（`??` 通配符），分块时相邻块重叠 `pattern_len-1` 字节，保证跨越块边界的匹配不漏不重；未命中抛 `E_PATTERN_NOT_FOUND`。不支持的布局分析抛 `E_LAYOUT_UNSUPPORTED`，指针反查超出 `[analysis] scan_timeout` 抛 `E_SCAN_TIMEOUT`。

### 4.10 性能优化要点

- **批量读**：`next_scan` 一次读入连续候选块再切片，减少 `ReadProcessMemory` 调用次数。
- **numpy 向量化**（`[speed]` extra）：数值定长类型的比较改走 numpy，未装时回落纯 Python slot 循环。
- **并行首扫**：`first_scan` 支持 workers 分区并行（GIL 下仅 numpy 路径真正提速）。
- **自适应冻结**：`[freeze] adaptive=true` 按写压在 `min_interval`/`max_interval` 间自动调节回写间隔（`GAME_MODIFIER_FREEZE_ADAPTIVE=0/1` 可临时开关），比固定 50ms 轮询更省 CPU 且不易被盖回。
- **扫描缓存 sidecar**：大候选集落盘二进制 sidecar，减轻 session JSON 负担。

---

## 5. 模块交互关系

```
                      ┌──────────┐          ┌───────────────┐
                      │ cli.py   │          │ mcp_server.py │
                      └────┬─────┘          └───────┬───────┘
                           │  argparse             │  MCP tools
                           └───────────┬───────────┘
                                       ▼
                          ┌────────────────────────┐
              ┌───────────│  ModifierService       │───────────┐
              │           └───┬────────┬───────┬───┘           │
              ▼               ▼        ▼       ▼               ▼
       ┌────────────┐  ┌──────────┐ ┌──────┐ ┌────────┐ ┌───────────┐
       │ SessionStore│ │ safety   │ │ nlp  │ │templates│ │ toolchain │
       │ (session.py)│ │ guard    │ │parse │ │ loader  │ │ registry  │
       │  Session    │ │ backup   │ └──┬───┘ └───┬────┘ └─────┬─────┘
       │  Symbol     │ │ validate │    │         │            │
       │  ScanState  │ └────┬─────┘    │         │      radare2/x64dbg
       └──────┬──────┘      │      lexicon    builtin/*.yaml  windbg/binja
              │             │      intents
              │             ▼
              │      ┌─────────────────────────────────┐
              └─────▶│  memory                         │
                     │  scanner ─┐                     │
                     │  pointers ─┼──▶ MemoryBackend   │
                     │  types  ───┘      (base.py ABC) │
                     │  process          │             │
                     └───────────────────┼─────────────┘
                                         ▼
                            ┌──────────────────────────┐
                            │ WindowsMemoryBackend     │
                            │ (ctypes → kernel32)      │
                            └──────────────────────────┘

                     ┌──────────┐
                     │ batch    │──▶ 回调 ModifierService 的各方法
                     │ runner   │    （9 种操作复用同一套服务方法）
                     └──────────┘

  横切依赖（几乎所有模块都引用）：
    errors.py  ──▶  统一异常与错误码
    config.py  ──▶  Config 注入 ModifierService 构造函数
    output.py  ──▶  仅表现层使用
```

**依赖方向铁律**：

- `memory` / `nlp` / `templates` / `batch` **不依赖** `service.py`（单向依赖，避免循环）
- `batch/runner.py` 通过**回调注入**（`execute: Callable`）调用服务方法，而非直接 import service
- `errors.py` 无内部依赖，是依赖图的叶节点
- 表现层（cli/mcp_server）**只**依赖 service + output + config + errors

---

## 6. 开发环境搭建

```bash
git clone <repo>
cd game-modifier

python -m venv .venv
.venv\Scripts\activate          # Windows PowerShell: .\.venv\Scripts\Activate.ps1

pip install -e .[dev]           # 或 pip install -e .[all] 装齐可选依赖
pytest tests/ -v
```

### 验证安装

```bash
game-modifier --help
game-modifier toolchain detect          # 查看本机已安装的逆向工具
game-modifier template list             # 应列出 rpg / action / strategy
```

### 本地联调（无需真实游戏）

`samples/target.py` 是一个自带可预测内存值的靶子进程，用于端到端手工验证：

```bash
python samples/target.py                          # 另开一个终端运行
game-modifier attach --process python.exe         # 记下 session_id
game-modifier scan --session <id> --type int32 --value 100
```

### 注意事项

- 附加真实游戏进程通常需要**管理员权限终端**
- 项目采用 `src/` 布局；`tests/conftest.py` 会把 `src/` 插入 `sys.path`，因此**未安装也能跑测试**
- Python 3.10 会走 `tomli` 分支，3.11+ 走 `tomllib`——如需验证 3.10 兼容性必须在 3.10 环境实测

---

## 7. 测试体系

### 概况

- **框架**：pytest（配置内嵌在 `pyproject.toml`，`testpaths=["tests"]`，`addopts="-q"`）
- **规模**：66 个测试文件，**858 个用例（857 passed / 1 skipped）**
- **覆盖率**：总体 **77%**

| 模块 | 覆盖率 |
| --- | --- |
| `errors.py` / `session.py` / `output.py` / `pointers.py` / `nlp/processor.py` / `safety/guard.py` / `analysis/__init__.py` | 100% |
| `safety/backup.py` | 95% |
| `memory/types.py` / `safety/validation.py` / `analysis/heap.py` | 93% |
| `nlp/lexicon.py` / `analysis/alignment.py` / `analysis/pointerscan.py` / `memory/aob.py` | 92% |
| `analysis/report.py` | 89% |
| `memory/base.py` / `toolchain/registry.py` / `analysis/classlayout.py` | 88% |
| `templates/loader.py` / `analysis/rtti.py` / `analysis/vtable.py` | 85% |
| `memory/scanner.py` | 77% |
| `service.py` | 69% |
| `mcp_server.py` | 57% |
| `toolchain/windbg.py` | 46% |
| `memory/process.py` | 35% |
| `memory/windows.py` | 29% |
| `toolchain/radare2.py` / `x64dbg.py` / `binaryninja.py` | 21%~24% |

低覆盖模块的共同点：都需要真实 Windows 进程或外部二进制工具，属于**有意的测试边界**而非疏漏。

### FakeBackend 架构（核心测试基础设施）

`tests/conftest.py` 中的 `FakeBackend(MemoryBackend)` 用**纯 bytearray 字典**实现完整后端契约：

```python
FakeBackend(regions={0x140000000: bytearray(...)},
            modules=[ModuleInfo(...)],
            arch="x64", pid=4242, name="fake.exe")
```

- `_regions: dict[int, bytearray]` — base 地址 → 字节缓冲
- `read/write` 按地址定位所属缓冲，越界抛 `RuntimeError("unmapped read/write")`
- `query/regions` 返回 `readable=True, writable=True` 的 `MemoryRegion`
- 构造时自动 `open(pid)`，无需显式生命周期管理

这让 **scanner、pointers、safety、service** 都能在无真实进程的情况下确定性测试——这是本项目测试策略的基石。任何新增的内存相关逻辑都应通过 `FakeBackend` 覆盖。

### 共享 fixtures

| fixture | 作用 |
| --- | --- |
| `fake_backend_factory` | 工厂函数，按需构造 `FakeBackend` |
| `tmp_config` | 指向 `tmp_path` 的 `Config`，隔离真实 `~/.game-modifier` |
| `sample_module` | `GameAssembly.dll` @ `0x140000000`，size `0x1000000` |

### 测试文件组织

`test_<模块>.py` 为基础用例，`test_<模块>_deep.py` 为边界与异常路径：

```
test_cli.py / test_cli_integration.py    CLI 参数解析与端到端分发
test_service.py / test_service_deep.py   服务层编排
test_scanner_deep.py / test_scanner_pointers.py / test_pointers_deep.py  扫描与指针
test_types.py / test_types_deep.py       类型系统
test_nlp.py / test_nlp_deep.py           意图解析
test_safety.py / test_safety_deep.py     反作弊/备份/校验
test_engines_deep.py / test_engines_toolchain.py 引擎与工具链
test_templates_batch.py                  模板与批处理
test_session.py test_config.py test_errors.py test_output.py  基础设施
```

### 运行命令

```bash
pytest tests/ -v                                            # 全量（verbose）
pytest tests/ -q                                            # 静默
pytest tests/test_service.py::test_modify_dry_run -v         # 单个用例
pytest tests/ --cov=game_modifier --cov-report=term          # 覆盖率
pytest tests/ --cov=game_modifier --cov-report=html          # HTML 报告
pytest tests/ -q --tb=short -x                               # 首次失败即停
python -m pyflakes src/game_modifier                         # 静态检查
```

---

## 8. 部署说明

### pip 安装

```bash
pip install -e .            # 开发模式
pip install .               # 常规安装
pip install .[all]          # 含全部可选依赖
```

### 入口点

| 命令 | 目标 | 说明 |
| --- | --- | --- |
| `game-modifier` | `game_modifier.cli:main` | CLI，每条命令输出单行 JSON |
| `game-modifier-mcp` | `game_modifier.mcp_server:main` | MCP stdio 服务器 |
| `python -m game_modifier` | `__main__.py` | 等价于 CLI（`freeze start` 内部即用此形式拉起后台进程） |

### MCP 部署

**Codex CLI** — 写入 `~/.codex/config.toml`：

```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = []
```

**Claude Code** — 仓库已内置 `.mcp.json` 与 `.claude-plugin/plugin.json`，直接识别。

**暴露的 MCP 工具（默认 profile，共 83 个 / 11 组）**：core / scan / modify / analysis / ue / il2cpp / il / mono / jobs / macros / safety（精确成员与计数以运行时 `tools_catalog` 或 `scripts/refresh_metrics.py` 为准）

**只读 profile**：`game-modifier-mcp --profile readonly` 只注册 **53 个只读工具**（剔除全部写操作工具），用于只读部署。

**输出限流**：单个返回超过约 50000 字符会被截断成预览（`data.totals` 保留原始条数，附 `preview_note`）；`name_get` / `backup_list` / `sessions` 的列表字段超 1000 条也会截断（常量 `MAX_OUTPUT_CHARS` / `LIST_DEFAULT_LIMIT`）。

**审计日志**：写操作追加到 `sessions/<id>/audit.jsonl`，`audit_tail` 工具回读。

**FastMCP 兼容层**：`mcp_server.py` 的 `_import_fastmcp()` 按顺序尝试 **4 个导入路径**，取第一个成功者：

1. `mcp.server.fastmcp`（mcp v1.x 官方位置）
2. `mcp.server`（较新 mcp 版本的 re-export）
3. `mcp`（可能的 mcp v2.x 顶层导出）
4. `fastmcp`（独立 FastMCP 2.x 包）

全部失败时抛 `ModuleNotFoundError`，`main()` 捕获后向 stderr 输出明确的安装提示（`pip install game-modifier[mcp]` 或 `pip install mcp`）并返回退出码 1。`pyproject.toml` 中的依赖约束为 `mcp>=1.0`，因此 mcp v1.x / v2.x / 独立 fastmcp 包均可驱动本服务器。导入是**延迟**的（只在 `build_server()` 中调用），保证未安装 mcp 时包的其余部分与测试不受影响。

### 插件资产

| 目录 | 内容 |
| --- | --- |
| `.claude-plugin/plugin.json` | Claude Code 插件清单 |
| `commands/*.md` | 9 个斜杠命令（attach/analyze/scan/modify/nl/template/batch/toolchain/ue） |
| `agents/game-modder.md` | 专用子 agent 定义 |
| `skills/game-modifier/SKILL.md` | 技能说明 |
| `hooks/hooks.json` + `pre_write_guard.py` + `session_notice.py` | 写入前护栏与会话提示钩子 |

### 运行时目录

```
~/.game-modifier/
├── config.toml                       # 用户配置（可选）
├── sessions/
│   ├── <session_id>.json             # 会话状态
│   └── <session_id>/
│       ├── backups/*.json            # 原始字节备份
│       └── freeze.pid                # 后台冻结进程 PID
└── templates/*.yaml                  # 用户自定义模板
```

---

## 9. 故障排除

### 常见问题

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| `E_ACCESS_DENIED` | 权限不足 / 目标为 64 位而 Python 为 32 位 | 用管理员终端；确保 Python 位数与游戏一致 |
| `E_ANTI_CHEAT` | 检测到反作弊 | **停止操作**。本工具只支持单机离线游戏，不要绕过 |
| `E_PROCESS_EXITED` | 游戏已退出，session 中的 pid 失效 | 重新 `attach` 获取新 session |
| `E_INVALID_ARGS` + `candidates` | 同名多进程 | 用 `--pid` 精确指定 |
| `E_NEEDS_SCAN` | 字段未映射到符号 | 按 `details.next` 给出的参数 `scan` → `name set` |
| `E_SYMBOL_NOT_FOUND` | 符号未定义 | `name set` 定义，或改用 `--address` |
| `E_UNSUPPORTED_OS` | 非 Windows 平台 | 本版本仅支持 Windows |
| `E_TOOL_NOT_FOUND` | 逆向工具未安装/未配置 | 装工具或在 `~/.game-modifier/config.toml` 的 `[tools]` 下写绝对路径 |
| 修改无效果 | 命中的是副本地址；游戏每帧回写 | 用 `--freeze` + `freeze start`；或用指针链定位稳定地址 |
| 扫描结果过多 | 首次扫描候选未收敛 | 游戏内改变数值后 `scan-next`（`changed`/`increased`/`decreased`）反复收敛 |
| `truncated: true` | 结果超 `max_results` | 提高 `scan.max_results` 或用更精确的初始值 |
| `dry_run: true` 未写入 | 未加 `--confirm` | 这是**有意的**默认行为，确认后加 `--confirm` |
| 指针解析报 `E_INVALID_POINTER` | 某级指针为空/无效 | 检查返回中的中间步骤；游戏可能尚未初始化该结构 |
| 后台冻结未生效 | 未 `freeze start`，或 worker 已退出 | `freeze list` 确认注册项，`freeze start` 拉起，必要时 `freeze stop` 后重启 |

### 错误码速查（40 个）

| 分组 | 错误码 | Agent 应采取的动作 |
| --- | --- | --- |
| 进程/会话 | `E_PROCESS_NOT_FOUND` | 确认游戏已启动，重试定位 |
| | `E_ACCESS_DENIED` | 提示用户用管理员权限 |
| | `E_SESSION_NOT_FOUND` | 重新 `attach` |
| | `E_PROCESS_EXITED` | 重新 `attach` |
| 安全 | `E_ANTI_CHEAT` | **停止**，不要重试 |
| | `E_NOT_CONFIRMED` | 补 `--confirm` |
| | `E_DRY_RUN` | 信息性，非硬失败 |
| 内存 | `E_INVALID_ADDRESS` | 重新 scan 或 resolve |
| | `E_ADDRESS_NOT_WRITABLE` | 检查目标区域；可能需要指针链 |
| | `E_READ_FAILED` / `E_WRITE_FAILED` | 检查进程存活与权限 |
| | `E_INVALID_TYPE` | 从 `details.supported` 选合法类型 |
| | `E_VALUE_OUT_OF_RANGE` | 换更宽的类型或调小数值 |
| | `E_INVALID_POINTER` | 检查偏移链 |
| 解析 | `E_NEEDS_SCAN` | 按 `details.next` 扫描后 `name set` |
| | `E_SYMBOL_NOT_FOUND` | `name set` 或改用 `--address` |
| | `E_NLP_UNRESOLVED` | 换更明确的措辞，或直接用 `modify` |
| 工具/引擎 | `E_TOOL_NOT_FOUND` | 读 `install_hint` 安装或配路径 |
| | `E_TOOL_FAILED` | 检查工具版本与输入文件 |
| | `E_ENGINE_UNKNOWN` | 回落到通用 `scan` 流程 |
| 模板/批处理 | `E_TEMPLATE_NOT_FOUND` | `template list` 查看可用模板 |
| | `E_TEMPLATE_INVALID` | 修正 YAML schema |
| | `E_BATCH_ERROR` | 检查批处理文件路径与结构 |
| | `E_BACKUP_NOT_FOUND` | `backup list` 查看可用 ID |
| 存档修改 | `E_SAVE_EDIT_REQUIRED` | 改用 `save-edit detect` → `save-edit modify` |
| | `E_SAVE_FORMAT_UNSUPPORTED` | 压缩/pickle 存档暂不支持，勿重试 |
| 扫描/分析 | `E_PATTERN_NOT_FOUND` | 放宽 AOB 模式或确认目标已加载 |
| | `E_LAYOUT_UNSUPPORTED` | 回落到通用 `scan`，或换一种 `layout --what` |
| | `E_SCAN_TIMEOUT` | 缩小范围 / 降低 `--max-depth`，或调高 `[analysis] scan_timeout` |
| | `E_SCAN_CACHE_STALE` | 区域布局变了，重新执行全新 `scan` |
| 通用 | `E_UNSUPPORTED_OS` | 无解，仅 Windows |
| | `E_INVALID_ARGS` | 按 `details` 修正参数 |
| | `E_DEPENDENCY_MISSING` | `pip install .[<extra>]` |
| | `E_INTERNAL` | 提 issue，附完整 JSON |

---

## 10. 维护建议

### 代码风格

- 全文件启用 `from __future__ import annotations`，类型注解用 PEP 585/604 风格（`list[int]`、`Optional[X]`）
- 数据模型统一用 `@dataclass`，一律提供 `to_dict()`（并在需要持久化时提供 `to_json`/`from_json`）
- **模块级 docstring 必写**，说明该模块在整体架构中的位置与设计约定（现有代码全部遵循，这是本项目最有价值的自文档特性）
- 公开函数使用**关键字参数**（`def modify(self, *, session_id, symbol=None, ...)`），避免位置参数误用
- 错误一律抛 `GameModifierError` 子类并带 `code` / `details` / `hint`；**绝不**让裸异常穿透到表现层
- 章节分隔注释风格：`# =========== attach`
- 不引入新的重量级运行时依赖；可选功能放 `[project.optional-dependencies]` 并保证缺失时优雅降级

### PR 检查清单

- [ ] `pytest tests/ -q` 全绿（290+ 用例）
- [ ] 新增/修改逻辑有对应测试；内存相关逻辑通过 `FakeBackend` 覆盖
- [ ] 覆盖率不低于 72%（`--cov=game_modifier`）
- [ ] `python -m pyflakes src/game_modifier` 无告警
- [ ] 新错误情况**追加**（不修改）`ErrorCode`，并带 `details` / `hint`
- [ ] 新功能**先落 `service.py`**，再在 `cli.py` 与 `mcp_server.py` 两处同步暴露
- [ ] 写操作默认 dry-run，`confirm` 才落盘；`auto_backup` 逻辑未被绕过
- [ ] 反作弊拦截逻辑未被削弱
- [ ] 版本号在 `pyproject.toml` 与 `__init__.py` 两处同步
- [ ] 新增 YAML 模板通过 `loader.py` 的 schema 校验，并有测试
- [ ] 输出仍是单行 JSON（token 契约），未混入 print 调试语句
- [ ] 涉及 CLI 变更时同步更新 `commands/*.md` 与 `AGENTS.md`

### 已知限制

1. **仅 Windows**：Linux（`process_vm_readv`/ptrace）与 macOS（mach vm）后端未实现，接口已预留
2. **无汇编级修改**：不支持代码注入、hook、nop 指令，只做数据内存读写
3. **freeze 为轮询实现**：虽已支持自适应间隔，仍是轮询回写（非 hook），对高频回写的游戏可能出现短暂闪回
4. **变长类型能力弱**：`string` / `bytes` 不支持范围与增量比较器
5. **多进程同名游戏**需手工 `--pid` 区分
6. **模板依赖预先映射的符号**，无法自动定位地址
7. **指针反查为启发式**：`pointer-scan` 结果带置信度，深度受 `[analysis] pointer_scan_max_depth` 限制，复杂多级指针仍可能需外部工具辅助

### 改进方向

**近期（低风险、高收益）**

- 继续提升 `mcp_server.py` 覆盖率（57% → 80%+），补齐只读 profile 与输出限流的边界分支
- 提升 `service.py` 覆盖率（69% → 85%+），重点是 freeze 生命周期、template apply 的 missing_symbols 分支、batch 的错误传播
- CI（GitHub Actions）：Windows runner 上跑 pytest + pyflakes + 覆盖率门禁

**中期**

- Linux 后端（`process_vm_readv` + `/proc/<pid>/maps`），验证 `MemoryBackend` 抽象的正确性
- 模板生态：更多游戏类型 + 社区模板分发机制
- 深化布局分析：结合引擎元数据提升 class/heap 推断准确率

**长期**

- frida 集成落地（`[frida]` extra 已预留），支持函数 hook 与动态追踪
- 结构体识别与自动字段推断（结合 Il2Cpp/UE dump 元数据）
- 冻结机制改用 hook 而非轮询，消除闪回

---

## 11. 已知问题

### 11.1 `engines/__init__.py` 名称遮蔽 — ✅ 已修复

**问题**：`engines` 包最初只 `from .detect import detect, ...`，而 `detect.py` 与被导入的 `detect` 函数同名。当外部写 `engines.detect` 时，得到的是**函数**还是**模块**取决于 `sys.modules` 中子模块是否已被加载，行为不确定；同样 `engines.unity` / `engines.unreal` 在未被显式导入时不可用。

**修复**：`engines/__init__.py` 现在显式 `from . import unity` / `from . import unreal`，并把 `"unity"` / `"unreal"` 一起列入 `__all__`，使子模块访问确定可用；`engines.detect` 明确解析为函数（`service.py` 中 `engines.detect(target=..., modules=...)` 即依赖此语义）。

**维护提醒**：向 `engines` 包新增子模块时，必须同时在 `__init__.py` 里显式导入并加入 `__all__`；避免让子模块名与导出的函数名冲突。

### 11.2 `memory/windows.py` 跨平台导入

**问题**：`windows.py` 在模块顶层使用 `ctypes.windll`，在非 Windows 平台导入即会失败。

**当前设计**：`memory/base.py` 的 `get_backend()` 采用**延迟导入**——只有 `sys.platform.startswith("win")` 成立时才 `from .windows import WindowsMemoryBackend`，否则抛 `UnsupportedOSError`。因此 `memory` 包本身在任何平台都能安全导入，测试可以在非 Windows 上跑（借助 `FakeBackend`）。

**残留影响**：`windows.py` 覆盖率仅 29%，其 ctypes 分支只能在真实 Windows 进程上验证；直接 `import game_modifier.memory.windows` 在非 Windows 上仍会失败。

**维护提醒**：任何新增的平台后端都必须遵循同样的延迟导入约定，不要在 `memory/__init__.py` 或 `base.py` 顶层直接 import 平台特定模块。

### 11.3 `mcp_server.py` 测试覆盖

**现状**：`mcp_server.py`（1,477 行）覆盖率 **57%**，由 `tests/test_mcp_extended.py` 等覆盖（输出限流、`value_convert`、readonly profile、各 handler 契约）。相比上一版本的 0% 已有实质改善。

**剩余风险**：依赖可选 `mcp` 包的部分导入路径与 `server.run()` 仍未覆盖；MCP 工具签名若与 `ModifierService` 漂移仍需契约测试兜底。

**建议**：
1. 继续用 `pytest.importorskip("mcp")` 保护，补齐只读 profile 与限流边界分支
2. 维持契约测试：断言 MCP 暴露的 83 个工具名与 `ModifierService` 的公开方法一一对应，防止签名漂移
3. 覆盖 `session_survey` / `audit_tail` / `layout_analyze` / `heap_scan` / `pointer_scan` 等新工具的服务层联动

### 11.4 其他需关注点

- **`session.py` 的 `ScanState.values` 键类型**：JSON 不支持 int 键，`to_json`/`from_json` 做了 str↔int 转换。手工编辑 session 文件或改动该结构时极易踩坑。
- **`freeze.pid` 陈旧残留**：若后台 worker 被强杀，PID 文件可能残留。`freeze_start` 会用 `process_exists()` 校验后再决定是否复用，但 PID 复用极端情况下仍可能误判。
- **`SessionStore.delete()` 只删文件不删空目录**：`sessions/<id>/` 目录在清空 backups 后仍会留下空壳。
- **配置文件缺失时的静默行为**：`load_config()` 对 `~/.game-modifier/config.toml` 与 `$GAME_MODIFIER_CONFIG` 不存在的情况静默跳过（仅 `--config` 显式路径会报错）。用户拼错环境变量路径时不会得到任何提示。
