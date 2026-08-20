# 游戏修改器 — AI Agent 集成指南

> 适用版本：game-modifier 0.1.0（Windows 单机 / 离线游戏）
> 本文所有命令、参数、错误码均来自源码（`src/game_modifier/cli.py`、`mcp_server.py`、`errors.py`、`service.py`）。

---

## 1. 概述

### 1.1 目标读者
本文面向 **AI Agent 开发者 / 集成者**：需要让 Claude Code、Codex CLI 或自研 Agent 驱动
`game-modifier` 完成"定位内存值 → 修改 → 锁定 / 还原"的自动化流程。人类使用说明请看
`USER_MANUAL.md`。

### 1.2 两种接入方式

| 方式 | 入口 | 适用场景 |
| --- | --- | --- |
| **CLI** | `game-modifier <子命令>` | 任何能执行 shell 的 Agent（Bash 工具即可） |
| **MCP 服务器** | `game-modifier-mcp`（stdio） | 支持 MCP 的 Agent，结构化工具调用，推荐 |

两者都是 `ModifierService` 的薄封装，**行为完全一致**：同一份会话文件、同一份安全策略、
同一份 JSON 结构。可以混用（先用 CLI attach，再用 MCP 工具复用同一个 `session_id`）。

### 1.3 设计理念
- **Token 高效**：attach 一次拿到 `session_id`，后续调用只传 id，不再重复传进程 / 模块表；
  符号表让 Agent 用 `player.gold` 代替裸指针链；模板 / 批处理把多次修改压缩成一次调用。
- **确定性**：中文 NLP 层是纯词典 + 正则（`nlp/lexicon.py`），不需要 Agent 二次推理；
  同样的输入永远得到同样的解析结果。
- **结构化输出**：每次调用返回一个固定形状的 JSON 信封，错误带**稳定错误码**，
  Agent 可以直接 `switch(error.code)` 分支，不用解析自然语言。

---

## 2. 安装和配置

### 2.1 安装

```bash
pip install -e .          # 基本安装（提供 game-modifier / game-modifier-mcp 两个可执行入口）
pip install -e .[all]     # 常用完整组合（+ r2pipe、mcp、numpy、capstone、pycryptodome、pytest；不含 frida）
```

按需安装可选分组：`.[radare2]`（r2pipe）、`.[mcp]`（MCP 服务器）、`.[speed]`（numpy 扫描加速）、
`.[disasm]`（capstone 反汇编）、`.[crypto]`（pycryptodome，Unity 加密存档）、`.[frida]`（动态插桩）、
`.[dev]`（pytest）。

> Windows 是本版本支持的目标平台；attach 到部分游戏进程需要**以管理员身份**运行终端
> （`attach` 返回的 `is_admin` 字段可用于判断）。

### 2.2 Claude Code 配置

本仓库已自带配置，克隆后无需手写：

- `.mcp.json` —— MCP 服务器声明：

```json
{
  "mcpServers": {
    "game-modifier": {
      "command": "game-modifier-mcp",
      "args": [],
      "description": "game-modifier structured tools (attach/scan/modify/nl/template/batch/...) over MCP."
    }
  }
}
```

- `.claude-plugin/plugin.json` —— 插件清单，把以下资源一次性挂载：
  - `commands` → `./commands`（`/attach`、`/scan`、`/modify`、`/nl`、`/template`、`/batch`、`/analyze`、`/toolchain` 斜杠命令）
  - `agents` → `./agents`（`game-modder` 子 Agent）
  - `hooks` → `./hooks/hooks.json`（写操作前置守卫、会话提示）
  - `mcpServers` → `./.mcp.json`
- `skills/game-modifier/SKILL.md` —— Skill 定义，供 Agent 自动按场景加载工作流说明。

### 2.3 Codex CLI 配置

在 `~/.codex/config.toml` 中追加：

```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = []
```

若只用 CLI（不走 MCP），把本仓库的 `AGENTS.md` 留在项目根目录即可，Codex 会自动读取。

### 2.4 运行时配置（可选）

配置优先级：`--config <path>` > `$GAME_MODIFIER_CONFIG` > `~/.game-modifier/config.toml` > 包内默认值。
关键项（见 `config/default.toml`）：

```toml
[safety]
dry_run = true                 # 写操作默认模拟
block_anti_cheat = true        # 检测到反作弊时拒绝 attach
auto_backup = true             # 每次真实写入前自动备份原始字节
require_writable_region = true
max_write_bytes = 4096         # 单次写入上限
# allowed_paths = ["D:/mods"]  # 文件类工具的额外放行根目录（智能默认已含游戏目录/
                               # sessions 目录/常见存档位置；系统目录硬拒绝）

[scan]
max_results = 20000            # 首次扫描保留的候选上限
chunk_size = 4194304
alignment = 4                  # 对齐字节数；默认 4 适配常见 dword 场景

[output]
format = "json"                # json | json-pretty | human

[tools]
radare2 = ""                   # 留空则自动探测；也可显式指定 x64dbg/cdb/il2cppdumper/ue4ss/il_tool 等
```

MCP 服务器同样接受 `--config <path>` 启动参数（写在 `args` 里）。

---

## 3. CLI 调用方式

### 3.1 全局选项

| 选项 | 说明 |
| --- | --- |
| `--format {json,json-pretty,human}` | 输出格式，默认取配置里的 `output.format`（出厂为 `json`） |
| `--json` | `--format json` 的简写（也是默认行为） |
| `--config PATH` | 指定 TOML 配置文件 |
| `--version` | 打印版本信封后退出 |

> **必须放在子命令之前**。`game-modifier --format json-pretty scan --session <id> ...` 正确；
> `game-modifier scan --session <id> --format json-pretty` 会被 argparse 拒绝（退出码 2）。

### 3.2 JSON 输出格式（Result Envelope）

成功：

```json
{"ok": true, "command": "modify", "data": {"address_hex": "0x1a2b3c", "type": "int32", "old_value": 100, "new_value": 9999, "applied": true, "backup_id": "bak-3f9c1a2b7d"}}
```

失败：

```json
{"ok": false, "command": "modify", "error": {"code": "E_SYMBOL_NOT_FOUND", "message": "symbol not defined: 'player.gold'", "hint": "Define it with `name set`, or pass an explicit --address.", "details": {"symbol": "player.gold", "known": []}}}
```

字段约定：
- `ok`：布尔，是否成功。
- `command`：命令名。子命令带命名空间，如 `name.set`、`template.apply`、`batch.run`、
  `freeze.start`、`backup.restore`、`toolchain.detect`、`save-edit.detect`、`save-edit.modify`；顶层命令为 `attach`、`analyze`、
  `scan`、`scan-next`、`read`、`modify`、`resolve`、`nl`、`sessions`、`session`、`detach`。
- `data`：成功时的负载（永不为 `null`，最少是 `{}`）。
- `error.code` / `error.message` / `error.hint`(可选) / `error.details`(可选)。
- `warnings`：可选字符串数组（例如目标区域不可写、扫描结果被截断）。

> **优先按 `error.hint` 行动**：所有关键错误码现在都带**可执行的下一步指令**（`hint` 字段），
> 面向 Agent 直接给出该跑哪条命令。遇到错误时先读 `hint` 再决定分支；`details` 提供补充上下文
> （如已定义符号、已知模块、建议参数）。显式上下文的 `hint`（如具体地址格式、具体符号名）优先于类级默认值。
> 关键码覆盖：`E_INVALID_ADDRESS`、`E_SCAN_TIMEOUT`、`E_PROCESS_EXITED`、`E_NEEDS_SCAN`、
> `E_SYMBOL_NOT_FOUND`、`E_LAYOUT_UNSUPPORTED`、`E_ANTI_CHEAT`、`E_TOOL_NOT_FOUND`、
> `E_DEPENDENCY_MISSING`、`E_PATTERN_NOT_FOUND`、`E_SAVE_FORMAT_UNSUPPORTED`。

**重要细节**：`modify` / `nl` / `template.apply` / `batch.run` 的 `data` 内部还有一个
自己的 `ok` 字段。外层 `ok:true` 只表示"命令执行完成"，业务结果要看 `data.ok`
（例如 `nl` 解析出 `unlock` 意图时返回 `{"ok": true, "data": {"ok": false, "error": {"code": "E_NEEDS_SCAN", ...}}}`）。
Agent 应同时检查两层。

### 3.3 退出码

| 码 | 含义 |
| --- | --- |
| `0` | 成功（`ok: true`） |
| `1` | 业务错误（`ok: false`，`error.code` 有效）；MCP 服务器缺少 `mcp` 包时也返回 1 |
| `2` | 参数错误 / 未给子命令（argparse 用法错误，此时输出的是帮助文本而非 JSON） |

> 注意：只有退出码 2 的 argparse 用法错误不是 JSON。其余错误（包括配置文件错误、
> 内部异常）都会被包成 JSON 信封并返回 1。

### 3.4 命令语法示例（每行一条，可直接复制）

```bash
game-modifier attach --process game.exe
game-modifier attach --pid 12345
game-modifier attach --exe "D:\Games\game\game.exe"
game-modifier attach --title "冒险物语.*"
game-modifier analyze --session <id> --deep
game-modifier scan --session <id> --type int32 --value 100
game-modifier scan --session <id> --type int32 --value 100 --progress   # 逐区域进度打到 stderr
game-modifier scan --session <id> --type float --comparator between --value 1.0 --value2 10.0
game-modifier scan-next --session <id> --value 80
game-modifier scan-next --session <id> --comparator decreased
game-modifier scan-aob --session <id> --pattern "48 8B ?? ?? 05"
game-modifier layout --session <id> --what vtables
game-modifier layout --session <id> --what class --address 0x1A2B3C40
game-modifier pointer-scan --session <id> --address 0x1A2B3C40 --max-depth 3
game-modifier pointer-scan --session <id> --address 0x1A2B3C40 --rescan
game-modifier pointer-scan --session <id> --address 0x1A2B3C40 --async --max-depth 4   # 后台任务，立即返回 job_id
game-modifier pointer-scan --session <id> --address 0x1A2B3C40 --async --timeout 300   # 可选墙钟上限（秒）
game-modifier job status <job_id> [--session <id>]
game-modifier job list [--session <id>]
game-modifier job cancel <job_id>
game-modifier dissect --session <id> --address 0x1A2B3C40
game-modifier dissect --session <id> --addresses "0x1A2B3C40,0x1A2B3C80,0x1A2B3CC0" --size 512
game-modifier find-writers --session <id> --address 0x1A2B3C40 --size 4 --duration 5 --max-hits 20
game-modifier disasm --session <id> --address 0x1A2B3C40 --size 256 --arch x64
game-modifier disasm --session <id> --address "game.exe+0x1A2B0" --blocks
game-modifier watch run --session <id> --address 0x1A2B3C40 --type int32 --iterations 100
game-modifier watch start --session <id> --address 0x1A2B3C40 --interval 0.05
game-modifier watch report --session <id> --limit 20
game-modifier watch stop --session <id>
game-modifier xrefs --session <id> --address 0x1A2B3C40 --direction to
game-modifier ue introspect --session <id> --gobjects "Game.exe+0x1D2E500" --gnames "Game.exe+0x1C9A380"
game-modifier ue actors --session <id> --limit 100
game-modifier ue actors --session <id> --class Player --list
game-modifier ue fname --session <id> --address 0x2A4C8810D40
game-modifier ue fname --session <id> --index 1234 --compare-index 1235
game-modifier read --session <id> --symbol player.gold
game-modifier read --session <id> --address 0x1A2B3C40 --type int32
game-modifier read --session <id> --address "0x1b0c00276c5-0x8" --type int32   # address arithmetic (only +/-)
game-modifier name set player.gold --session <id> --base 0x1A2B3C40 --type int32
game-modifier name set player.hp --session <id> --base "GameAssembly.dll+0x1234" --offsets "0x10,0x20" --type int32
game-modifier name set probe.tmp --session <id> --base 0x1A2B3C40 --temp              # 临时符号
game-modifier name chain mgr --session <id> --base "Game.exe+0x1A4" --offsets "0x10,0x28,0x0"   # 注册 mgr.step0..N 中间符号（默认临时）
game-modifier name chain mgr --session <id> --base "Game.exe+0x1A4" --offsets "0x10,0x28,0x0" --persist   # 中间符号持久化
game-modifier name clear-temp --session <id>                                          # 清除全部临时符号
game-modifier name get --session <id>
game-modifier resolve --session <id> --pointer "GameAssembly.dll+0x1234,0x10,0x20"
game-modifier resolve --session <id> --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain            # 结构体字段链（offset+deref）
game-modifier resolve --session <id> --base 0x200000 --offsets "0x10,0x20,0x08" --mode field_chain --no-deref-last   # 值类型字段：停在字段地址
game-modifier modify --session <id> --symbol player.gold --value 9999
game-modifier modify --session <id> --symbol player.health --value max --confirm --freeze
game-modifier modify --session <id> --address 0x1A2B3C40 --type float --value 9.0 --confirm
game-modifier nl --session <id> "将金币设为9999" --confirm
game-modifier template list
game-modifier template show rpg
game-modifier template apply --session <id> --template rpg --option set_gold --param amount=99999 --confirm
game-modifier batch run --session <id> samples/example_batch.yaml --confirm
game-modifier batch run --session <id> big_ops.yaml --confirm --offset 20 --limit 20   # 分页内联结果，完整结果读 results_file
game-modifier macro define set_gold --session <id> --file gold_macro.yaml [--description TEXT]   # 或 --inline "<YAML>"
game-modifier macro list --session <id>
game-modifier macro show set_gold --session <id>
game-modifier macro run set_gold --session <id> --params amount=99999 [--confirm] [--no-stop-on-error]
game-modifier macro delete set_gold --session <id>
game-modifier freeze list --session <id>
game-modifier freeze start --session <id> --interval 0.05
game-modifier freeze stop --session <id>
game-modifier freeze clear --session <id>
game-modifier backup create --session <id> --symbol player.gold --label before-edit
game-modifier backup list --session <id>
game-modifier backup restore --session <id> <backup_id>
game-modifier save-edit detect --session <id>
game-modifier save-edit modify --session <id> --path "D:\Games\game\save\file1.rmmzsave" --field gold --value 99999 --confirm
game-modifier toolchain detect
game-modifier sessions
game-modifier session <id>
game-modifier session snapshot before-experiment --session <id>   # 会话状态打快照
game-modifier session snapshots --session <id>                    # 列出快照
game-modifier session restore before-experiment --session <id>    # 恢复（先自动归档当前状态为 .pre-restore）
game-modifier detach <id>
game-modifier --format json-pretty analyze --session <id>
```

---

## 4. MCP 服务器方式

### 4.1 工具列表（默认 profile，来自 `mcp_server.py`）

精确工具总数与逐组成员**以运行时调用 `tools_catalog` 返回为准**（不写死数字以免漂移）；下表按功能域给出结构概览：

| 分类 | 工具 |
| --- | --- |
| 会话 | `attach`, `sessions`, `session_info`, `session_survey`, `session_snapshots`（只读）, `session_snapshot` / `session_restore`（可写 profile；恢复前自动归档当前状态为 `<名>.pre-restore.json`）, `session_notes`（`action=get` 全 profile 只读；`set` / `delete` 需非 readonly profile，存 `sessions/<id>/notes.jsonl`）, `detach` |
| 分析 | `analyze`, `toolchain_detect`, `layout_analyze`, `heap_scan`, `pointer_scan`（可选参数 `rescan: true` 验证已保存路径；`async_run: true` + 可选 `timeout` 秒提交后台任务）, `dissect`（结构体解剖，只读）, `disasm`（只读，需 capstone）, `xrefs`（只读；`aligned` 默认 true；radare2 缺失时纯 Python 兜底，`data.backend` 标注后端） |
| 后台任务 | `job_status`（`job_id` + 可选 `session`，只读）, `job_list`（可选 `session`，只读）, `job_cancel`（可写 profile） |
| UE 内省（只读） | `ue_introspect`, `ue_actors`, `ue_fname` |
| Unity Il2Cpp | `il2cpp_string`, `il2cpp_list`, `il2cpp_dict`, `il2cpp_lookup`（均只读）；`il2cpp_dump`（运行外部 Il2CppDumper，可写 profile） |
| .NET IL（il 组） | `il_analyze`, `il_dump`, `il_callers`, `il_verify`（只读）；`il_patch`, `il_backup`, `il_restore`（可写 profile，patch 前自动文件备份）。走随包分发的 il-tool 子进程（需 .NET 8 运行时；默认以常驻 `--serve` worker 复用进程，崩溃自动重启、闲置 300s 回收；`il_analyze` 全量枚举按程序集指纹缓存，游戏更新后自动失效重跑） |
| Mono 运行时（mono 组） | `mono_string`, `mono_list`, `mono_dict`, `mono_static`, `mono_heap_scan`, `mono_symbol`（全部只读、全 profile）；`mono_dump`（可写 profile，产物指纹缓存复用） |
| 定位 | `scan`（`offset` / `limit` 分页、`min_addr` / `max_addr` / `region_types` 区域过滤、`encoding=utf8|utf16le`；返回 `region_summary` / `candidates_total` / `candidates_file` / `results_file` / `page`）, `scan_next`（`retain_stale`）, `scan_aob`（分页 + 区域过滤 + `stop_on_limit` + 并行）, `scan_candidates`（只读，分页浏览已持久化候选集，不重扫）, `read`, `resolve` |
| 监视 | `watch_run`（前台轮询，只读）, `watch_report`（读变化历史，只读）, `watch_start`（后台 worker，可写 profile）, `watch_stop`（可写 profile） |
| 写入定位 | `find_writers`（DR0-3 硬件写断点，会短暂挂起目标线程，需管理员，可写 profile） |
| 符号 | `name_set`（新增 `temp: true` 标记临时符号）, `name_get`, `name_chain`（遍历指针链并注册 `<名>.step0..N` 中间符号，链断裂保留已解析部分；默认 `temp: true`，`temp: false` 持久化）, `name_clear_temp`（清除全部临时符号）；后三者仅可写 profile |
| 修改 | `modify`, `nl`（高危目标——代码段/只读/未知区域——除 `confirm=true` 外还需 `confirm_code=true` 二级确认，与 batch/macro 语义一致；`template_apply` 遇高危目标逐项跳过并标 `skipped_reason`） |
| 宏 | `macro_list`, `macro_show`（只读）；`macro_define`（`definition` 为 YAML/JSON 字符串）, `macro_run`（`params` 为字典，`${param}` 代入后走批处理管道）, `macro_delete`（可写 profile） |
| 辅助 | `value_convert`（十进制/十六进制/字节/浮点位型互转与地址算术 +/-，不访问进程） |
| 模板 / 批处理 | `template_list`, `template_show`, `template_apply`, `batch_run`（`file` 或内联 `yaml` 二选一；`offset` / `limit` 分页内联结果；完整结果始终落盘到 `results_file`）, `batch_preview`（只读写前预检：逐项 risk 分级 + `estimated_write_bytes`，全 profile 可用） |
| 冻结 | `freeze_list`, `freeze_start`, `freeze_stop` |
| 备份 | 内存：`backup_create`, `backup_list`, `backup_restore`；外部文件（safety 组）：`file_snapshot`（sha256 + manifest + 审计）, `file_restore`（`confirm=true` 且游戏运行中时拒绝），均可写 profile |
| 存档修改 | `save_edit_detect`, `save_edit_modify` |
| 目录 | `tools_catalog`（列出全部工具分组与工具总数，任何 profile / 分组配置下都始终注册，用于挑选 `--groups`） |
| 审计 | `audit_tail` |
| 产物回读 | `results_read`（只读，全 profile 含 readonly；按 `offset` / `limit` 分页回读 `sessions/<id>/` 内的落盘产物——溢出的大 dump、batch 完整结果、扫描 sidecar；越出会话目录报 `E_PATH_NOT_ALLOWED`） |
| 安全档位 | `safety_get_level`（只读，所有 profile 都注册，返回 `{level, source}`）、`safety_set_level`（切换运行时档位 `normal` / `dry_run_only`，仅 default profile） |

**多级工具 profile（`--profile`）**：`game-modifier-mcp --profile {default,readonly,dry-run,symbols,limited}` 五档：

| Profile | 工具数 | 允许的操作 |
| --- | --- | --- |
| `default` | 全部 | 全部工具（现有行为），含 `safety_set_level` |
| `readonly` | 只读子集 | 只读工具，不含 `modify` / `nl` / `name_set` / `name_chain` / `name_clear_temp` / `template_apply` / `batch_run` / `freeze_start` / `freeze_stop` / `watch_start` / `watch_stop` / `find_writers` / `backup_create` / `backup_restore` / `file_snapshot` / `file_restore` / `save_edit_modify` / `il2cpp_dump` / `il_patch` / `il_backup` / `il_restore` / `mono_dump` / `detach` / `job_cancel` / `macro_define` / `macro_run` / `macro_delete` / `session_snapshot` / `session_restore` / `session_notes` set/delete / `safety_set_level` |
| `dry-run` | 只读+写工具 | 只读 + 写工具强制 dry-run：写工具照常注册，但 `confirm=true` 被服务端拒绝（`E_PROFILE_RESTRICTED`），`confirm=false` 预览透传 |
| `symbols` | 只读+符号 | 只读 + `name_set` / `name_chain` / `name_clear_temp` / `session_snapshot` / `session_restore` / `macro_define` / `macro_delete`，不写游戏内存 |
| `limited` | 只读+单步写 | symbols + `modify` / `nl` 单步写（仍受 `max_write_bytes` 与写风险分级约束）；batch / freeze / template 批量写不注册 |

各档精确工具数以 `tools_catalog` 运行时返回为准。

UE 内省三工具、Unity il2cpp 解码四工具（`il2cpp_string` / `il2cpp_list` / `il2cpp_dict` / `il2cpp_lookup`）、任务查询二工具（`job_status` / `job_list`）、宏查看二工具（`macro_list` / `macro_show`）、快照列表（`session_snapshots`）以及 `disasm` / `xrefs` / `dissect` / `watch_run` / `watch_report` / `safety_get_level` 本身只读，所有 profile 都包含。保守部署建议直接用 `--profile dry-run`（agent 可预览不可写）或 `--profile symbols`（只整理符号表）。运行时安全档位与 profile 正交：`safety_set_level` / CLI `safety level --set dry_run_only|normal` 可进一步锁成“只允许预览”（见 7.6）。

**输出限流**：单个返回超过约 50000 字符会被截断成预览（列表只留前 N 项，`data.totals` 为原始条数，附 `preview_note`）；`name_get` / `backup_list` / `sessions` 的列表字段超 1000 条也会截断。**`batch_run` 例外**：超限时返回摘要 + 前 10 条 + `results_file` 提示（完整结果始终落盘 `sessions/<id>/batch_results/<时间戳>.json`），全量数据读该文件或用 `offset` / `limit` 分页重调，不要依赖预览。

### 4.2 调用方式和参数格式

参数是**具名 JSON 字段**（没有 `--` 前缀），会话参数统一叫 `session`：

```json
{"name": "attach",   "arguments": {"process": "game.exe"}}
{"name": "analyze",  "arguments": {"session": "<id>", "deep": true}}
{"name": "scan",     "arguments": {"session": "<id>", "type": "int32", "value": "100", "comparator": "exact"}}
{"name": "scan_next","arguments": {"session": "<id>", "comparator": "decreased"}}
{"name": "name_set", "arguments": {"session": "<id>", "name": "player.gold", "base": "0x1A2B3C40", "type": "int32"}}
{"name": "modify",   "arguments": {"session": "<id>", "symbol": "player.health", "value": "max", "confirm": true, "freeze": true}}
{"name": "nl",       "arguments": {"session": "<id>", "text": "将金币设为9999", "confirm": true}}
{"name": "template_apply", "arguments": {"session": "<id>", "template": "rpg", "option": "set_gold", "params": {"amount": "99999"}, "confirm": true}}
{"name": "batch_run","arguments": {"session": "<id>", "file": "samples/example_batch.yaml", "confirm": true, "stop_on_error": true}}
{"name": "batch_run","arguments": {"session": "<id>", "file": "big_ops.yaml", "confirm": true, "offset": 20, "limit": 20}}
{"name": "name_chain", "arguments": {"session": "<id>", "name": "mgr", "base": "Game.exe+0x1A4", "offsets": "0x10,0x28,0x0"}}
{"name": "resolve", "arguments": {"session": "<id>", "base": "0x200000", "offsets": "0x10,0x20,0x08", "mode": "field_chain", "deref_last": false}}
{"name": "name_clear_temp", "arguments": {"session": "<id>"}}
{"name": "macro_define", "arguments": {"session": "<id>", "name": "set_gold", "definition": "params: {amount: {required: true}}\noperations:\n  - modify: {symbol: player.gold, type: int32, value: ${amount}}"}}
{"name": "macro_run", "arguments": {"session": "<id>", "name": "set_gold", "params": {"amount": 99999}, "confirm": true}}
{"name": "session_snapshot", "arguments": {"session": "<id>", "name": "before-experiment"}}
{"name": "session_snapshots", "arguments": {"session": "<id>"}}
{"name": "session_restore", "arguments": {"session": "<id>", "name": "before-experiment"}}
{"name": "pointer_scan", "arguments": {"session": "<id>", "address": "0x1A2B3C40", "async_run": true, "timeout": 300}}
{"name": "job_status", "arguments": {"job_id": "<job_id>", "session": "<id>"}}
{"name": "job_list",   "arguments": {"session": "<id>"}}
{"name": "job_cancel", "arguments": {"job_id": "<job_id>"}}
{"name": "backup_restore", "arguments": {"session": "<id>", "backup_id": "<backup_id>"}}
{"name": "save_edit_detect", "arguments": {"session": "<id>"}}
{"name": "save_edit_modify", "arguments": {"session": "<id>", "file": "D:\\Games\\game\\save\\file1.rmmzsave", "field": "gold", "value": "99999", "confirm": true}}
{"name": "save_edit_modify", "arguments": {"session": "<id>", "file": "D:\\Games\\game\\player.sav", "field": "player.gold", "value": "99999", "key": "<密钥>", "iv": "<可选IV>", "confirm": true}}   # unity-encrypted 存档
```

返回值就是 3.2 节的同一个信封字典（`{"ok": ..., "command": ..., "data"|"error": ...}`），
其中 `command` 用下划线形式（`name_set`、`template_apply`、`batch_run`、`scan_next` …）。

### 4.3 与 CLI 的差异点

| 差异 | CLI | MCP |
| --- | --- | --- |
| 会话参数 | `--session <id>`（`session <id>` 为位置参数） | `session: "<id>"` |
| 进程选择 | `--process` / `--pid` / `--exe` / `--title`（互斥且必填） | `process` / `pid` / `exe` / `window_title`（都可空，但至少给一个，否则 `E_INVALID_ARGS`） |
| 确认写入 | `--confirm` | `confirm: true` |
| `modify` 的 value | 可省略（省略时沿用当前值） | **必填**（函数签名要求） |
| `resolve` | 支持 `--pointer "Mod.dll+0x10,0x8"` 一体式写法；`--deref-last/--no-deref-last` | 只有 `base` + `offsets`，需自行拆分；`deref_last: false`（可选，默认 true） |
| `batch_run` | `--continue-on-error`（取反后传入）；`--offset` / `--limit` | `stop_on_error: true/false`；`offset` / `limit`（同名） |
| `pointer_scan` 异步 | `--async` [--timeout N] | `async_run: true`（可选 `timeout` 秒）；轮询用 `job_status` / `job_list`，取消用 `job_cancel`（CLI `job status|list|cancel`） |
| `template_apply` 参数 | `--param k=v`（可重复） | `params: {"k": "v"}` |
| `save-edit modify` 文件参数 | `--path <file>` | `file: "<file>"` |
| 冻结 | `list/clear/run/start/stop` | 只有 `freeze_list` / `freeze_start` / `freeze_stop`（无 `clear`、无前台 `run`） |
| 版本 / 输出格式 | `--version`、`--format` | 无（始终返回结构化字典） |
| 失败表现 | 非零退出码 + JSON | 无退出码概念，错误一律进信封 `error` |
| 依赖 | 仅核心依赖 | 需要 `pip install game-modifier[mcp]`，否则进程启动失败并提示 |

### 4.4 `--groups` 启动参数：按需加载工具组（省 token）

每个工具的描述 + 参数 schema 都会在每次调用时占用上下文 token。默认启动注册全部工具组（向后兼容）；只用得到部分能力时用 `--groups` 只注册需要的组：

```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = ["--groups", "core,scan,modify,ue,jobs"]
```

11 个工具组：`core`、`scan`、`modify`、`analysis`、`ue`、`il2cpp`、`il`（il-tool 子进程，.NET IL 分析/补丁）、`mono`（Mono 运行时读取）、`jobs`、`macros`、`safety`（`safety_get_level` / `safety_set_level` / `file_snapshot` / `file_restore`）。每组精确成员与工具数以 `tools_catalog` 运行时返回为准（它在任何配置下都始终注册），各组成员详见 USER_MANUAL 5.5。

推荐组合：

| 场景 | `--groups` |
| --- | --- |
| UE 游戏 | `core,scan,modify,ue,jobs` |
| Unity il2cpp | `core,scan,modify,il2cpp,jobs` |
| Unity Mono | `core,scan,modify,mono,jobs` |
| .NET IL 补丁流 | `core,scan,il,safety,jobs` |
| 存档型（RPG Maker / Ren'Py） | `core,modify` |
| 纯逆向分析（不写入） | `core,scan,analysis`（再叠加 `--profile readonly`） |
| 宏驱动重复操作 | `core,modify,macros` |

未知组名会报 `ValueError` 并列出合法组名；`--groups` 与 `--profile readonly` 可叠加（readonly 在分组过滤之上再排除可写工具）。

---

## 5. 完整工作流程

### 5.1 基本流程：scan → modify

```
Step 1: game-modifier attach --process game.exe
        （多进程游戏可改用 --title "窗口标题模式" 按窗口标题匹配进程）
        → data.session_id（后续全部复用）、data.engine、data.anti_cheat、data.is_admin、
          data.save_edit（存档型游戏时含 required:true 提示，应转 5.5 流程）
Step 2: game-modifier analyze --session <id>              # 可选，了解引擎与 next_steps
Step 3: game-modifier scan --session <id> --type int32 --value 100     # 首次扫描
Step 4: 让玩家在游戏中改变这个值（消耗金币 / 受伤 …）
Step 5: game-modifier scan-next --session <id> --value 80              # 缩小候选
        （重复 Step 4~5，直到 data.count == 1）
Step 6: game-modifier name set player.gold --session <id> --base 0x<addr> --type int32
Step 7: game-modifier modify --session <id> --symbol player.gold --value 9999          # dry-run
        → data.status="dry_run_preview"（仅预览，未写入）+ data.risk
Step 8: game-modifier modify --session <id> --symbol player.gold --value 9999 --confirm
        → data.status="applied"（data.applied=true）、data.verified_value、data.backup_id
```

扫描要点：
- 首次扫描比较器：`exact`、`not_equal`、`gt`、`gte`、`lt`、`lte`、`between`（需 `--value2`）、`unknown`（全收）。
- `scan-next` 额外支持 `changed`、`unchanged`、`increased`、`decreased`（不需要 `--value`）。
- `string` / `bytes` 这类变长类型只支持 `exact`。
- 数值类型：`int8/uint8/int16/uint16/int32/uint32/int64/uint64/float/double/bool/string/string_utf16/bytes`，
  也接受别名（`int`、`dword`、`byte`、`short`、`long`、`qword` …）。
- 结果被 `scan.max_results` 截断时 `data.truncated=true`，应先缩小范围再继续。

### 5.2 自然语言流程

```
Step 1: game-modifier attach --process game.exe
Step 2: game-modifier nl --session <id> "将金币设为9999" --confirm
```

前提：该字段已在符号表里（`gold` 会自动尝试 `gold` / `player.gold` / `weapon.gold` /
`resource.gold`，以及任何叶子名等于 `gold` 的符号）。没有映射时抛 `E_NEEDS_SCAN`，
`error.details.next` 会直接给出该扫什么类型、什么值、之后 `name set` 什么名字。

可识别字段：`gold`、`gem`、`health`、`mana`、`stamina`、`move_speed`、`attack`、`defense`、
`ammo`、`level`、`exp`、`score`、`lives`、`skill_points`、`durability`、`attribute_points`。
可识别动作：设为（设为/改为/置为/set…）、增加、减少、无限（无限/无敌/锁定/冻结→自动 freeze）、
读取（查看/读取/get）、最大（拉满/满/max）、最小（清零/归零/min）、解锁（unlock → 引导用模板）。
数字支持阿拉伯数字、全角数字与中文数字（如"九千九百九十九"）。

### 5.3 模板流程

```
Step 1: game-modifier attach --process game.exe
Step 2: game-modifier template show rpg                    # 看清 option 与所需 symbol
Step 3: game-modifier template apply --session <id> --template rpg --option set_gold --param amount=99999 --confirm
```

内置模板与选项（`template list` 可查）：

| 模板 | 选项 |
| --- | --- |
| `rpg` | `infinite_health`, `infinite_mana`, `infinite_stamina`, `set_gold`(参数 `amount`), `set_level`(参数 `amount`), `max_attributes` |
| `action` | `infinite_health`, `infinite_ammo`, `no_reload`, `infinite_armor`, `one_hit_kill`, `infinite_grenades` |
| `strategy` | `infinite_money`, `infinite_resources`, `max_population`, `instant_build` |

模板引用的是**符号名**（如 `player.gold`、`weapon.ammo`），因此必须先 scan + `name set`；
`template apply` 会报告缺失符号，不会凭空猜地址。`strategy: freeze` 的目标在应用后需要
`freeze start` 才会持续生效。

### 5.4 批处理流程

一次调用完成多次修改（最省 token 的路径）。批处理文件（YAML）：

```yaml
# ops.yaml
confirm: true            # 文件级开关：会覆盖命令行的 --confirm（写 false 则强制 dry-run）
stop_on_error: true
operations:
  - nl: "将金币设为777"
  - modify:
      symbol: player.move_speed
      type: float
      value: 9.0
  - read:
      symbol: player.gold
```

```
Step 1: game-modifier attach --process game.exe
Step 2: game-modifier name set ... （把批处理里用到的符号都映射好）
Step 3: game-modifier batch run --session <id> ops.yaml            # 先 dry-run 看每一步
Step 4: game-modifier batch run --session <id> ops.yaml --confirm
```

每个 operation 必须**恰好**选一个动作键：`nl`、`modify`、`template`、`scan`、`scan_next`、
`read`、`resolve`、`name`、`backup`。返回汇总：`total`、`executed`、`ok_count`、
`error_count`、`stopped_early`、`results[]`（逐步结果，失败步骤带自己的 `error`）。
加 `--continue-on-error` 可在单步失败后继续（等价 MCP 的 `stop_on_error: false`）。

**结果持久化与分页**：完整结果始终落盘 `sessions/<id>/batch_results/<时间戳>.json`，
返回中的 `results_file` / `results_total` 指向它；`--offset` / `--limit`（MCP `offset` / `limit`）
只控制内联 `results` 窗口。结果多时不要试图一次拿全部：读 `results_file` 或分页重调。

### 5.5 存档型游戏修改流程

RPG Maker（MV/MZ）、Ren'Py 这类引擎把玩家数据存在**存档文件**里，内存地址不稳定，
attach 时会在 `data.save_edit` 中给出提示（形如 `{"required": true, "engine": "rpg-maker", "note": ...}`）。
此时应改走 save-edit，而不是 scan / modify：

```
Step 1: game-modifier attach --process Game.exe        # NW.js 多进程时改用 --title "窗口标题" 更可靠
        → data.save_edit.required == true → 走存档修改
Step 2: game-modifier save-edit detect --session <id>
        → data.saves[]（每条含 path、format、size、editable、reason）
Step 3: game-modifier save-edit modify --session <id> --path <存档路径> --field gold --value 99999
        → dry-run：old_value / new_value / applied:false
Step 4: game-modifier save-edit modify --session <id> --path <存档路径> --field gold --value 99999 --confirm
        → applied:true、backup（写入前自动生成的 .bak 路径）
```

要点：
- `--field` 支持点号路径（如 `party.gold`）；字段不存在时 `data.ok=false` 并给出 hint。
- 目前可直接修改 RPG Maker 的 JSON / base64 JSON 存档（`.rmmzsave` / `.rpgsave` / `.json`）；
  pako/zlib 压缩存档与 Ren'Py pickle 存档（`.save`）只支持 detect（`editable: false`），
  modify 会抛 `E_SAVE_FORMAT_UNSUPPORTED`。
- 修改前让玩家**退到标题界面或关闭游戏**，避免游戏在写入后覆盖存档；改完在游戏内读档验证。

**Unity 自定义加密存档分支（`unity-encrypted`）**：部分 Unity 单机游戏的存档是
`Base64( DES-CBC( JSON ) )`（常见 `*.sav` / `*.dat`）。`save-edit detect` 会将其标记为
`{"engine": "unity-encrypted", "editable": "with_key"}`：

```
Step 1: save-edit detect → saves[] 中出现 engine=unity-encrypted、editable=with_key
Step 2: 需要用户提供密钥（来自游戏代码逆向：il2cpp dump / 反编译中的硬编码字符串）；
        无密钥直接 modify 会报 E_INVALID_ARGS（hint 提示补 --key）
Step 3: save-edit modify --session <id> --path <存档> --field player.gold --value 99999 --key "<密钥>" [--iv <IV>]
        → dry-run 预览；确认后加 --confirm，写回前自动生成 .bak
```

要点：DES 密钥规整到 8 字节（UTF-8 取字节，不足补 0、过长取前 8）；IV 缺省等于密钥。
密钥错误/文件损坏报 `E_SAVE_FORMAT_UNSUPPORTED`（提示核对密钥或从 .bak 恢复）。
密钥仅作为调用参数传递，**不落盘**（不进 session JSON，也不进审计记录）。
需要可选依赖：`pip install "game-modifier[crypto]"`（缺失报 `E_DEPENDENCY_MISSING`）。
MCP 调用：`save_edit_modify` 追加可选 `key` / `iv` 参数。

### 5.6 UE 游戏修改流程（introspect → actors → modify）

Unreal 游戏的 UObject 都由 GObjects 统一管理；用 UE dumper（UE4 Dumper / UE4SS）拿到
GObjects / GNames 偏移后，走内省路线而不是盲扫。三个 `ue_*` 工具**全部只读**，无需 `confirm`：

```
Step 1: game-modifier attach --process ue_game.exe
Step 2: ue_introspect(session, gobjects="Game.exe+0x1D2E500", gnames="Game.exe+0x1C9A380")
        → data.verdict == "confirmed" 时布局写入会话 introspect 字段，后续调用直接命中缓存
          （data.cached == true）；force=true 可强制重探。pattern 参数只产出候选，不会自动采纳
Step 3: ue_actors(session, limit=100)                        → 默认返回按类聚合的 by_class 统计
        ue_actors(session, class_filter="Player", list_results=true) → 小范围内看逐条明细
Step 4: （可选）ue_fname(session, address=...) 或 ue_fname(session, index=N) 解码 / 校验 FName
Step 5: name set / name_set 把 Actor 实例或字段地址固化成符号
Step 6: modify / freeze 走常规写入流程（dry-run → confirm）
```

要点：
- `ue_actors` / `ue_fname(index)` 在没有缓存布局时抛 `E_LAYOUT_UNSUPPORTED`：先跑 `ue_introspect`，
  或给 `ue_actors` 显式传 `gobjects`（临时探测，不会覆盖缓存）。
- `ue_fname` 必须给 `address` 或 `index` 至少一个，否则 `E_INVALID_ARGS`；
  `index` + `compare_index` 按纯整数规则比较两个名字池索引。
- 探测 / 枚举受 `[analysis] scan_timeout` 时间预算限制，超时抛 `E_SCAN_TIMEOUT`；
  枚举规模上限由配置 `[ue]` 段（`max_objects` 等）控制。

### 5.7 Unity il2cpp 修改流程（dump → lookup → string/list/dict → modify）

Unity il2cpp 游戏的 .NET 对象（字符串 / List / Dictionary）有固定运行时布局，直接用
`il2cpp_*` 工具解码，不要手工拼字节。四个解码 / 反查工具**全部只读**，无需 `confirm`；
`il2cpp_dump` 会运行外部 dumper，仅可写 profile 提供：

```
Step 1: game-modifier attach --process unitygame.exe → engine == "unity-il2cpp"
Step 2: il2cpp_dump(session)                          → 按 metadata 版本自动选 dumper，script.json /
                                                          dump.cs 路径写入会话 engine artifacts
Step 3: il2cpp_lookup(session, rva="0x7ff6a12b8560-0x7ff69c432ef0", tolerance=256)
                                                      → RVA → 方法名（matched: exact/nearest/none）；
                                                        dump 后无需传 script_json
Step 4: il2cpp_string(session, address=...)           → Il2CppString 一次解码（value/length/truncated）
        il2cpp_list(session, address=..., elem_type="ptr")   → List<T> 元素（ptr 元素可再喂回 il2cpp_string）
        il2cpp_dict(session, address=...)             → Dictionary 条目的 key_ptr / value_ptr
Step 5: 按 dump.cs 的字段偏移 name set 固化符号，之后常规 modify / freeze（dry-run → confirm）
```

要点：
- 会话未关联 script.json 且未传 `script_json` 时，`il2cpp_lookup` 抛 `E_INVALID_ARGS`：
  先跑 `il2cpp_dump`，或显式传 `script_json` 路径。
- RVA 索引懒构建并缓存为 gzip sidecar（`script.json.idx`，按文件大小 + mtime 指纹失效），
  首次大 dump 稍慢，之后亚秒；`force_index=true` 强制重建。
- 解码工具地址给错不抛异常，返回 `ok=false` + `reason`；`reason` 提示布局可疑时，
  说明是魔改运行时，需走 Python API 的 `layout=` 覆盖（见 USER_MANUAL 4.25）。
- `il2cpp_dump` 未安装 dumper 时抛 `E_TOOL_NOT_FOUND`（提示安装 Il2CppDumper /
  il2cpp-dumper-rs 或在配置 `[tools]` 段设 `il2cppdumper` / `il2cppdumper_rs` 路径）。
- **转储验证**：`il2cpp_dump` 关联 artifacts 前验证产物（script.json 可解析 + 非空
  `ScriptMethod`；dump.cs 存在时非空）。返回 `ok=false` + `errors` 时说明转储损坏，
  产物不会被关联——修复 dumper 输出后重跑，不要手工指定损坏的 script.json。
- **游戏更新失效检测（stale_warning 响应策略）**：`il2cpp_dump` 成功时记录游戏二进制
  （GameAssembly.dll，找不到时用主 exe）指纹（大小 + mtime + 头部 64KB sha256）。
  之后 `il2cpp_lookup` 返回 `stale_warning`、或 `analyze` 返回 `dump_stale`，都表示
  游戏二进制已变化（大概率游戏更新过）：
  1. **不要继续信任旧 RVA / 旧 dump 结果**（非阻断提示，lookup 仍会返回匹配，但可能已失效）；
  2. 重跑 `il2cpp_dump`（指纹陈旧时会自动重转储并附 `previous_stale` 原因；
     也可显式 `force=true` / `--force` 强制重跑）；
  3. 新转储完成后再重新 `il2cpp_lookup`；`force=true` 的 lookup 只应在明知二进制
     未变、只想跳过检查时使用。
- **转储复用**：已有转储且指纹仍新鲜时，`il2cpp_dump` 直接返回 `reused=true`
  不重跑 dumper；需要强制重新转储时传 `force=true` / `--force`。

---

## 6. 主要命令详解

### attach — 附加进程
- 参数：`--pid N` | `--process name.exe` | `--exe <完整路径>` | `--title <窗口标题模式>`（四者互斥，必须给一个）、`--allow-anti-cheat`
- `--title` 按**窗口标题**匹配进程：大小写不敏感的正则（非法正则自动降级为子串匹配），
  适合 NW.js / RPG Maker 这类多进程、或进程名固定为 `nw.exe` / `Game.exe` 的游戏（MCP 对应参数名 `window_title`）
- 返回：`session_id`、`pid`、`process`、`arch`、`engine` + `engine_detail`、`anti_cheat`、
  `module_count`、`is_admin`、`symbols`、`scan_candidates`、`save_edit`（存档型游戏时含
  `required:true` 与提示语，应转用 save-edit，见 5.5）
- 同名进程 / 标题命中多个进程时抛 `E_INVALID_ARGS`，`details.candidates` 列出候选，改用 `--pid`
- 检测到反作弊且配置 `block_anti_cheat=true` 时抛 `E_ANTI_CHEAT`（`--allow-anti-cheat` 可强行覆盖，**不推荐**）

### analyze — 引擎与工具链分析
- 参数：`--session <id>`（可选）、`--target <exe或目录>`（无会话时使用）、`--deep`
- 返回：`engine`（`unity-il2cpp` / `unity-mono` / `unreal` / `nwjs` / `rpg-maker` / `renpy` / `webview` / 未知）、`toolchain.available`、
  `next_steps`；`--deep` 且装有 radare2 时附带 `static`（失败则为 `static_error`）
- 会话已关联 il2cpp 转储且记录了二进制指纹时，会校验游戏二进制新鲜度：陈旧时返回
  `dump_stale`（`reason` + 重跑提示，只提示不阻断）——应重跑 `il2cpp dump` 后再用旧 RVA
- NW.js / RPG Maker / Ren'Py 也带 `.pak` 文件（Chromium 资源包），检测层已做排除，
  不会再仅凭 `.pak` 误判为 Unreal

### scan / scan-next — 定位地址
- `scan`：`--session`(必填)、`--type`(默认 `int32`)、`--value`、`--comparator`(默认 `exact`)、`--value2`(用于 `between`)
- `scan-next`：`--session`(必填)、`--comparator`(默认 `exact`)、`--value`、`--value2`
- 返回：`type`、`comparator`、`count`、`truncated`、`addresses_hex`（仅前 20 个候选的十六进制样本）、
  `sample_values`（样本地址 → 当前值）、`scanned_regions`、`scanned_bytes`
- 完整候选集只保存在会话文件里（不回传，省 token），`scan-next` 基于上一次结果；
  没有上一次结果时抛 `E_NEEDS_SCAN`

### read — 读取当前值
- 参数：`--session`(必填)、`--symbol` 或 `--address`、`--type`、`--offsets "0x10,0x20"`
- 返回：`address_hex`、`type`、`value`、`symbol`

### modify — 写入值
- 参数：`--session`(必填)、`--symbol` 或 `--address`、`--type`、`--value`、`--offsets`、`--confirm`、`--freeze`
- `--value` 支持 `max` / `min` 特殊值；`--freeze --value max` 表示"锁在当前值"（真正的无限，不会被拉高到类型上限）
- dry-run 返回：`address_hex`、`type`、`old_value`、`new_value`、`bytes`、`applied:false`、`dry_run:true`、`status:"dry_run_preview"`、双语 `hint`、`risk`（目标区域风险：`normal` / `high`）
- 确认后返回：`applied:true`、`status:"applied"`、`bytes_written`、`verified_value`、`backup_id`、`risk`。**判定写入结果以 `status` 为准**
- `--freeze` 只是**注册**冻结项，需要 `freeze start`（后台）或 `freeze run`（前台）才会持续写入

### resolve — 解析指针链
- 参数：`--session`(必填)、`--base "Module.dll+0x1234"`、`--offsets "0x10,0x20"`，或用 `--pointer "Module.dll+0x1234,0x10,0x20"` 一次给全；`--mode {relative,pointer_chain,field_chain}`（默认 `pointer_chain`）；`--deref-last/--no-deref-last`（仅 field_chain，默认开）
- 两者都没给时返回 `E_INVALID_ARGS`
- 返回：`base_expr`、`offsets`、`mode`、`final_address`、`final_address_hex`、`trace`（逐级 `read_at_hex`/`deref_hex`/`offset_hex`/`address_hex`；field_chain 每步额外带 `op`：`offset+deref` 或 `offset`）
- **三种模式选择指南**（每步对 `addr` 做什么）：
  - `relative`：`addr = addr + offset`（仅加法）——已知绝对地址上的单层结构体字段偏移。
  - `pointer_chain`：`addr = read(addr) + offset`（先解引用再加偏移，CE 风格）——指针数组 / 链表等 `Module.dll+0x...` 指针路径。
  - `field_chain`：`addr = read(addr + offset)`（先加偏移再解引用）——**嵌套结构体字段链**（如 `gem.__data.MainPowerData.mPowerType`），一次调用走完，避免多次 `read` + 地址表达式手工步进；若解引用读到的总是 klass/vtable 之类无关指针，说明用错了模式，应改 field_chain。
  - **值类型字段**（int/float 本身即目标值）：`--mode field_chain --no-deref-last` 停在字段地址，随后直接 `read --address <结果>`；或用 `name set --mode field_chain` 把整条链存成符号（默认最后一步解引用，适合字段指向对象的场景）。
- MCP：`resolve` 工具同名参数 `mode` + 可选 `deref_last`（默认 true）。

### nl — 自然语言修改
- 参数：`--session`(必填)、位置参数 `text`（如 `"无限生命"`、`"将金币设为9999"`）、`--confirm`
- 返回：`intent`（解析出的 `action`/`field`/`value`/`value_type`）+ `result`（读取）或修改结果
- 解析失败抛 `E_NLP_UNRESOLVED`；字段未映射抛 `E_NEEDS_SCAN`（含 `details.next` 指引）

### name — 符号表
- `name set <NAME> --session <id> --base <表达式>`（`--base` 必填）、`--offsets`、`--type`(默认 `int32`)、`--description`、`--temp`（标记临时符号，可被 `name clear-temp` 清除）、`--mode {relative,pointer_chain,field_chain}`（存入符号，后续 read/modify 自动沿用）
- `name get --session <id> [NAME]`：不带 NAME 列出全部；NAME 不存在抛 `E_SYMBOL_NOT_FOUND`（`details.known` 给出已知符号）
- `name chain <NAME> --session <id> --base <表达式> [--offsets "0x10,0x28"] [--type uint64] [--mode pointer_chain|field_chain] [--persist]`：遍历多级指针链，每级注册 `<NAME>.stepN` 中间符号（默认临时，`--persist` 持久化）；`--mode field_chain` 按结构体字段语义（offset+deref）遍历；链断裂时已解析的中间符号保留并在返回里报告断点（MCP `name_chain`，`temp: false` 对应 `--persist`）
- `name clear-temp --session <id>`：删除全部临时符号，持久符号不动（MCP `name_clear_temp`）
- 建议命名：`player.gold`、`player.health`、`weapon.ammo`、`resource.wood`（NLP 与模板按这些前缀查找）

### template — 模板
- `template list`：列出全部模板及选项
- `template show <name>`：展示 `options`（含 `label`/`description`/`params`/`targets`）
- `template apply --session <id> --template <name> --option <opt> [--param k=v ...] [--confirm]`
- 模板不存在抛 `E_TEMPLATE_NOT_FOUND`；模板格式错误抛 `E_TEMPLATE_INVALID`

### batch — 批处理
- `batch run --session <id> <file.yaml> [--confirm] [--confirm-code] [--continue-on-error] [--offset N] [--limit M]`
- 文件内的 `confirm` / `confirm_code` / `stop_on_error` 覆盖命令行
- **写风险分级**：dry-run 预览每步带 `risk`，汇总带 `risk_breakdown`（如 `{"high": 2, "normal": 5}`）；确认执行默认只放行 `risk=normal` 项，高风险项（代码段/只读/未知区域）被跳过并标 `skipped_reason: "high_risk_requires_confirm_code"`，需 `--confirm-code`（MCP `confirm_code: true` / YAML 顶层 `confirm_code: true`）才放行
- 完整结果始终落盘 `sessions/<id>/batch_results/<时间戳>.json`（返回 `results_file` / `results_total`）；`--offset` / `--limit` 分页内联窗口
- 文件结构非法（缺 `operations`、某步选了 0 或多个动作键）抛 `E_BATCH_ERROR`

### macro — 参数化宏（可复用操作序列）
- `macro define <name> --session <id> (--file <宏.yaml> | --inline "<YAML>") [--description TEXT]`：同名覆盖；定义含 `params`（名称 -> `{description, required, default}`）与 `operations`（与 batch 相同，支持 `${param}` 占位与内置 `${i}` 操作下标）
- `macro list / show / delete --session <id>`：列出 / 查看 / 删除（宏按会话存储）
- `macro run <name> --session <id> [--params k=v,k=v] [--confirm] [--stop-on-error | --no-stop-on-error]`：代入参数后走批处理管道，写操作同样默认 dry-run
- 必填参数缺失 / 占位符无法解析：`E_INVALID_ARGS`（`details.missing` / `details.declared` + `hint` 补参示例）
- MCP：`macro_list` / `macro_show`（只读）；`macro_define`（`definition` 为 YAML/JSON 字符串）/ `macro_run`（`params` 为字典）/ `macro_delete`（可写 profile）

### job — 后台任务（长时间只读分析）
- `pointer-scan --async`（MCP `pointer_scan` + `async_run: true`，可选 `timeout` 秒）提交后台扫描，立即返回 `job_id`，无 30s 硬超时
- `job status <job_id> [--session <id>]`：轮询状态与进度（`depth` / `paths_found`）；`--session` 可在服务重启后从落盘结果恢复
- `job list [--session <id>]`：列出任务；`job cancel <job_id>`：协作式取消，部分结果先落盘再置 `cancelled`
- 结果持久化在 `sessions/<id>/jobs/<job_id>.json`：`done` / `failed` / `cancelled` 均不丢已完成部分；MCP 工具 `job_status` / `job_list`（只读）、`job_cancel`（可写 profile）

### freeze — 冻结
- `freeze list --session <id>`：已注册冻结项
- `freeze clear --session <id>`：清空（仅 CLI）
- `freeze start --session <id> [--interval 0.05]`：后台进程持续写入
- `freeze stop --session <id>`：停止后台进程
- `freeze run --session <id> [--interval 0.05] [--iterations 0]`：前台循环，`0` = 直到 Ctrl-C
  （中断时返回 `{"ok": true, "data": {"interrupted": true}}`，仅 CLI）

### save-edit — 存档文件修改（存档型游戏）
- `save-edit detect --session <id>`：在游戏目录查找可编辑存档，返回 `saves[]`
  （每条含 `path`、`format`、`size`、`editable`、`reason`）与 `engine`
- `save-edit modify --session <id> --path <存档文件> --field <字段> --value <值> [--confirm]`
- `--field` 支持点号路径（如 `party.gold`）；`--value` 自动转换为 int / float / bool
- 默认 dry-run：返回 `old_value` / `new_value` / `applied:false`；`--confirm` 后返回
  `applied:true` 与 `backup`（写入前自动生成的 `.bak` 路径）
- 支持格式：`.rmmzsave` / `.rpgsave` / `.json`（RPG Maker JSON 或 base64 JSON）；
  `.save`（Ren'Py pickle）目前仅可 detect，修改抛 `E_SAVE_FORMAT_UNSUPPORTED`
- MCP 工具：`save_edit_detect`、`save_edit_modify`（文件参数名为 `file`）

### backup — 备份与还原
- `backup create --session <id> [--symbol NAME | --address 0x..] [--type T] [--offsets ..] [--size N] [--label ..]`
- `backup list --session <id>`：列出全部备份记录（每条含 `id`（形如 `bak-3f9c1a2b7d`）、`label`、`created_at`、`entries` 条目数）
- `backup restore --session <id> <backup_id>`：写回原始字节；`backup_id` 不存在抛 `E_BACKUP_NOT_FOUND`

### 其他
- `toolchain detect`：探测 radare2/rizin、x64dbg、cdb/WinDbg、Binary Ninja、Il2CppDumper / il2cpp-dumper-rs / Il2CppInspector、UE4 Dumper/UE4SS；检测到引擎但工具缺失时的推荐安装流程见下节「toolchain — 工具链检测与 AI 推荐安装」
- `sessions` / `session <id>` / `detach <id>`：列出、查看（引擎、反作弊、符号、冻结、是否存活）、删除会话
- `session snapshot <name> --session <id>` / `session snapshots` / `session restore <name>`：会话状态（符号表、扫描摘要、引擎判定）命名快照，落盘 `sessions/<id>/snapshots/<name>.json`；恢复前当前状态自动归档为 `<name>.pre-restore.json`；快照不存在抛 `E_INVALID_ARGS`（`details.known` 列出可用名）。MCP：`session_snapshots`（只读）、`session_snapshot` / `session_restore`（可写 profile）
- `safety level [--set normal|dry_run_only]`：查看 / 切换运行时安全档位（进程级生效、不落盘）；`dry_run_only` 时 modify / nl / batch run / macro run 的 confirm 写入一律拒绝（`E_PROFILE_RESTRICTED`），预览不受影响。MCP：`safety_get_level`（只读，所有 profile）/ `safety_set_level`（default profile）

### toolchain — 工具链检测与 AI 推荐安装

`toolchain detect` 按「配置 `[tools]` 显式路径 → PATH → 常见安装目录（含 `[tools.search_dirs].extra`）」顺序探测全部外部工具；缺失的工具不抛异常，报告 `found: false` 并附安装 `hint`。**检测到引擎但缺失对应工具链时，优先推荐用户让 AI 自动安装对应工具，而不是直接降级或放弃任务。**

**引擎 → 工具链映射**：

| 场景 | 检测信号 | 推荐安装的工具 | 安装方式 |
| --- | --- | --- | --- |
| Unity Il2Cpp 游戏 | `analyze` 报告 `engine=unity-il2cpp` 且无 dump 产物（script.json） | **il2cpp-dumper-rs**（首选，Rust 实现速度快，支持 metadata v16-v39）或 Il2CppDumper（仅 metadata ≤ 31，Unity < 2022.2） | GitHub release 下载二进制（或 `cargo install il2cpp_dumper`）；不在 PATH 时在配置 `[tools]` 设 `il2cppdumper_rs`（或 `il2cppdumper`）路径 |
| Unreal Engine 游戏 | `analyze` 报告 `engine=unreal` 且无 GObjects/GNames offsets | **UE4SS**（首选，运行时注入 + SDK dump）或 UE4 Dumper / Dumper-7 | UE4SS release 下载后放入游戏目录，并在配置 `[tools]` 设 `ue4ss`（备选 `ue4dumper`） |
| 交叉引用 / 静态分析 | `analyze --deep` 报 `E_TOOL_NOT_FOUND`（缺 radare2）。注意：`xrefs` 缺 radare2 时**不报错**，静默切换纯 Python 兜底（`data.backend=python`）；想要静态分析结果才需要装 radare2 | **radare2**（+ Python 侧 r2pipe） | `winget install radare2` 或官网下载加入 PATH；再 `pip install ".[radare2]"` 安装 r2pipe |
| 运行时反汇编 | `disasm` 报 `E_DEPENDENCY_MISSING`（缺 capstone） | **capstone** | `pip install ".[disasm]"`（或 `.[all]`） |

**四个触发时机**（出现任一即进入推荐安装流程）：

1. `toolchain detect` 报告某工具 `found: false` 且附 `hint` 安装提示时；
2. 命令返回 `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING` 错误码时（`hint` 字段已含具体安装指引）；
3. `analyze` 检测到引擎但缺少对应转储产物时（il2cpp 无 script.json / UE 无 offsets）；
4. `il2cpp dump` / UE 分析流程启动前发现对应 dumper 缺失时。

**AI 推荐安装标准流程**：

1. 向用户说明缺失的工具及其作用（如「缺少 il2cpp-dumper-rs，无法转储 Unity Il2Cpp 的字段偏移与方法 RVA」）；
2. 给出具体的安装命令（见上方映射表）；
3. 请求用户确认后由 AI 执行安装命令（或用户手动安装）；
4. 安装后重跑 `toolchain detect` 验证该工具 `found: true`；
5. 必要时在 `~/.game-modifier/config.toml` 的 `[tools]` 段指定非 PATH 路径（`[tools.search_dirs].extra` 可追加自动探测目录）。

**Agent 行为约定**：收到 `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING` 时**不要放弃任务**，而是按上述标准流程向用户提议安装并给出命令；用户同意并安装完成后验证、再重试原操作。仅当用户明确拒绝安装或环境无法安装时，才按 8.2 对应行降级（如 `analyze` 不用 `--deep`、改走 `scan`/`scan-next`）。

---

## 7. 安全机制

### 7.1 dry-run 默认模式
- **所有写操作默认 dry-run**：`modify`、`nl`、`template apply`、`batch run`、`save-edit modify`
  不加 `--confirm`（MCP：`confirm=true`）都只做"解析 + 读取当前值 + 编码新值"，不写内存 / 不写文件。
- dry-run 返回里带 `dry_run: true`、`applied: false`、`status: "dry_run_preview"` 以及双语 `hint`；确认写入成功返回 `status: "applied"`。**判定写入结果看 `status` 字段**：`dry_run_preview` ≠ 已写入。
- 即使配置里把 `safety.dry_run` 关掉，仍然必须显式确认才会写（`resolve_write_mode` 只看 `confirm`）。

### 7.2 自动备份
- `safety.auto_backup=true`（默认）时，每次确认写入前自动快照原始字节，返回 `backup_id`。
- `backup list` 查看历史，`backup restore <backup_id>` 一键回滚。
- 备份按会话存放在 `~/.game-modifier/`（会话目录下的 `backups`）。
- Agent 应把 `backup_id` 一并告知用户，这是唯一的撤销凭证。
- `save-edit modify` 同样遵守该机制：确认写入前自动把原存档复制为 `.bak` 文件
  （路径在返回的 `backup` 字段里），回滚时把 `.bak` 改回原名即可。

### 7.3 反作弊检测
- attach 时同时扫描**已加载模块名**与**系统进程名**，匹配 16 种已知反作弊：
  EasyAntiCheat、BattlEye、Riot Vanguard、nProtect GameGuard、XIGNCODE3、
  Denuvo Anti-Cheat、PunkBuster、mhyprot (miHoYo)、FACEIT、FairFight、Ricochet (COD)、
  TenSafe/ACE (Tencent)、NEACProtect (NetEase)、HackShield、Anti-Cheat Expert、VAC。
- 命中即返回 `E_ANTI_CHEAT`，`details` 含 `detected` / `systems` / `hits`（每条带 `system`、`match`、`where`）。
- **Agent 收到 `E_ANTI_CHEAT` 必须停止**：不要重试、不要自动加 `--allow-anti-cheat`，
  而是告知用户"检测到反作弊，本工具仅用于单机 / 离线游戏"。
- 联网 / 多人游戏一律拒绝，这是硬规则（见 `agents/game-modder.md`）。

### 7.4 地址验证
每次读写前执行 `validate_address`：
- 地址必须 > 0，否则 `E_INVALID_ADDRESS`；
- 地址必须落在已映射（committed）区域内，且 `[addr, addr+size)` 不跨界，否则 `E_INVALID_ADDRESS`；
- 区域必须可读，否则 `E_INVALID_ADDRESS`；
- 需要可写时区域不可写则 `E_ADDRESS_NOT_WRITABLE`（写路径会尝试 `VirtualProtectEx`，
  此时 `data.warnings` 会提示"target region is not marked writable"）；
- 值必须在类型范围内，越界抛 `E_VALUE_OUT_OF_RANGE`；类型名非法抛 `E_INVALID_TYPE`。

### 7.5 多级工具 profile（MCP `--profile`）
- 五档：`default`（全部）/ `readonly`（只读子集）/ `dry-run` / `symbols` / `limited`，各档精确工具数与成员对照表见 4.1（运行时以 `tools_catalog` 返回为准）。
- `dry-run`：写工具照常注册，但 `confirm=true` 被服务端拒绝（`E_PROFILE_RESTRICTED`），预览透传——适合“AI 可预览不可写”。
- `symbols`：只读 + 符号管理 + 会话快照 + 宏定义，不写游戏内存。
- `limited`：symbols + `modify` / `nl` 单步写；batch / freeze / template 批量写入口不注册。
- **保守场景（不确定的游戏、低信任 agent、演示环境）直接用 `--profile dry-run` 或 `--profile symbols` 启动**。

### 7.6 运行时安全档位（与 profile 正交）
- CLI `safety level` 查看，`safety level --set dry_run_only|normal` 切换；MCP `safety_get_level`（所有 profile，只读）/ `safety_set_level`（default profile）。
- `dry_run_only`：`modify` / `nl` / `batch_run` / `macro_run` 的 confirm 写入在入口处一律拒绝（`E_PROFILE_RESTRICTED`），`confirm=false` 预览不受影响。
- 仅进程级生效、不落盘，进程重启后恢复 `normal`。把会话交给不受控的调用方前先切 `dry_run_only`。

### 7.7 批量写风险分级
- `batch run` / `macro run` 执行前对每个写步骤的目标区域分类：可写数据段 → `risk: "normal"`；可执行段 / 只读 / 未知区域 → `risk: "high"`（保守判定）。
- dry-run 预览：汇总带 `risk_breakdown`（如 `{"high": 2, "normal": 5}`）与每步 `risk`；**confirm 前先看 `risk_breakdown`**，有 `high` 项要向用户逐项说明（目标在代码段 / 只读区域）。
- 确认执行：默认只放行 `normal` 项；高风险项被跳过并标 `skipped_reason: "high_risk_requires_confirm_code"`（不算失败，汇总附 `skipped_high_risk` 计数与 `hint`）。
- 只有用户明确授权（如有意的代码 patch）才加 `--confirm-code`（MCP `confirm_code: true` / YAML 顶层 `confirm_code: true`）放行高风险项，不要替用户授权。

### 7.8 单写高危二级确认
- 同一风险分级同样约束单步 `modify` / `nl`：目标落在代码段 / 只读 / 未知区域时，dry-run 预览带 `requires_confirm_code: true`；`confirm=true` 单独提交被拒（`E_NOT_CONFIRMED`），必须再加 `--confirm-code`（MCP `confirm_code: true`）——与批量语义一致。
- `template_apply` 遇到高危目标不会整体中止：该项标记 `skipped_reason: "high_risk_requires_confirm_code"`，其余正常目标照常应用。

### 7.9 文件路径白名单
- 文件类工具（`file_snapshot` / `file_restore` / `save_edit_modify` / `batch_run` 的 `file=` 参数）只接受白名单根目录内的路径，越界报 `E_PATH_NOT_ALLOWED`。
- 智能默认放行：会话游戏目录（exe 所在目录）、sessions 目录、常见存档位置（`Documents` / `Saved Games` / `AppData` 三个子树 / Steam userdata）；额外根目录在 `~/.game-modifier/config.toml` 的 `[safety] allowed_paths` 追加。
- 系统目录（`%SystemRoot%`）是硬拒绝，配置也无法解锁。

### 7.10 会话写串行化
- 会话的所有写路径（load → 变更 → save）按会话串行：进程内为每会话可重入锁，跨进程（CLI ↔ MCP 服务器）为 `sessions/<id>.lock` 字节范围锁；竞争方在超时后收到 `E_SESSION_BUSY`（hint 指向 `job list` / `job_cancel`）。
- 后台任务（`pointer_scan_async`）结束时在锁内重新加载会话再合并结果，不再用陈旧对象覆盖（消除 lost update）。

---

## 8. 错误处理

### 8.1 错误码分类表

| 分类 | 错误码 | 含义 |
| --- | --- | --- |
| 进程 / 会话 | `E_PROCESS_NOT_FOUND` | 找不到指定 pid / 进程名 / exe |
| | `E_ACCESS_DENIED` | 打开进程被拒（权限不足，需管理员） |
| | `E_SESSION_NOT_FOUND` | `session_id` 不存在（已 detach 或写错） |
| | `E_PROCESS_EXITED` | 会话记录的进程已退出 |
| 安全 / 守卫 | `E_ANTI_CHEAT` | 检测到反作弊，拒绝操作 |
| | `E_NOT_CONFIRMED` | 需要确认才能执行写入 |
| | `E_DRY_RUN` | 信息性标记：本次为模拟执行，非硬失败 |
| | `E_PROFILE_RESTRICTED` | 当前 profile / 运行时安全档位禁止确认写入（dry-run profile 服务端拒绝，或运行时档位 `dry_run_only`） |
| | `E_PATH_NOT_ALLOWED` | 文件路径不在白名单内（文件类工具仅放行游戏目录 / sessions 目录 / 常见存档位置 + `[safety] allowed_paths` 配置追加；系统目录硬拒绝） |
| | `E_SESSION_BUSY` | 会话正被另一操作占用（写路径按会话串行化：进程内锁 + 跨进程锁文件）；稍候重试或先 `job list` / `job_cancel` |
| 内存 | `E_INVALID_ADDRESS` | 地址为 0 / 未映射 / 跨区 / 不可读 |
| | `E_ADDRESS_NOT_WRITABLE` | 目标区域不可写 |
| | `E_READ_FAILED` | 读取失败 |
| | `E_WRITE_FAILED` | 写入失败 |
| | `E_INVALID_TYPE` | 未知数据类型 |
| | `E_VALUE_OUT_OF_RANGE` | 值超出该类型范围 |
| | `E_INVALID_POINTER` | 指针链解析失败（某级为空 / 非法） |
| 定位 / 解析 | `E_NEEDS_SCAN` | 目标尚未映射，需要先扫描（`details.next` 给出扫描参数） |
| | `E_SYMBOL_NOT_FOUND` | 符号未定义（`details.known` 列出已有符号） |
| | `E_NLP_UNRESOLVED` | 自然语言无法解析出字段 / 动作 |
| 工具 / 引擎 | `E_TOOL_NOT_FOUND` | 外部逆向工具未安装或路径未配置（如 `analyze --deep` / `il *` 缺 radare2 / dotnet）。注意：`xrefs` 缺 radare2 时**不抛此错**，而是静默切换纯 Python 兜底（`data.backend=python`）；命中时优先走推荐安装流程（见「toolchain — 工具链检测与 AI 推荐安装」） |
| | `E_TOOL_FAILED` | 外部工具执行失败 |
| | `E_ENGINE_UNKNOWN` | 无法识别游戏引擎 |
| 模板 / 批处理 / 备份 | `E_TEMPLATE_NOT_FOUND` | 模板名不存在 |
| | `E_TEMPLATE_INVALID` | 模板文件结构非法 |
| | `E_BATCH_ERROR` | 批处理文件非法或执行出错 |
| | `E_BACKUP_NOT_FOUND` | `backup_id` 不存在 |
| 存档修改 | `E_SAVE_EDIT_REQUIRED` | 游戏基于存档文件，内存修改无效，应改用 save-edit |
| | `E_SAVE_FORMAT_UNSUPPORTED` | 存档格式不支持修改（未知扩展名、pako/zlib 压缩、Ren'Py pickle） |
| 扫描 / 分析 | `E_PATTERN_NOT_FOUND` | AOB 字节模式未命中任何地址 |
| | `E_LAYOUT_UNSUPPORTED` | 当前场景不支持该布局分析 |
| | `E_SCAN_TIMEOUT` | 扫描超出时间预算（`[analysis] scan_timeout`） |
| | `E_SCAN_CACHE_STALE` | 区域布局变化，上一轮扫描缓存已失效 |
| 通用 | `E_UNSUPPORTED_OS` | 当前平台不支持（本版本面向 Windows） |
| | `E_INVALID_ARGS` | 参数缺失 / 冲突（如同名进程多个、缺 `--base`） |
| | `E_DEPENDENCY_MISSING` | 缺少可选依赖（psutil / r2pipe / mcp / capstone …；`disasm` 缺 capstone 时抛此码）；优先走推荐安装流程（见「toolchain — 工具链检测与 AI 推荐安装」） |
| | `E_INTERNAL` | 未预期的内部异常 |

### 8.2 Agent 错误响应策略

| 错误码 | Agent 应该做什么 |
| --- | --- |
| `E_ANTI_CHEAT` | **立即停止**，向用户说明只支持单机 / 离线游戏；不重试、不绕过 |
| `E_PROFILE_RESTRICTED` | **不要重试**：这不是瞬时错误，而是权限 / 档位限制。改用 `confirm=false` 预览模式完成可验证部分；确需写入时提示用户换更高 profile（`--profile default` / `limited`）或 `safety level --set normal`（MCP `safety_set_level`），不要自行寻找绕过方式 |
| `E_NEEDS_SCAN` | 按 `error.details.next` 执行 `scan`（→`scan-next` 收敛），再 `name set` 后重试原操作 |
| `E_SYMBOL_NOT_FOUND` | 用 `name set` 建立符号（地址来自 scan 或引擎 dump），或本次改用 `--address` |
| `E_PROCESS_EXITED` | 重新 `attach` 拿新的 `session_id`（符号表需重建），再继续 |
| `E_SESSION_NOT_FOUND` | 先 `sessions` 查看活跃会话；没有则重新 `attach` |
| `E_PROCESS_NOT_FOUND` | 让用户确认游戏已启动 / 进程名是否正确；必要时用 `--pid` |
| `E_ACCESS_DENIED` | 提示用户以管理员身份重开终端（`attach` 的 `is_admin` 可佐证）。**来自 `find-writers` 时**：说明当前终端无 `DebugActiveProcess` 权限，不要重试也不要反复加大 `duration`；让用户用管理员终端重开会话后重试，无法提权时降级用 `watch` + `xrefs --direction to` + `disasm` 组合定位写入来源 |
| `E_INVALID_ARGS` | 读 `details`（如 `candidates`）修正参数后重试，不要盲目重复同一条命令 |
| `E_INVALID_ADDRESS` / `E_INVALID_POINTER` | 地址已失效：重新 `resolve` 指针链或重新扫描；游戏重启后基址会变 |
| `E_ADDRESS_NOT_WRITABLE` | 说明可能是只读镜像数据；改找真正的运行时副本（重新扫描）|
| `E_VALUE_OUT_OF_RANGE` / `E_INVALID_TYPE` | 换正确类型（如 `int32`→`int64`、`float`）或改用 `max` |
| `E_TEMPLATE_NOT_FOUND` | 先 `template list` 再选择合法 option |
| `E_BATCH_ERROR` | 按 `details.index` / `found_keys` 修正 YAML，每步只留一个动作键 |
| `E_INVALID_ARGS`（快照缺失，来自 `session restore`） | `details.known` 列出该会话全部可用快照名：先 `session snapshots`（或读 `details.known`）确认名字再重试，不要猜名字反复重试 |
| `E_INVALID_ARGS`（宏参数缺失，来自 `macro run`） | `details.missing` 列出缺哪些必填参数、`details.declared` 是完整参数声明（含默认值）；按 `hint` 补全 `--params k=v`（MCP `params` 字典）后重试；带 `default` 的参数可省略 |
| `E_BACKUP_NOT_FOUND` | `backup list` 取正确 `backup_id` |
| `E_SAVE_EDIT_REQUIRED` | 停止内存扫描 / 修改，改走 5.5 存档流程：`save-edit detect` → `save-edit modify` |
| `E_SAVE_FORMAT_UNSUPPORTED` | 看 `details.known`（支持的扩展名）与 `hint`；压缩 / pickle 存档不要重试，如实际是内存型游戏可回退 `scan` 流程，否则如实告知用户暂不支持 |
| `E_PATTERN_NOT_FOUND` | 检查 / 放宽 AOB 模式（多加 `??` 通配），或确认目标模块已加载；不要无脑重试同一模式 |
| `E_LAYOUT_UNSUPPORTED` | 该布局分析不适用，回落到通用 `scan`，或换一种 `layout --what`；**若来自 `ue_actors` / `ue_fname`（UE 场景）**：会话还没有确认过的 UE 布局，先跑 `ue introspect`（或给 `ue_actors` 显式传 `--gobjects`）再重试，不要直接回落盲扫 |
| `E_SCAN_TIMEOUT` | 缩小扫描范围、降低 `pointer-scan --max-depth`，或调高 `[analysis] scan_timeout` 后重试；长时间指针反查直接改用 `pointer-scan --async`（MCP `async_run: true`）后台任务，无硬超时且部分结果落盘 |
| job `failed` | 读 `error` 字段定位原因（多为地址失效 / 进程退出）；不要无脑重新提交同一任务，先修正输入（重新 `resolve` / 重新 attach）再重提 |
| job `cancelled` | 属于预期终态：部分结果已落盘到 `results_file`，可直接用已有路径；不够用时才重新提交新任务 |
| `E_SCAN_CACHE_STALE` | 区域布局变了，重新执行一次全新 `scan`，不要继续 `scan-next` |
| `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING` | **首选走推荐安装流程，不要直接放弃任务**：按「toolchain — 工具链检测与 AI 推荐安装」的标准流程向用户说明缺失工具、给出安装命令，经确认后执行安装，`toolchain detect` 验证通过再重试原操作。用户拒绝或无法安装时才降级：不用 `--deep`，改走 `scan`/`scan-next`；或提示安装对应工具 / `pip install .[all]`。**新命令具体策略**：`disasm` 报 `E_DEPENDENCY_MISSING`（缺 capstone，`DependencyMissingError`）→ 不要重试，提示 `pip install .[disasm]`（或 `.[all]`）后重试；若无法安装，用 `read --type bytes` + `scan-aob` 退化替代。`xrefs` 缺 radare2 时**不会报错**（静默走纯 Python 兜底，`data.backend=python`）——看到 `backend=python` 又想要静态分析语义时，才提示安装 radare2 并 `pip install .[radare2]`（或在配置 `[tools] radare2` 写路径）；兜底结果噪音多时用 `watch` + `disasm` 组合辅助定位写入来源 |
| `E_NLP_UNRESOLVED` | 换更明确的措辞，或直接用 `modify --symbol` |
| `E_WRITE_FAILED` / `E_READ_FAILED` | 重试一次；仍失败则 `backup restore` 回滚并停手上报 |
| `E_INTERNAL` | 不要重试循环，把 `message` 原样上报用户 |

---

## 9. 最佳实践

### 9.1 Token 效率
- **attach 一次，复用 `session_id`**：会话里已存进程、模块基址、符号表、扫描候选，
  后续调用不必重传任何上下文。
- **用符号名代替裸地址**：`name set` 一次，之后 `modify --symbol player.gold`、
  `nl "无限生命"`、模板都能直接命中，避免每轮回传指针链。
- **批量优先**：多处修改用 `batch run`（一次调用多步）或 `template apply`（一次调用多目标），
  而不是循环调用 `modify`。
- **用 NL 压缩步骤**：`nl "将金币设为9999" --confirm` 一步完成"解析字段 + 类型 + 值 + 写入"，
  比 Agent 自己推理再拼 `modify` 更省。
- **默认 `--format json`**（紧凑单行）；只在给人看时才用 `json-pretty` / `human`。
- **只读 `data` 里需要的字段**：`scan` 只回传 `count` 与前 20 个候选样本（`addresses_hex`），
  先看 `count` / `truncated` 决定是否继续收敛，不要试图让工具吐出全部候选。
- **定位指针链用 `name chain` 保留中间态**：多级链一次遍历并注册 `<名>.step0..N` 中间符号；
  链断裂时已解析部分保留，可从断点继续而不用从头重来；探索性符号用 `name set --temp`，
  结束时 `name clear-temp` 一次清空，不污染正式符号表（也避免 `name get` 列表越来越长）。
- **重复模式封装为 `macro`**：同一套操作只是参数不同时，`macro define` 一次（带 `${param}` 声明），
  之后 `macro run --params k=v` 一条命令完成，不用每轮重传整段 YAML / 多步调用。
- **长流程前打快照**：批量实验 / 多轮调试前 `session snapshot <name>`；符号表被改乱或想回退时
  `session restore <name>`（恢复前当前状态自动归档为 `.pre-restore`，不会丢）。
- **MCP 用 `--groups` 精简 schema**：按游戏类型只加载需要的分组（如 UE：`core,scan,modify,ue,jobs`，见 4.4），
  每个工具的描述 + schema 都占上下文；`tools_catalog` 可查分组清单。

### 9.2 安全操作
- 先 dry-run（不加 `--confirm`）检查 `old_value → new_value` 是否符合预期，
  把 dry-run 结果展示给用户并取得同意后再 `--confirm`。
- 修改前用 `read` 或 `nl "查看金币"` 确认当前值，避免改错地址。
- 明确告知 `backup_id`，并说明 `backup restore` 可撤销。
- "无限"类需求用 `--freeze` + `freeze start`；用完提醒用户 `freeze stop`。
- **写入结果判定看 `status` 字段**：`dry_run_preview` = 未写入，`applied` = 已写入；预览成功（`ok: true`）不等于写入成功，不要把预览当成“已修改”汇报给用户。
- **保守场景用低权限 profile**：不确定目标游戏或在低信任环境执行时，用 `--profile dry-run` 或 `--profile symbols` 启动 MCP 服务器；运行时临时锁死用 `safety level --set dry_run_only`（MCP `safety_set_level`）。
- **batch confirm 前先看 `risk_breakdown`**：预览汇总里 `risk_breakdown.high > 0` 时，向用户说明哪些项目标是代码段 / 只读区域；高风险写入需要用户明确授权后才加 `--confirm-code`（MCP `confirm_code: true`）放行。
- 绝不为绕过检测而使用 `--allow-anti-cheat`；绝不对联网 / 多人游戏操作。

### 9.2.1 存档型游戏（RPG Maker / Ren'Py）
- attach 返回里出现 `save_edit.required=true` 时，**直接转 5.5 存档流程**，不要先花 token
  扫内存：这类游戏的内存值多为 JS 堆里的临时副本，改了也会被存档覆盖。
- NW.js / RPG Maker 常见多进程（主进程 + 渲染进程）且进程名千篇一律（`nw.exe` / `Game.exe`），
  attach 优先用 `--title "窗口标题"` 匹配，避免命中错误子进程。
- `save-edit modify` 前先 dry-run 核对 `old_value`，确认改的是对的存档与字段；
  修改时让游戏处于标题界面或已关闭，改完读档验证，必要时用 `.bak` 回滚。

### 9.3 会话管理
- 记住 `attach` 返回的 `session_id` 并在整轮对话中复用；不要重复 attach 制造多个会话。
- `sessions` 查看全部会话，`session <id>` 查看单个会话是否仍存活（`alive`）及其符号 / 冻结。
- 游戏重启 → 进程与基址都变：`E_PROCESS_EXITED` 后必须重新 `attach`，并重新建立符号
  （模块相对基址表达式 `Module.dll+0x...` 比绝对地址更耐重启）。
- 任务结束用 `detach <id>` 清理；先 `freeze stop` 再 detach。

### 9.4 错误恢复
- **保持幂等**：写操作用"设为具体值"而非"增加 N"，重试不会叠加；重试前先 `read` 核对现状。
- **失败即回滚**：写入链中途失败时用 `backup list` + `backup restore` 恢复原始字节，再重新规划。
- **扫描无结果时换策略**：换类型（`int32` ↔ `int64` / `float`）、
  换比较器（`exact` → `unknown` 后配合 `changed`/`decreased` 收敛）、
  考虑值被加密或按倍数存储（如显示 100 实际存 1000）、必要时提高 `scan.alignment` 或先 `analyze --deep`。
- **批处理用 `--continue-on-error` 诊断**：一次跑完拿到所有失败步骤的 `error`，
  再针对性修复，比逐步试探省 token。
- 不要对同一失败命令连续重试超过一次；先根据 `error.code` 改变策略。

### 9.5 新增 MCP 工具的高效用法

- **输出限流与分页**：`scan` / `scan_next` / `scan_aob` 的大结果集会被自动截断成预览（上限约 50000 字符）。先看 `data.count` / `data.totals` 判断候选量，不要试图一次拿回全部地址；需要更多时先用 `scan-next` 收敛，而不是调大 `max_results`。
- **用 `session_survey` 压缩往返**：想一次性了解会话全貌（引擎、主要模块、符号、冻结、备份、工具链、健康状态）时，调一次 `session_survey` 即可，不要分别调 `session_info` + `name_get` + `freeze_list` + `backup_list` + `toolchain_detect`。
- **用 `audit_tail` 回溯修改**：需要确认“刚刚到底改了什么、备份 id 是多少”时，用 `audit_tail`（读 `sessions/<id>/audit.jsonl`）拿最近 N 条写操作记录，而不必翻历史输出。
- **用 `value_convert` 做进制换算与地址算术**：十进制 / 十六进制 / 字节 / 浮点位型互转交给 `value_convert`，Agent 不要自己做位运算（避免幻觉）。地址加减法也直接传表达式（如 `value_convert("0x7fffe2a22ce0-0x5702ce0")`，仅支持 `+`/`-`），返回额外携带 `expression`/`evaluated` 字段；不要心算地址。同样，`read`/`modify` 的 address 与 `resolve` 的 base 也接受同类表达式（如 `0x1b0c00276c5-0x8`），指针链手工遍历时可直接用表达式步进，模块语法 `game.exe+0x1A4` 不受影响；表达式结果为负会报 `E_INVALID_ARGS`。
- **用 `layout_analyze` / `heap_scan` / `pointer_scan` 取代盲扫**：已知是 C++ / 引擎对象时，先 `layout_analyze`（vtables/rtti/class）+ `heap_scan` 定位实例，再用 `pointer_scan` 反查稳定指针链，比反复 `scan` 更省 token。
- **UE 游戏先内省后修改**：有 dumper 偏移时走 5.6 流程（`ue_introspect` → `ue_actors` → `modify`）：布局一次确认后缓存在会话里，后续调用零探测成本；`ue_actors` 默认返回按类聚合的统计视图（`by_class` 计数），只有候选已经收敛到小范围时才用 `list_results=true`（CLI `--list`）看逐条明细，避免一次回传大量 Actor 字段。
- **用 `watch` 定位「值何时变化」**：候选地址不止一个、或想知道某值在什么游戏行为下被改写时，`watch_start`（或 `watch_run`）轮询监视，在游戏里触发动作后 `watch_report` 看变化时间点与 old/new 序列；`stable: true` 说明盯错了地址（可能是显示副本）。轮询只能回答**何时**变，不能回答**哪条指令**写。
- **用 `disasm` 确认代码结构**：`scan-aob` 或 dumper 给出代码地址后，`disasm`（`--blocks` 看基本块）确认指令序列，判断该改数值、改分支还是 NOP；避免对着一段数据区盲猜指令。
- **用 `xrefs` 定位引用来源**：要找「谁在写这个地址」时用 `xrefs --direction to`（axt）拿引用方列表，再对候选调用方 `disasm` 确认写入指令；`--direction from` 反过来看某函数引用了什么。三者组合（watch 定时间 → xrefs 定来源 → disasm 定指令）是定位写入代码的标准路线。
- **用 `find_writers` 实时抓写入指令**：比 `xrefs`（静态）更精确——DR0-3 硬件写断点直接捕获写入指令的 RIP（`data.hits[].rip`）。**采样时长建议**：`duration` 3~10 秒即可（太短可能抓不到低频写入如每帧重置，太长徒增卡顿），并在采样窗口内主动触发写入行为（受伤 / 花钱）；`max_hits` 保持默认 20 足够去重归并。注意它会短暂挂起目标线程（游戏瞬间卡顿）、需管理员权限（`E_ACCESS_DENIED` 见 8.2），反作弊会话直接拒绝（`E_ANTI_CHEAT`）；拿到 RIP 后立即 `disasm` 看指令。标准升级路线：watch 定时间 → find-writers 定指令 → disasm 看代码。
- **用 `dissect` 推断对象字段布局**：已知实例地址但不知道字段偏移时，`dissect` 按指针宽度切槽并启发式分类（vtable/ptr/int/float/bool，每个字段带 `confidence`）。**多实例提升置信度**：尽量一次传入同一类的 2~5 个实例（`addresses` 逗号分隔），跨实例一致的模式（如都指向堆）会显著拉高 confidence；单实例结果只能当假设，高 confidence 字段也要先用 `read` / `watch` 验证语义再 `name set`。只读，无副作用，可反复调用。
- **用 `pointer_scan(rescan=true)` 验证指针链稳定性**：游戏重启 / 场景切换后不必重新全量扫描，直接 `rescan` 验证 sidecar（`sessions/<id>/pointer_paths.bin`）里保存的路径哪些仍能到达目标；无已保存路径时报 `E_LAYOUT_UNSUPPORTED`，此时回退全新 `pointer_scan`。
- **长 `pointer_scan` 用异步任务 + 轮询**：预期会超过 30s（深度 ≥ 3、大内存进程）时直接 `pointer_scan` 传 `async_run: true`（CLI `--async`），拿到 `job_id` 后用 `job_status` 轮询（进度看 `depth` / `paths_found`），不要同步等死或反复撞 `E_SCAN_TIMEOUT`；不急了就 `job_cancel`（部分结果仍落盘）。任务终态后从 `results_file`（`sessions/<id>/jobs/<job_id>.json`）取指针链；服务重启后用 `job_status(job_id, session=<id>)` 从落盘结果恢复。
- **大 `batch_run` 结果用 `results_file` / 分页，不依赖截断输出**：完整结果始终落盘 `sessions/<id>/batch_results/<时间戳>.json`；超限时返回的是摘要 + 前 10 条 + `preview_note`，全量数据读 `results_file` 或用 `offset` / `limit` 分页重调，永远不要把预览当成全部结果。
- **Unity il2cpp 用专门工具，不手工拼字节**：解码 `Il2CppString` 用 `il2cpp_string`（一次调用完成 length@0x10 + UTF-16 chars@0x14 的读取与解码），不要再自己 `read` 长度再 `read` 字符区再拼 UTF-16；`il2cpp_list` / `il2cpp_dict` 同理，且地址给错只返回 `ok=false`，试错成本极低。
- **`il2cpp_dump` 之后 `il2cpp_lookup` 免参**：dump 会把 script.json 关联到会话，之后反查只需传 `rva`；索引有 gzip sidecar 缓存，重复反查亚秒级。反查 `find-writers` 抓到的 RIP 时用地址表达式直接传 `"RIP-模块基址"`，并给 `tolerance`（如 256）把函数体内的地址匹配到最近函数起始（看 `matched: exact|nearest|none` 判断命中质量）。
- **扫描结果一律走 `results_file` / `scan_candidates`**：`scan` / `scan_aob` 现在把完整候选集持久化并返回 `results_file` + `region_summary` + `candidates_total`；候选量大时用 `scan_candidates`（`offset` / `limit` / `min_addr` / `max_addr`）分页浏览，或用 MCP `scan` 的分页/区域过滤参数（`offset` / `limit` / `min_addr` / `max_addr` / `region_types`）把回传窗口压到最小，不要试图一次拿回全部地址。
- **`batch_preview` 先于 `batch_run`**：写入批处理前先调 `batch_preview`（只读、全 profile）拿逐项 risk 分级与 `estimated_write_bytes`，确认无 high 风险项或已获用户授权后再 `batch_run`；`batch_run` 也支持内联 `yaml` 参数（与 `file` 互斥），小批处理不必先落盘文件。
- **用 `session_notes` 保持定位链上下文**：跨轮次 / 跨压缩的任务里，把「player.gold 已定位于 0x…、经 watch 验证、指针链 step2 断裂」等结论用 `session_notes(action=set)` 写进会话（`sessions/<id>/notes.jsonl`），后续轮次 `action=get` 一次读回，避免重新扫描；`get` 全 profile 可用，`set` / `delete` 需非 readonly profile。
- **`xrefs` 先看 `data.backend` 再解读**：radare2 在场时 `backend=radare2`（静态二进制分析）；不在场时自动回落纯 Python 活内存指针扫描（`backend=python`），两者语义不同。默认 `aligned=true` 只报 4/8 字节对齐引用（降噪），噪音仍多时不要关掉对齐，先用 `disasm` 验证头部候选。
- **Unity Mono 游戏用 `mono` 组，不手工拼布局**：`mono_dump` 先建类型索引（指纹缓存，重复调用 `reused=true` 秒回）→ `mono_symbol` 反查名称/RVA → `mono_string` / `mono_list` / `mono_dict` 直接解码运行时对象；静态字段用 `mono_static`（扫 JIT 代码里的加载指令），实例定位用 `mono_heap_scan`（按 vtable 找活对象）。这些读取工具全 profile 只读，试错成本极低。
- **.NET IL 补丁走 `il` 组五步**：`il_analyze`（`member_filter` 定位方法全名）→ `il_callers`（评估影响面）→ `il_backup`（先备份）→ `il_patch`（`mul_before_ret` 等四种 op；`--out-assembly` 可写新文件）→ `il_verify`（`--expect` 断言 opcode 序列）。全程不动游戏内存，失败 `il_restore` 回退。依赖 .NET 8 运行时（`toolchain detect` 的 `il_tool` 条目）。
- **外部文件先 `file_snapshot` 再动**：改存档 / 换程序集 / 编辑配置前，`file_snapshot`（sha256 + manifest + 审计，`sessions/<id>/file_backups/`）留底，`file_restore` 回滚；游戏进程运行中 `file_restore(confirm=true)` 会被拒绝，先 `freeze stop` + detach 或退出游戏再还原。

---

## 附录：快速参考

```text
attach → analyze → scan → scan-next → name set → modify(dry-run) → modify --confirm → freeze start
                                   ↘ nl "中文指令" --confirm
                                   ↘ template apply --template rpg --option set_gold --confirm
                                   ↘ batch run ops.yaml --confirm
存档型 → attach 返回 save_edit.required=true → save-edit detect → save-edit modify --confirm
UE 型  → ue introspect（dumper 偏移）→ ue actors → name set → modify(dry-run → --confirm)
Unity il2cpp → il2cpp dump → il2cpp lookup（RVA 反查）→ il2cpp string/list/dict（运行时解码）→ name set → modify
Unity mono → mono dump（指纹缓存）→ mono symbol → mono string/list/dict/static/heap-scan（只读解码）→ name set → modify
.NET IL → il analyze → il callers → il backup → il patch --confirm → il verify（失败：il restore）
文件级操作 → file snapshot <path> → 修改/换文件 → 出问题 file restore <backup_id> --confirm（游戏运行中会被拒）
写入定位 → watch run（定时间）→ find-writers（定指令，需管理员）→ disasm（看代码）；静态引用：xrefs（看 data.backend，radare2 缺失自动 Python 兜底）
长扫描 → pointer-scan --async → job status <job_id> 轮询 → results_file 取结果（急停：job cancel，部分结果保留）
大候选集 → scan/scan_aob 返回 results_file → scan_candidates 分页（offset/limit/min_addr/max_addr），不看截断预览
大批量 → batch_preview（risk 预检）→ batch run → results_file 读全量（或 --offset/--limit 分页），不看截断预览
批量风险 → 预览先看 risk_breakdown → confirm 只放行 normal → high 项需用户授权后 --confirm-code
上下文保持 → session_notes set/get（sessions/<id>/notes.jsonl；get 全 profile，set/delete 需非 readonly）
安全分级 → game-modifier-mcp --profile dry-run|symbols|limited（只预览 / 只符号表 / 单步写）
运行时锁 → safety level --set dry_run_only（拒绝 confirm 写入；恢复：--set normal）
写入判定 → 看 data.status：dry_run_preview=未写入，applied=已写入
指针链 → name chain（每级注册 <名>.stepN，断链保留中间态）→ 探索完 name clear-temp
重复操作 → macro define（${param} 参数化）→ macro run --params k=v [--confirm]
回退   → 长流程前 session snapshot <name> → 出问题 session restore <name>（自动 .pre-restore 归档）
省token → game-modifier-mcp --groups core,scan,modify,<引擎组>,jobs（tools_catalog 查分组）
缺工具链 → toolchain detect 看 hint → AI 提议安装（引擎→工具映射见「toolchain — 工具链检测与 AI 推荐安装」）→ 装后验证 found:true → 重试原命令
出错   → 看 error.code → 8.2 策略表
撤销   → backup list → backup restore <backup_id>
收尾   → freeze stop → detach <id>
```
