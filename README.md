# game-modifier

**面向 AI Agent 的单机 / 离线游戏内存修改器**——一条 CLI 命令一个 JSON 行，外加一套 MCP 结构化工具服务器。把"找地址 → 改数值"和"修改游戏逻辑"的 token 开销压到最低。

> ⚠️ **仅限单机 / 离线游戏。** 检测到反作弊时会立即拒绝附加（`E_ANTI_CHEAT`）。不支持联机作弊与 DRM 对抗。详见[安全声明](#安全声明)。

---

## 要点速览

- **Python**：≥ 3.10（`requires-python = ">=3.10"`）
- **现目前支持的平台**：Windows 10 / 11（内存读写后端为 Windows API；附加需管理员终端）
- **版本**：`0.1.0` ｜ 分发包名 `game-modifier`，导入名 `game_modifier`
- **MCP 工具**：default profile 84 个（另有常驻 `tools_catalog`）/ readonly profile 54 个
- **引擎识别**：Unity Il2Cpp / Unity Mono / Unreal / NW.js / RPG Maker / Ren'Py / WebView
- **许可证**：MIT（见[许可证与免责](#许可证与免责)）

---

## 安装

1. 将项目下载下来、解压，在项目目录中选择以下其中一个指令进行安装。

```powershell
# 完整安装（所有功能）
pip install ".[all]"

# 最小安装（仅 CLI，核心依赖 psutil + PyYAML + tomli[Python<3.11]）
pip install .

# 含 MCP 服务器（暴露结构化工具给 Agent）
pip install ".[mcp]"


```
2. 安装后配置到你的AI agent。让它们识别到game-modifier。（可以用AI来帮你）

**例如：**

**Codex CLI**

  在 `~/.codex/config.toml` 中需要添加：

```
[mcp_servers.game-modifier]
command = "<你的项目目录>/.venv/Scripts/game-modifier-mcp.exe"
args = []
```

**Claude CLI**

  在 `~/.claude/mcp.json` 中需要添加：

```
"game-modifier": {
  "command": "<你的项目目录>/.venv/Scripts/game-modifier-mcp.exe",
  "args": [],
  "description": "game-modifier structured tools (attach/scan/modify/nl/template/batch/...) over MCP."
}
```

### 安装后验证


**在你的AI agent会话框里面输入`/mcp`,即可查看是否显示game-modifier，来确认是否安装完毕。**


以下指令是检查当前电脑是否有game-modifier工具

```powershell
game-modifier --version                 # {"ok": true, "command": "version", "data": {"version": "0.1.0"}}
python -c "import game_modifier; from game_modifier.memory import get_backend; from game_modifier.nlp import parse; print('import OK')"
game-modifier toolchain detect          # 外部逆向工具探测（缺失自动降级，不阻塞）
pytest tests/                           # 开发环境：900 collected / 899 passed / 1 skipped
```



完整安装指南（wheel 分发安装 / 升级 / 卸载 / 工具链 AI 自动安装流程）见 [INSTALL_GUIDE.md](INSTALL_GUIDE.md)。

---

## 功能概览

每条命令输出一行 JSON：`{"ok": bool, "command": ..., "data" | "error": ...}`，错误带稳定 `error.code` 与可执行 `hint`。

| 命令组 | 能力 |
| --- | --- |
| `attach` | 附加进程（`--process` / `--pid` / `--exe` / `--title` 窗口标题正则匹配，适配 NW.js 多进程通用 exe 名）；报告引擎、反作弊、是否存档型游戏 |
| `analyze` | 引擎与模块分析，`--deep` 走 radare2 静态分析（缺工具自动降级） |
| `scan` / `scan-next` / `scan-candidates` | 数值 / 字符串（UTF-8 / UTF-16）/ 字节扫描；分页（`offset` / `limit`）、区域过滤、完整候选集落盘（`results_file`），`scan-candidates` 免重扫分页浏览 |
| `scan-aob` | `??` 通配字节模式（AOB）扫描，支持区域过滤与 `stop_on_limit` |
| `read` / `modify` / `resolve` | 读 / 写 / 解析地址；支持 `0x...+/-0x...` 地址表达式，写操作默认 dry-run + `--confirm` 门控 + 自动备份；高危区域（代码段等）追加 `--confirm-code` 二级确认 |
| `nl` | 确定性中文自然语言："将金币设为9999" → 直接执行（含字段 / 动作 / 中文数字识别） |
| `name` | 符号化地址表（`name set`）；`name chain` 注册指针链中间步骤 |
| `template` | 内置修改模板（rpg / action / strategy），按符号应用 |
| `batch` | YAML 批处理（文件或内联 `yaml` 参数），`batch preview` 逐项 risk 预检；完整结果恒落盘可分页 |
| `freeze` | 数值冻结回写（自适应间隔），后台启停 |
| `save-edit` | 存档型游戏：RPG Maker（JSON / base64 JSON）、Ren'Py detect、Unity 自定义加密存档（DES-CBC，需 `crypto` 组与密钥） |
| `il` | .NET IL 七工具：analyze / dump / callers / verify（只读）+ patch / backup / restore（写；随包分发 il-tool，需 .NET 8 运行时；il-tool 常驻 `--serve` worker 复用进程，analyze 全量枚举按程序集指纹缓存） |
| `mono` | Unity Mono 运行时解码：string / list / dict / static / heap-scan（只读）+ dump / symbol（指纹缓存类型索引） |
| `il2cpp` | Unity Il2Cpp：string / list / dict / lookup（RVA → 方法名）只读解码 + dump（外部 dumper） |
| `ue` | Unreal 只读内省：introspect（GObjects / FNamePool 探测）、actors（枚举聚合）、fname（解码比对） |
| `disasm` | capstone 运行时反汇编（只读，需 `[disasm]` 组） |
| `watch` | 前台 / 后台数值变化监控（`watch run` / `start` / `report` / `stop`） |
| `xrefs` | 交叉引用（只读）：radare2 在场走静态分析，缺失时静默切纯 Python 活内存兜底（`data.backend` 标注） |
| `find-writers` | 硬件写断点（DR0-3）定位写入源头代码（需管理员；反作弊会话直接拒绝） |
| `dissect` / `layout` | 对象字段自动解剖 / 布局分析（虚表、RTTI、类布局、堆对象），只读带置信度 |
| `pointer-scan` | 指针链反查（支持 `--rescan` 复验与 `--async` 后台任务，`job` 组轮询取结果） |
| `job` | 后台任务管理：status / list / cancel（部分结果保留） |
| `macro` | 宏定义 / 执行 / 管理 |
| `session` | 会话快照 / 恢复、键值笔记（`session_notes`）、审计日志（`audit_tail`）、大结果回读（`results_read`，限会话目录内分页） |


---

## 快速开始

以"把金币改成 9999"为例（PowerShell；注意 PowerShell 不支持 `&&`，用 `;` 分隔）：

```powershell
# 1. 安装（开发模式，含测试依赖）
pip install -e ".[dev]"

# 2. 附加进程（管理员终端）→ 拿到 session_id，后续全部复用
game-modifier attach --process game.exe
# {"ok": true, "command": "attach", "data": {"session_id": "s1", "engine": "unknown", "anti_cheat": false, ...}}

# 3. 首次扫描（假设当前金币 100）
game-modifier scan --session s1 --type int32 --value 100

# 4. 在游戏里花掉一些金币（100 → 80），再次缩小候选
game-modifier scan-next --session s1 --value 80
# 重复 3~4 直到 data.count == 1

# 5. 把裸地址固化成符号
game-modifier name set player.gold --session s1 --base 0x1B0C00276C5 --type int32

# 6. 先 dry-run 预览（默认不写）
game-modifier modify --session s1 --symbol player.gold --value 9999
# {"ok": true, ..., "data": {"status": "dry_run_preview", "risk": "...", ...}}

# 7. 确认写入（自动备份原值，backup restore 可回滚）
game-modifier modify --session s1 --symbol player.gold --value 9999 --confirm
# {"ok": true, ..., "data": {"status": "applied", "verified_value": 9999, "backup_id": "...", ...}}
```

多进程 / 通用 exe 名的游戏（NW.js 等）用窗口标题附加更可靠：`game-modifier attach --title "游戏窗口标题.*"`。

### 典型工作流（ASCII 示意）

```
 attach（--process / --title）          analyze（引擎 + next_steps）
        │ session_id                             │
        ▼                                        ▼
 scan（首扫） ──游戏内改变数值──▶ scan-next（收敛到唯一候选）
        │
        ▼
 name set 固化符号 ──▶ modify（dry-run 预览）──▶ modify --confirm（自动备份）
        │                                              │
        ├─▶ template / batch（一次调用多处修改）         ├─▶ backup restore（回滚）
        ├─▶ freeze（持续锁值）                          └─▶ audit_tail（审计追踪）
        └─▶ pointer-scan --async（裸地址 → 稳定指针链）

 存档型游戏（attach 提示 save_edit.required=true）：
 save-edit detect ──▶ save-edit modify --field gold --value 99999 --confirm（自动 .bak）
```

---

## 安全声明

本项目**仅面向单机 / 离线游戏的个人研究与学习**：

1. **拒绝反作弊**：`attach` 检测到反作弊组件时会立即拒绝附加并返回 `E_ANTI_CHEAT`，不提供绕过手段；`find-writers` 等敏感能力对此类会话同样直接拒绝。
2. **默认 dry-run**：所有写操作（`modify` / `nl` / `batch` / `template apply` / `save-edit modify` / `il patch` 等）默认只预览，必须显式 `--confirm`（MCP `confirm=true`）才落盘 / 写内存；高风险区域（代码段 / 只读 / 未知区域）写入还需额外 `confirm_code`（`modify` / `nl` / `batch` / `macro` 语义一致）。
3. **会自动备份与审计**：写入前自动备份原值（`backup restore` 回滚），存档写入自动生成 `.bak`；每次确认写入追加到 `sessions/<id>/audit.jsonl`。
4. **只读优先的 profile**：MCP 服务器可 `--profile readonly` 启动，剔除全部写工具；另有 `dry-run` / `symbols` / `limited` 细粒度 profile。
5. **文件路径白名单**：文件类工具（`file snapshot` / `file restore` / `save-edit modify` / `batch run --file`）只接受白名单根目录内的路径——智能默认放行游戏目录、sessions 目录与常见存档位置（Documents / AppData / Saved Games / Steam userdata），可在配置 `[safety] allowed_paths` 追加；系统目录（`%SystemRoot%`）硬拒绝，越界报 `E_PATH_NOT_ALLOWED`。
6. **会话写串行化**：同一会话的写操作在进程内（锁）与跨进程（锁文件，CLI ↔ MCP 服务器）两个层面串行，冲突时报 `E_SESSION_BUSY`，杜绝并发写会话状态互相覆盖。
7. **明确的不支持**：联机游戏作弊、反作弊绕过、DRM 破解。使用者须自行确认目标游戏的使用条款与当地法律法规。

---


### 可选依赖分组速查

定义于 `pyproject.toml` 的 `[project.optional-dependencies]`，缺失时相关能力优雅降级：

| 分组 | 依赖 | 用途 |
| --- | --- | --- |
| `radare2` | `r2pipe>=1.8` | `analyze --deep` 静态分析 / `xrefs` 静态路径（radare2 可执行文件需另装） |
| `frida` | `frida>=16.0` | 动态插桩（可选后端） |
| `mcp` | `mcp>=1.0` | MCP 服务器 `game-modifier-mcp` |
| `speed` | `numpy>=1.26` | 扫描向量化加速（未装回落纯 Python） |
| `disasm` | `capstone>=5.0` | `disasm` 运行时反汇编（未装时，会报 `E_DEPENDENCY_MISSING`） |
| `crypto` | `pycryptodome>=3.20` | `save-edit` 编辑 Unity 自定义加密存档 |
| `dev` | `pytest>=7.0`, `pyflakes>=3.0` | 测试与静态检查 |
| `all` | r2pipe + mcp + numpy + capstone + pycryptodome + pytest | 常用完整组合（**不含 frida**，需要时用 `".[all,frida]"`） |



## 文档导航

| 文档 | 内容 |
| --- | --- |
| [USER_MANUAL.md](USER_MANUAL.md) | 完整命令参考与使用流程（含引擎专题：UE / Il2Cpp / Mono / 存档型游戏） |
| [AI_AGENT_GUIDE.md](AI_AGENT_GUIDE.md) | Agent 集成与 token 优化实践、标准工作流、错误码表 |
| [AGENTS.md](AGENTS.md) | 面向编码 Agent 的速查说明（安全约定 / 错误处理 / 工具链安装） |
| [INSTALL_GUIDE.md](INSTALL_GUIDE.md) | 安装指南（源码 / wheel / 升级 / 卸载 / 工具自动安装） |
| [HANDOVER_GUIDE.md](HANDOVER_GUIDE.md) | 项目交接与架构说明 |
| [skills/game-modifier/SKILL.md](skills/game-modifier/SKILL.md) | Agent Skill 定义 |
| [docs/decisions/](docs/decisions/) | 决策复盘系列文档 |
| [scripts/refresh_metrics.py](scripts/refresh_metrics.py) | 项目规模指标生成脚本（源文件/测试/MCP 工具/错误码等，重跑后刷新各文档数字） |

---

## 许可证与免责
- MIT
- 本工具仅供单机 / 离线游戏的个人研究与学习使用。使用本工具可能违反目标游戏的用户协议或当地法律法规，**由此产生的一切后果由使用者自行承担**。作者不对任何滥用行为负责，亦不提供联机作弊、反作弊绕过相关支持。
