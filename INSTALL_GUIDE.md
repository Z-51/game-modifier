# 游戏修改器 CLI 插件 — 安装指南

> 分发包名：`game-modifier` ｜ 版本：`0.1.0` ｜ 导入名：`game_modifier`
> 构建产物：`dist/game_modifier-0.1.0-py3-none-any.whl`（纯 Python，无平台限制的 wheel）

**适用范围：单机 / 离线游戏。** 检测到反作弊时工具会拒绝附加进程。

---

## 目录

- [1. 系统要求](#1-系统要求)
- [2. 安装包说明](#2-安装包说明)
- [3. 安装场景](#3-安装场景)
- [4. 安装验证](#4-安装验证)
- [5. 安装后配置](#5-安装后配置)
- [6. 常见安装问题](#6-常见安装问题)
- [7. 升级和卸载](#7-升级和卸载)
- [8. 分发说明（给发布者）](#8-分发说明给发布者)
- [9. 本版本新增功能](#9-本版本新增功能)

---

## 1. 系统要求

| 项目 | 要求 | 说明 |
| --- | --- | --- |
| 操作系统 | Windows 10 / 11 | 本版本的支持目标；内存读写后端为 Windows API（`memory/windows.py`） |
| Python | 3.10 及以上 | `pyproject.toml` 中 `requires-python = ">=3.10"` |
| 权限 | 管理员终端 | 附加游戏进程需要 `SeDebugPrivilege` |
| 磁盘 | 约 10 MB | wheel 包约 79 KB，加依赖后约数 MB |

核心运行依赖（自动安装）：

- `psutil>=5.9` — 进程与模块枚举
- `PyYAML>=6.0` — 模板与批处理文件解析
- `tomli>=2.0` — 仅 Python < 3.11 时安装（3.11+ 使用标准库 `tomllib`）

---

## 2. 安装包说明

### 2.1 从源码安装（开发者）

仓库根目录包含 `pyproject.toml`，使用 setuptools 构建后端，源码位于 `src/` 布局：

```powershell
cd <项目目录>
pip install .
```

开发时使用可编辑安装（改代码立即生效，无需重装）：

```powershell
pip install -e .
```

### 2.2 从 wheel 包安装（用户分发）

发布者构建出的单文件 wheel 可直接拷贝给用户，无需源码、无需编译：

```powershell
pip install dist\game_modifier-0.1.0-py3-none-any.whl
```

wheel 内已打包模板与默认配置数据文件：

- `game_modifier/templates/builtin/action.yaml`、`rpg.yaml`、`strategy.yaml`
- `game_modifier/data/default.toml`

### 2.3 从 PyPI 安装（未来）

当前版本尚未发布到 PyPI。发布后可直接使用：

```powershell
pip install game-modifier
pip install "game-modifier[all]"
```

---

## 3. 安装场景

依赖分组定义在 `pyproject.toml` 的 `[project.optional-dependencies]`：

| 分组 | 额外依赖 | 用途 |
| --- | --- | --- |
| （无） | psutil, PyYAML, tomli | CLI 全部核心功能 |
| `radare2` | `r2pipe>=1.8` | `analyze --deep` 静态分析 |
| `frida` | `frida>=16.0` | 动态插桩（可选后端） |
| `mcp` | `mcp>=1.0` | MCP 服务器 `game-modifier-mcp` |
| `speed` | `numpy>=1.26` | 扫描向量化加速（未装时回落纯 Python） |
| `disasm` | `capstone>=5.0` | `disasm` 命令运行时反汇编（未装时报 `E_DEPENDENCY_MISSING`） |
| `crypto` | `pycryptodome>=3.20` | `save-edit` 编辑 Unity 自定义加密存档（Base64(DES-CBC(JSON))；未装时报 `E_DEPENDENCY_MISSING`） |
| `dev` | `pytest>=7.0`, `pyflakes>=3.0` | 测试与静态检查 |
| `all` | r2pipe + mcp + numpy + capstone + pycryptodome + pytest | 常用完整组合（不含 frida） |

> 注意：`all` 不包含 `frida`。需要 frida 时请显式安装 `".[all,frida]"`。`speed`（numpy）能显著加速数值扫描；对扫描性能敏感的场景建议安装 `".[all]"` 或额外加 `speed`。

### 场景A：仅 CLI 工具（最小安装）

```powershell
pip install dist\game_modifier-0.1.0-py3-none-any.whl
# 或从源码
pip install .
```

核心依赖：`psutil`、`PyYAML`、`tomli`（Python 3.10）。
可用能力：attach / analyze / scan / scan-next / read / modify / freeze / name / nl / template / batch / backup / save-edit。

### 场景B：CLI + MCP 服务器

```powershell
pip install "dist\game_modifier-0.1.0-py3-none-any.whl[mcp]"
# 或从源码
pip install ".[mcp]"
```

额外依赖：`mcp>=1.0`。安装后可执行 `game-modifier-mcp`，向 Agent 暴露结构化工具调用。

### 场景C：CLI + 逆向工具链

```powershell
pip install "dist\game_modifier-0.1.0-py3-none-any.whl[radare2]"
# 或从源码
pip install ".[radare2]"
```

额外依赖：`r2pipe`。r2pipe 只是 Python 侧桥接，**还需自行安装 radare2 / rizin 可执行文件**，见 [5.2 工具链配置](#52-工具链配置可选)。

### 场景D：完整安装（所有功能）

```powershell
pip install "dist\game_modifier-0.1.0-py3-none-any.whl[all]"
# 或从源码
pip install ".[all]"
```

### 场景E：开发环境

```powershell
git clone <repo>
cd game-modifier
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

若 PowerShell 拒绝执行激活脚本，先放开当前用户的脚本策略：

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

或不激活环境，直接使用解释器全路径调用（本仓库的实际做法）：

```powershell
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest tests/
```

---

## 4. 安装验证

以下命令均已在本项目虚拟环境中实测通过。

### 4.1 验证 CLI 入口点

```powershell
game-modifier --version
# 实测输出: {"ok": true, "command": "version", "data": {"version": "0.1.0"}}
```

未激活虚拟环境时：

```powershell
.venv\Scripts\game-modifier.exe --version
```

`[project.scripts]` 注册了两个入口点：

- `game-modifier` → `game_modifier.cli:main`
- `game-modifier-mcp` → `game_modifier.mcp_server:main`

### 4.2 验证 MCP 服务器（如安装了 mcp）

```powershell
python -c "from game_modifier.mcp_server import build_server; print('MCP OK')"
# 实测输出: MCP OK
```

未安装 `mcp` 可选依赖时该导入会失败，属预期行为——CLI 功能不受影响。

### 4.3 验证核心模块

```powershell
python -c "from game_modifier.memory import get_backend; print('Memory OK')"
python -c "from game_modifier.nlp import parse; print('NLP OK')"
python -c "from game_modifier.engines import detect; print('Engines OK')"
```

实测三条均输出 `... OK`。

### 4.3.1 验证新功能模块

```powershell
# 验证引擎检测扩展（NW.js / RPG Maker / Ren'Py / WebView）
python -c "from game_modifier.engines import NWJS, RPG_MAKER, RENPY, WEBVIEW; print('Engines OK')"

# 验证存档修改模块
python -c "from game_modifier.save_edit import detect_saves, load_save, modify_save; print('save_edit OK')"

# 验证窗口标题附加功能
python -c "from game_modifier.memory.process import find_by_window_title; print('window_title OK')"

# 验证布局分析子包（analysis/）
python -c "from game_modifier.analysis import find_vtables, find_pointer_paths, scan_heap_objects, infer_class_layout, find_rtti_classes; print('analysis OK')"

# 验证 AOB 通配扫描模块（memory/aob.py）
python -c "from game_modifier.memory.aob import parse_pattern; print('aob OK')"

# 验证新增 CLI 子命令
game-modifier scan-aob --help
game-modifier layout --help
game-modifier pointer-scan --help

# 验证 save-edit CLI 子命令（需先 attach 获得会话 <id>）
game-modifier --format json-pretty save-edit detect --session <id>
```

实测前三条均输出 `... OK`。

### 4.4 验证工具链检测

```powershell
game-modifier --format json-pretty toolchain detect
```

未安装任何外部逆向工具时返回：

```json
{
  "ok": true,
  "command": "toolchain.detect",
  "data": {
    "available": [],
    "available_count": 0,
    "tools": { "radare2": { "...": "..." } }
  }
}
```

`available` 为空不代表安装失败——外部工具是可选项，缺失时自动降级。检测到引擎但缺失对应工具链时，推荐按 5.2 节的自动安装流程补齐（AI Agent 也会主动提议，见 `AI_AGENT_GUIDE.md` 「toolchain — 工具链检测与 AI 推荐安装」）。

### 4.5 运行测试（开发环境）

```powershell
pytest tests/
# 实测输出: 858 collected, 857 passed, 1 skipped
# 唯一 skip tests/test_watchpoint.py::test_find_writers_self_child：环境跨进程调试
# 权限不足时该测试按设计自动跳过（skip 而非 fail），非代码缺陷
```

`pyproject.toml` 的 `[tool.pytest.ini_options]` 已设置 `testpaths = ["tests"]` 与 `addopts = "-q"`，直接执行 `pytest` 即可。

---

## 5. 安装后配置

### 5.1 MCP 服务器配置

#### Claude Code

仓库已包含 `.mcp.json` 与 `.claude-plugin/plugin.json`，在项目目录内打开 Claude Code 即自动加载，无需额外配置。

#### Codex CLI

在 `~/.codex/config.toml` 中添加：

```toml
[mcp_servers.game-modifier]
command = "game-modifier-mcp"
args = []
```

若 `game-modifier-mcp` 不在 PATH 中（例如装在虚拟环境里且未激活），写入入口点 exe 的绝对路径：

```toml
[mcp_servers.game-modifier]
command = "<项目目录>/.venv/Scripts/game-modifier-mcp.exe"
args = []
```

MCP 默认 profile 注册全部工具组（core / scan / modify / analysis / ue / il2cpp / il / mono / jobs / macros / safety）。工具总数与逐组成员**以运行时调用 `tools_catalog` 工具的返回为准**（它恒注册、列出每组当前成员与计数），文档不写死数字以免漂移。

> 用 `game-modifier-mcp --profile readonly` 启动时只注册只读工具（剔除全部写操作工具；`disasm` / `xrefs` / `dissect` / `watch_run` / `watch_report` / UE 内省 / `il` 只读四件（analyze/dump/callers/verify）/ `mono` 运行时读取工具等两种 profile 均可用）。逐 profile 的精确成员清单同样查询 `tools_catalog`。

### 5.2 工具链配置（可选）

外部逆向工具自动从 PATH 探测，未安装则相关能力降级。需要显式指定路径时，在 `~/.game-modifier/config.toml` 的 `[tools]` 段配置：

```toml
[tools]
radare2 = "C:/Tools/radare2/bin/radare2.exe"
x64dbg = "C:/Tools/x64dbg/release/x64/x64dbg.exe"
```

可选工具清单：

- radare2 / rizin — 静态分析，支撑 `analyze --deep`
- x64dbg — 调试脚本生成
- WinDbg / cdb — 进程检查
- Il2CppDumper / il2cpp-dumper-rs / Il2CppInspector — Unity Il2Cpp 字段偏移与方法 RVA
- UE4 Dumper / UE4SS — Unreal GObjects / GNames
- **.NET 8 运行时**（dotnet）— 随包分发的 il-tool（`il *` 命令）为 framework-dependent 发布，缺它时 `il *` 报 `E_TOOL_NOT_FOUND` 并提示安装；`toolchain detect` 中显示为 `il_tool` 条目

配置完成后用 `game-modifier toolchain detect` 复核 `available` 列表。

#### 工具自动安装（AI 推荐流程）

出现以下任一信号时，推荐让 AI 自动安装对应工具：

- `toolchain detect` 报告某工具 `found: false`（附安装 `hint`）；
- 命令返回 `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING`（错误的 `hint` 字段已直接携带安装指引）；
- `analyze` 检测到引擎但缺少对应转储产物（il2cpp 无 script.json / UE 无 offsets）。

**AI 推荐流程（五步）**：① AI 说明缺失工具的作用与必要性 → ② 给出下述安装命令 → ③ 请求用户确认 → ④ 执行安装（或由用户手动安装） → ⑤ `toolchain detect` 验证 `found: true` 后重试原命令。本节与 `AI_AGENT_GUIDE.md`「toolchain — 工具链检测与 AI 推荐安装」章节、`USER_MANUAL.md` 4.14 节内容一致，可交叉引用避免重复。

**场景 → 工具映射**（配置键为 `toolchain/registry.py` 探测的 `[tools]` 键；pip 依赖无需配置键）：

| 场景 | 推荐工具 | 安装方式 | `[tools]` 配置键 |
| --- | --- | --- | --- |
| Unity Il2Cpp（`engine=unity-il2cpp`，无 dump 产物） | **il2cpp-dumper-rs**（首选，Rust 实现速度快，支持 metadata v16-v39）或 Il2CppDumper（仅 metadata ≤ 31 / Unity < 2022.2） | il2cpp-dumper-rs：GitHub release 下载二进制（或 `cargo install il2cpp_dumper`）；Il2CppDumper：https://github.com/Perfare/Il2CppDumper release 下载 | `il2cppdumper_rs` / `il2cppdumper` |
| Unreal Engine（`engine=unreal`，无 offsets） | **UE4SS**（首选，运行时注入 + SDK dump）或 UE4 Dumper / Dumper-7 | UE4SS：https://github.com/UE4SS-RE/RE-UEPseudo release 下载后放入游戏目录 | `ue4ss` / `ue4dumper` |
| 交叉引用 / 静态分析（`analyze --deep` 报 `E_TOOL_NOT_FOUND`） | **radare2** + Python 侧 r2pipe | `winget install radare2`（或官网下载加入 PATH），再 `pip install ".[radare2]"`。注意：`xrefs` 缺 radare2 时不报错，静默切换纯 Python 兜底（`data.backend=python`） | `radare2` |
| 运行时反汇编（`disasm` 报 `E_DEPENDENCY_MISSING`） | **capstone** | `pip install ".[disasm]"`（或 `".[all]"`） | —（pip 依赖） |
| .NET IL 补丁（`il *` 报 `E_TOOL_NOT_FOUND`，缺 dotnet） | **.NET 8 运行时**；il-tool 二进制随 wheel 分发（`data/il-tool/`），也可用 `iltool/build.ps1` 自行构建 | `winget install Microsoft.DotNet.Runtime.8` 或 https://dotnet.microsoft.com/download/dotnet/8.0 | `il_tool`（运行时探测 `dotnet`） |
| Unity 自定义加密存档（`save-edit` 报 `E_DEPENDENCY_MISSING`） | **pycryptodome** | `pip install ".[crypto]"` | —（pip 依赖） |

各工具安装命令按来源分组：

**pip 分组（Python 依赖）**：

```powershell
pip install ".[disasm]"     # capstone：disasm 运行时反汇编（缺失报 E_DEPENDENCY_MISSING）
pip install ".[radare2]"    # r2pipe：xrefs / analyze --deep 的 Python 侧桥接（radare2 可执行文件需另装）
pip install ".[crypto]"     # pycryptodome：save-edit 编辑 Unity 自定义加密存档（缺失报 E_DEPENDENCY_MISSING）
pip install ".[all]"        # r2pipe + capstone + mcp + numpy + pycryptodome + pytest 常用组合
```

**winget（系统工具）**：

```powershell
winget install radare2                        # radare2 静态分析（也可从 https://github.com/radareorg/radare2 官网下载后加入 PATH）
winget install Microsoft.DotNet.Runtime.8     # .NET 8 运行时（il * 命令依赖；也可从微软官网下载）
```

**安装后验证**：

```powershell
game-modifier --format json-pretty toolchain detect
```

确认 `data.tools.<工具名>` 为 `found: true` 且 `available` 列表包含该工具，再重试原本失败的命令。

**非 PATH 工具的 `[tools]` 配置示例**（键名为 `toolchain/registry.py` 探测的配置键）：

```toml
[tools]
il2cppdumper_rs = "C:/Tools/il2cpp-dumper-rs/il2cpp_dumper.exe"
il2cppdumper = "C:/Tools/Il2CppDumper/Il2CppDumper.exe"
ue4ss = "D:/Games/MyGame/UE4SS.dll"
ue4dumper = "C:/Tools/UE4Dumper/Dumper-7.exe"
radare2 = "C:/Tools/radare2/bin/radare2.exe"

[tools.search_dirs]
extra = ["C:/Tools"]   # 追加自动探测目录，免逐工具写路径
```

### 5.3 配置加载顺序与环境变量

配置按以下顺序叠加，后者覆盖前者：

1. 包内默认配置 `game_modifier/data/default.toml`
2. 用户配置 `~/.game-modifier/config.toml`
3. `$GAME_MODIFIER_CONFIG` 指向的文件

```powershell
$env:GAME_MODIFIER_CONFIG = "D:\configs\game-modifier.toml"
```

`~/.game-modifier/` 同时存放会话数据与写入备份。

---

## 6. 常见安装问题

### Q：pip 报依赖冲突

安装 `mcp` 时可能与环境中已有的 `starlette` / `fastapi` 版本冲突：

```powershell
pip install --upgrade fastapi
```

更稳妥的做法是使用独立虚拟环境，避免污染全局解释器：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install "dist\game_modifier-0.1.0-py3-none-any.whl[all]"
```

### Q：`game-modifier` 命令找不到

说明 Python 的 `Scripts` 目录不在 PATH 中。临时加入当前会话：

```powershell
$env:PATH += ";$HOME\AppData\Local\Programs\Python\Python312\Scripts"
```

或绕过 PATH 直接调用：

```powershell
.venv\Scripts\game-modifier.exe --version
python -m game_modifier --version
```

### Q：需要管理员权限

附加游戏进程需要 `SeDebugPrivilege`，请以管理员身份启动 PowerShell 后再执行 `attach`。权限不足时会返回附加失败错误。

### Q：MCP 导入失败

未安装 `mcp` 可选依赖：

```powershell
pip install "game-modifier[mcp]"
```

### Q：`pip install ".[mcp]"` 在 PowerShell 中报错

PowerShell 会解析方括号，务必给整个参数加引号（如上例）。同理，PowerShell 不支持 `&&` 连接命令，请使用分号 `;`。

### Q：wheel 安装后模板找不到

确认安装的是通过 `python -m build` 构建的 wheel。`[tool.setuptools.package-data]` 已声明打包 `templates/builtin/*.yaml` 与 `data/*.toml`，可用以下命令核对：

```powershell
python -m zipfile -l dist\game_modifier-0.1.0-py3-none-any.whl
```

---

## 7. 升级和卸载

### 升级

```powershell
pip install --upgrade "dist\game_modifier-X.Y.Z-py3-none-any.whl"
# 或从源码
pip install --upgrade .
```

可编辑安装（`pip install -e .`）下拉取新代码即生效；仅当入口点或依赖变更时需要重新执行安装命令。

同版本号强制重装：

```powershell
pip install --force-reinstall dist\game_modifier-0.1.0-py3-none-any.whl
```

### 卸载

```powershell
pip uninstall game-modifier
```

> 卸载使用分发包名 `game-modifier`（带连字符），而导入名为 `game_modifier`（带下划线）。

### 清理配置和数据

`~/.game-modifier` 下存放配置、会话与写入备份。删除前请确认无需回滚游戏内存修改：

```powershell
Remove-Item -Recurse "$HOME\.game-modifier"
```

---

## 8. 分发说明（给发布者）

### 构建 wheel

```powershell
pip install build
python -m build --wheel
# 输出: dist/game_modifier-0.1.0-py3-none-any.whl
```

本仓库实测（虚拟环境内）：

```powershell
cd <项目目录>
.venv\Scripts\python.exe -m pip install build
.venv\Scripts\python.exe -m build --wheel
# Successfully built game_modifier-0.1.0-py3-none-any.whl（约 79 KB）
```

### 构建 sdist + wheel

```powershell
python -m build
# 输出: dist/game_modifier-0.1.0.tar.gz + dist/game_modifier-0.1.0-py3-none-any.whl
```

### 验证包

```powershell
pip install twine
twine check dist/*
```

### 发布前检查清单

1. `pyproject.toml` 中 `version` 已递增
2. `pytest tests/` 与基线一致（当前基线 **858 collected / 857 passed / 1 skipped**，以 `scripts/refresh_metrics.py` 输出为准；唯一 skip `tests/test_watchpoint.py::test_find_writers_self_child` 为环境跨进程调试权限不足时按设计自动跳过，非缺陷）
3. `python -m zipfile -l dist\*.whl` 确认模板与 `data/default.toml` 已打包，且包含 `engines/nwjs.py`、`save_edit/` 子包（`__init__.py`、`rmmz.py`、`renpy.py`）、`memory/aob.py`、`memory/watchpoint.py`、`analysis/` 子包完整文件（`__init__.py`、`disasm.py`、`pointerscan.py`、`classlayout.py`、`vtable.py`、`rtti.py`、`heap.py`、`alignment.py`、`report.py`）、新增模块 `mono_layout.py`、`xrefs_fallback.py`、`safety/file_backup.py` 以及 `data/il-tool/` 目录（il-tool 发布产物，`iltool/build.ps1` 生成）
4. 确认 `pyproject.toml` 中 `disasm` 可选依赖组（`capstone>=5.0`）声明完好——`disasm` 命令依赖它，缺失时应报 `E_DEPENDENCY_MISSING` 而非崩溃
5. 在干净虚拟环境中安装 wheel，并跑完[第 4 节](#4-安装验证)的验证命令
6. `twine check dist/*` 通过

### 上传到 PyPI

```powershell
twine upload dist/*
# 先上传到测试仓库
twine upload --repository testpypi dist/*
```

---

## 9. 本版本新增功能

安装或升级后即可使用以下新能力，无需额外配置（`save_edit` 子包由 `pyproject.toml` 的 `packages.find` 自动发现并打包进 wheel）。

### 9.1 引擎检测扩展

- 现在支持 7 种引擎识别：Unity Il2Cpp、Unity Mono、Unreal、NW.js、RPG Maker、Ren'Py、WebView
- NW.js / RPG Maker 游戏自带的 `.pak` 文件不再被误判为 Unreal
- `attach` / `analyze` 返回结果中的 `engine` 字段会报告检测到的引擎

### 9.2 save-edit 命令（存档型游戏）

RPG Maker / Ren'Py 等引擎的玩家数据存放在存档文件而非稳定内存地址中，此类游戏 `attach` 会返回 `save_edit.required=true`，应改用存档修改而非内存扫描：

```powershell
game-modifier save-edit detect --session <id>
game-modifier save-edit modify --session <id> --path save1.rmmzsave --field gold --value 99999 --confirm
```

- 支持格式：RPG Maker MZ（`.rmmzsave`，JSON）
- 默认 dry-run，加 `--confirm` 才实际写入
- 写入前自动在存档旁生成 `.bak` 备份

### 9.3 窗口标题 attach

```powershell
game-modifier attach --title "游戏窗口标题"
```

- 支持正则表达式或子串匹配
- 解决 NW.js 多进程场景：此类游戏常为多进程且 exe 名称通用（`nw.exe` / `Game.exe`），按窗口标题附加更可靠

### 9.4 新增错误码

| 错误码 | 含义 | 处理建议 |
| --- | --- | --- |
| `E_SAVE_EDIT_REQUIRED` | 游戏使用存档文件，内存修改无效 | 跳过内存扫描，改用 `save-edit detect` → `save-edit modify` |
| `E_SAVE_FORMAT_UNSUPPORTED` | 存档格式暂不支持（压缩 / Ren'Py pickle） | 不要重试，等待后续版本支持 |
| `E_PATTERN_NOT_FOUND` | AOB 字节模式未命中任何地址 | 放宽模式（多加 `??`）或确认目标已加载 |
| `E_LAYOUT_UNSUPPORTED` | 当前场景不支持该布局分析 | 回落到通用 `scan`，或换一种 `layout --what` |
| `E_SCAN_TIMEOUT` | 扫描超出时间预算 | 缩小范围 / 降低 `--max-depth`，或调高 `[analysis] scan_timeout` |
| `E_SCAN_CACHE_STALE` | 区域布局变化导致扫描缓存失效 | 重新执行一次全新 `scan` |

### 9.5 AOB 扫描与布局分析

```powershell
game-modifier scan-aob --session <id> --pattern "48 8B ?? ?? 05"
game-modifier layout --session <id> --what vtables   # 也支持 rtti / class / heap
game-modifier pointer-scan --session <id> --address 0x<addr>
```

- `scan-aob`：`??` 通配符字节模式扫描，按签名定位地址。
- `layout`：只读布局分析（虚表 / RTTI 类名 / 类字段布局 / 堆对象），结果带置信度与理由。
- `pointer-scan`：自动反查能到达目标地址的指针链，把易失裸地址换成稳定的模块相对路径。

### 9.6 扫描性能优化

- `scan-next` 采用批量读，减少系统调用。
- 安装 `[speed]`（numpy）后数值扫描走向量化路径；`first_scan` 支持 workers 并行。
- 大候选集自动落盘到二进制 sidecar，减轻会话文件负担。
- 冻结回写默认自适应间隔（`[freeze] adaptive`）。

### 9.7 反汇编与交叉引用（只读逆向增强）

```powershell
game-modifier disasm --session <id> --address 0x<addr> [--size 256] [--arch x64] [--blocks]
game-modifier xrefs --session <id> --address 0x<addr> [--direction to|from] [--binary path]
game-modifier dissect --session <id> --address 0x<addr> [--addresses a,b,c] [--size 256]
```

- `disasm`：基于 capstone 的运行时反汇编（只读），需安装可选依赖组 `[disasm]`（`capstone>=5.0`），缺失时报 `E_DEPENDENCY_MISSING`。
- `xrefs`：基于 radare2 / r2pipe 的交叉引用分析（只读）。radare2 / r2pipe 在场时分析磁盘二进制；**缺失或失败时不报错，静默切换纯 Python 活内存兜底扫描**（扫描目标进程中指向该地址的指针槽位），返回的 `data.backend` 字段标注实际后端（`radare2` | `python`），`fallback_reason` 说明切换原因。装齐 r2pipe 与 radare2/rizin 可恢复静态分析路径（语义不同：静态分析查磁盘二进制的引用，Python 兜底查活内存中的指针）。
- `dissect`：自动剖析对象字段布局（只读），辅助把裸地址还原为结构化字段。
- 三者均为只读操作，无需 `--confirm`，且在 readonly MCP profile 中同样可用。

### 9.8 写入源头定位与值监控

```powershell
game-modifier find-writers --session <id> --address 0x<addr> [--size 4] [--duration 5]
game-modifier watch run --session <id> --address 0x<addr> [--type int32] [--interval 0.1]
game-modifier watch start --session <id> --address 0x<addr>   # 后台监控，watch stop / watch report 收尾
```

- `find-writers`：硬件写断点（DR0-3），定位是哪段代码在写目标地址；需管理员终端，采样期间短暂挂起目标线程，退出时恢复全部调试寄存器；检测到反作弊的会话直接拒绝（`E_ANTI_CHEAT`）。
- `watch run` / `watch start`：前台 / 后台数值变化监控，后台日志写入 `sessions/<id>/watch.jsonl`，`watch report` 汇总变化序列。

### 9.9 Unreal 引擎内省（只读）

```powershell
game-modifier ue introspect --session <id> --gobjects "Game.exe+0x1D2E500" --gnames "Game.exe+0x1C9A380"
game-modifier ue actors --session <id> --limit 100
game-modifier ue fname --session <id> --address 0x<addr>
```

- 只读探测 GObjects / FNamePool，枚举 Actor，解码并比对 FName；确认的布局会缓存到会话，后续调用直接复用（`--force` 可重探）。
- `ue actors` / `ue fname` 报 `E_LAYOUT_UNSUPPORTED` 时先执行 `ue introspect`（或显式传 `--gobjects`）。

### 9.10 pointer-scan 复验（rescan）

```powershell
game-modifier pointer-scan --session <id> --address 0x<addr> --rescan
```

- 对已保存的指针路径（`pointer_paths.bin` sidecar）重新验证，游戏重启或版本更新后快速筛出仍然有效的指针链。

### 9.11 MCP 升级

- 工具总数与逐组成员**不在此写死**：以运行时 `tools_catalog` 工具返回为准（恒注册，列出每组当前成员与计数）。
- **输出限流**：超约 50000 字符的返回自动截断成预览（`data.totals` 保留原始条数）。
- **只读 profile**：`game-modifier-mcp --profile readonly` 只注册只读工具（精确清单查 `tools_catalog`）。
- **审计日志**：写操作追加到 `sessions/<id>/audit.jsonl`，`audit_tail` 可回读。

### 9.12 扫描与候选集管理（阶段 1）

- `scan` / `scan_aob` 支持 `offset` / `limit` 分页；`scan_aob` 支持区域过滤（`min_addr` / `max_addr` / `region_types`）、`stop_on_limit` 与并行扫描；两者返回 `region_summary` 并把完整候选集持久化到 `results_file`。
- `scan_candidates`：不重扫，直接分页浏览上一次扫描的持久化候选集（CLI：`scan-candidates`；只读）。
- **il-tool 子进程子系统**：C# 源码在仓库 `iltool/` 目录，`iltool/build.ps1` 以 **framework-dependent**（`--self-contained false`，win-x64）发布到 `src/game_modifier/data/il-tool/`，随 wheel 分发（`pyproject.toml` 的 `package-data` 已含 `data/il-tool/*`）。**运行 `il *` 命令需要目标机器装有 .NET 8 运行时**（`winget install Microsoft.DotNet.Runtime.8` 或 https://dotnet.microsoft.com/download/dotnet/8.0）；重新构建需 .NET 8 SDK（`dotnet --version` >= 8.x，publish 阶段 NuGet 需联网拉 Mono.Cecil）。
- **dotnet 缺失时的降级行为**：`toolchain detect` 报告 `il_tool: found=false` 且 `hint` 指向 `iltool/build.ps1`；`il *` 命令返回 `E_TOOL_NOT_FOUND` / `E_DEPENDENCY_MISSING` 并附安装指引，其余功能不受影响。
- MCP 工具：`il_analyze` / `il_dump` / `il_callers` / `il_verify`（只读），`il_patch` / `il_backup` / `il_restore`（写，自动先做文件备份）；`mono_dump` / `mono_symbol`（CLI `mono dump/symbol`）。

### 9.13 Mono 运行时工具与文件快照（阶段 2）

- `mono_string` / `mono_list` / `mono_dict` / `mono_static` / `mono_heap_scan`（CLI `mono string/list/dict/static/heap-scan`）：全部只读、全 profile 可用；`mono_string` 按架构感知布局解码（x86 length@0x8/chars@0xC，x64 0x10/0x14）。
- `mono_dump` 产物带指纹缓存（size/mtime/head-hash sidecar），未变更时直接复用（`reused=true`），`--force` 重建。
- `scan` 支持 `encoding=utf8|utf16le`（MCP 参数）；配置文件 `[scan] fingerprint_mode=strict|lenient`（默认 strict）+ `stale_detail`，`scan_next` 支持 `retain_stale`。
- `file_snapshot` / `file_restore`（CLI `file snapshot/restore`）：FileBackupManager 管理的外部文件快照/还原，存 `sessions/<id>/file_backups/<backup_id>/`（sha256 + manifest + 审计）；`file_restore --confirm` 在游戏进程运行中会被拒绝。

### 9.14 批处理预检、笔记与 xrefs 兜底（阶段 3）

- `batch_run` 支持内联 `yaml` 参数（与 `file` 互斥）；`batch_preview`（MCP，只读，全 profile）预检批处理：逐项 risk 分级 + `estimated_write_bytes`。
- `scan` / `scan_aob` 返回 `results_file`（完整候选集持久化），超大结果不必依赖截断预览。
- `session_notes`（MCP）：会话键值笔记，存 `sessions/<id>/notes.jsonl`；`get` 全 profile 只读，`set` / `delete` 在 readonly profile 被拒（`E_PROFILE_RESTRICTED`）。
- `xrefs` 新增 `aligned` 参数（默认 true，4/8 字节对齐过滤）；radare2 不可用时自动切换纯 Python 活内存扫描兜底，返回 `data.backend`（`radare2` | `python`）标注实际后端。

---

## 附：相关文档

| 文档 | 内容 |
| --- | --- |
| `USER_MANUAL.md` | 完整命令参考与使用流程 |
| `AI_AGENT_GUIDE.md` | Agent 集成与 token 优化实践 |
| `AGENTS.md` | 面向编码 Agent 的速查说明 |
| `HANDOVER_GUIDE.md` | 项目交接与架构说明 |
