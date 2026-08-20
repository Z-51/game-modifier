# iltool — Unity Mono IL 分析/补丁子进程

`il-tool` 是 game-modifier 的 .NET 侧桥接工具：通过 **Mono.Cecil** 读取/改写
托管程序集（`Assembly-CSharp.dll` 等）的 IL 元数据，**不反射加载任何类型**。
Python 侧由 `src/game_modifier/engines/il_tool.py::run_il_tool()` 以子进程方式驱动。

## 构建

需要 **.NET 8 SDK**（`dotnet --version`）。仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\iltool\build.ps1
```

产物为 **framework-dependent win-x64**（运行需 .NET 8 Runtime），输出到
`src/game_modifier/data/il-tool/`，随包分发（pyproject package-data 已登记）。

二进制定位顺序（Python 侧 `locate_il_tool`）：

1. 包内 `src/game_modifier/data/il-tool/il-tool.exe`
2. config `[tools] il_tool` 显式路径
3. toolchain registry 探测（PATH / `[tools.search_dirs].extra`）

手动构建等价命令：

```powershell
dotnet publish .\iltool\src\IlTool\IlTool.csproj -c Release -r win-x64 --self-contained false -o .\src\game_modifier\data\il-tool
```

NuGet 依赖钉版本：`Mono.Cecil 0.11.5`（restore 需联网）。

## 子进程协议

与 game-modifier 主信封同构。**stdin 读入恰好一行 JSON 请求，stdout 输出恰好一行 JSON 信封**；
stderr 仅诊断文本；exit code `0` = 信封有效（含 `ok:false` 业务错误），非 0 = 传输层失败。

### 运行模式

| 模式 | 说明 |
| --- | --- |
| 单发（默认） | 读一行请求 → 回一行信封 → 退出。 |
| `--serve` / `-s` | 常驻循环：每行一个请求、每行一个信封，直到 stdin EOF（宿主关管）干净退出；空行视为 keep-alive ping 直接忽略；单个请求的业务错误只回错误信封、不中断循环。 |

Python 侧 `run_il_tool()` 对真实 `.exe` 默认走**常驻 worker**（`--serve`，进程级单例：
请求串行化、崩溃透明重启并重试一次、闲置 300s 自动回收）；`.py` 替身（测试）始终走
单发路径。旧版二进制接到 `--serve` 参数会退化为"单发后退出"，宿主检测到进程退出后
自动重建，因此无需版本协商。

### 请求（stdin 单行）

```json
{"v":1,"command":"analyze|dump|callers|patch|verify|index",
 "assembly":"<程序集路径>",
 "args":{},
 "patch":{"op":"mul_before_ret","value":4.0},
 "out":"<可选：大输出落盘路径>"}
```

大输出（analyze 全枚举 / dump 指令流 / callers 全表 / index 全量索引）**必须**通过
`out` 参数落盘：stdout 只回 `{"out_file": "...", "*_count": N}` 摘要。

### 响应（stdout 恰好一行）

```json
{"ok":true,"command":"...","data":{...}}
```
或
```json
{"ok":false,"error":{"code":"E_IL_...","message":"...","details":{...}}}
```

工具内部错误码：`E_IL_BAD_REQUEST` / `E_IL_ASSEMBLY_NOT_FOUND` /
`E_IL_METHOD_NOT_FOUND` / `E_IL_PATCH_FAILED` / `E_IL_VERIFY_FAILED` /
`E_IL_UNSUPPORTED` / `E_IL_INTERNAL`。

## 命令

方法定位（`args`）：`method`（全名精确优先，其次大小写不敏感子串）+ 可选 `type`
（声明类型子串过滤）。

| command | 说明 | 关键 args |
| --- | --- | --- |
| `analyze` | 类型/方法/字段枚举（Cecil 元数据） | `filter`（子串）、`max_types` |
| `dump` | 方法体 IL 指令流 + Operand 解析 | `method`、`type` |
| `callers` | 全程序集 call/callvirt/ldftn 引用扫描 | `target`（必需）、`max_results` |
| `patch` | 执行补丁（委托 PatchOps 注册表） | `method`、`out_assembly`（默认原地写回） |
| `verify` | 读回 IL 与期望 opcode 模式比对 | `method`、`expected`（opcode 列表）、`exact` |
| `index` | 全量类型/方法索引 JSON（mono_dump/mono_symbol 用） | — |

`--version` 打印版本横幅（registry 探测用）。

## PatchOps 注册表

| op | patch 载荷 | 语义 |
| --- | --- | --- |
| `replace_body` | `{"value": N}` | 方法体替换为 `ldc(N); ret`（void 方法仅 `ret`） |
| `mul_before_ret` | `{"value": N}` | 每个 `ret` 前插入 `ldc(N); mul`（缩放返回值） |
| `insert_before_ret` | `{"value": N}` | 非 void 方法每个 `ret` 前插入 `pop; ldc(N)`（强制常量返回） |
| `insert_after_call` | `{"target": "...", "value": N}` | 每个匹配 `target` 的 call/callvirt 后插入 `ldc(N); mul`（缩放调用结果，仅数值返回类型） |

典型闭环：`patch`（如 `mul_before_ret value=4.0`）→ `verify`
（`expected: ["ldc.r4","mul","ret"]`）。verify 不匹配时返回
`ok:false / E_IL_VERIFY_FAILED`，details 带 expected/actual 序列。

## 安全约定

- `analyze` / `dump` / `callers` / `verify` / `index` 严格只读。
- `patch` 默认原地写回目标 dll；生产调用方应先经 `backup create` 备份，
  或用 `args.out_assembly` 写到副本。
- 仅限单机/离线游戏的托管程序集；工具不接触进程内存。
