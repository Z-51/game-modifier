# game-modifier 原生代码注入能力 — 执行文档（v2，Frida 路线修正版）

> 状态：已完成全仓文档深度复核（README / HANDOVER_GUIDE / GAME_TECHNIQUES / AI_AGENT_GUIDE /
> USER_MANUAL / INSTALL_GUIDE / docs/retrospective / docs/decisions/*4 份 / pyproject / .mcp.json /
> samples / hooks / skills / tests 目录）。本版基于项目**既定路线图**重写，修正 v1 的方向性错误。
> 读者：实现该能力的 coding agent。

---

## 1. 项目真实目的（证据链，勿偏离）

本项目**不是**通用游戏修改器，而是**面向 AI Agent（Claude Code / Codex CLI）的 token 高效单机游戏内存修改插件**。四条不可动摇的设计支柱（出处见括号）：

1. **Token 效率优先**（README / HANDOVER §1）：会话复用、符号地址表、确定性中文 NLP、单行 JSON、模板/批处理——一切 API 都为了让 Agent 少传 token。
2. **硬安全契约**（README 安全声明 / HANDOVER §1 / decisions/02 §3）：反作弊即拒绝且**禁止弱化路径**（"禁止添加绕过开关、白名单、'仅读写不注入'之类的弱化路径"）；所有写默认 dry-run + `--confirm` + 备份 + 审计。
3. **优雅降级**（decisions/01 D9）：重依赖全部进**可选 extras 组 + try-import 懒加载**，缺失给 `E_DEPENDENCY_MISSING` + 安装 hint。
4. **文档-代码一致性是硬工程约束**（HANDOVER §5.4）：改动命令清单 / MCP 工具数与分组 / 错误码 / profile / 依赖组 / 测试基线时，AGENTS.md、USER_MANUAL.md、AI_AGENT_GUIDE.md、HANDOVER_GUIDE.md、INSTALL_GUIDE.md、SKILL.md **必须同步**，否则视为缺陷。

**能力边界现状（官方明确声明）**：
- `GAME_TECHNIQUES.md` §6"诚实边界"：能做=值级+IL 级（Mono `il patch`）修改；**不能做=任意 x86 汇编注入 / shellcode / DLL 注入、运行时改写可执行代码段、IL2CPP/原生引擎代码级补丁**。
- `docs/decisions/04-对外分享版`：公开声明"不做代码注入、不做 hook、不对抗 DRM"。
- `docs/decisions/01-学习版` D16：**keystone（汇编器）始终未引入，"因为只需要读不需要写指令"**。

**路线图落点（本次要实现的正是它）**：
- `HANDOVER_GUIDE.md` §10"长期"第 1 条：**frida 集成落地（`[frida]` extra 已预留），支持函数 hook 与动态追踪**。
- `pyproject.toml`：`frida = ["frida>=16.0"]`（"动态插桩（可选后端）"）——**已预留，零实现**（`src/` 全仓 grep 无 frida/hook/inject 引用）。
- 关联但**不在本次范围**：HANDOVER"长期"第 3 条"冻结机制改用 hook 而非轮询"（以本次能力为地基的后续项，见 §10）。

**结论**：用户需求 = **落地 HANDOVER 长期路线图第 1 条（Frida 动态插桩后端）**，并把"函数 hook 与动态追踪"扩展为完整的"代码注入"能力面（detour / 远程调用 / DLL 注入），同时**补写官方声明为"不能做"的能力**。这与项目既定方向完全一致，不是另起炉灶。

---

## 2. 需求映射（5 轮澄清 × 项目路线图对齐）

| 用户澄清结论 | 实现路径（Frida-first） |
|---|---|
| 仅运行时（内存），不写盘 | ✅ Frida 只改内存，天然运行时 |
| 内联钩子/detour + DLL 注入 | `Interceptor.attach/replace`（自带 trampoline）、`Module.load` |
| Payload 三种都要：模板/机器码字节/汇编文本 | 模板→生成 Frida JS；字节→`Memory.patchCode(hex)`；汇编→Frida `x86Writer`（JS 内写）或可选 keystone 离线生成字节 |
| 目标定位四种都要 | 复用现有 `resolve_base` / `unity_lookup` / `aob` / symbol，Frida 只做执行 |
| 远程调用任意原生函数 | `NativeFunction`（Frida 原生支持完整调用约定/多参/返回值，**免手写 callstub**） |
| session 级注册表 + detach 恢复 | `inject/registry.py` 登记 + frida session 分离时自动卸载；原字节/脚本状态审计 |
| 沿用现有安全模型 | `E_ANTI_CHEAT` 硬拒绝（铁律）；`confirm`/`confirm_code` 双门；readonly profile 剔除；审计 |
| 新 MCP 组 `inject` + CLI `inject` | 按既定；`tools_catalog` 与 `test_surface_lock` 同步 |
| AI agent 提供逻辑 | payload 核心形态 = **agent 编写的 Frida JS 脚本**（token 最少、能力最强） |
| 接受可选依赖 | `frida` extra **已存在**（零新增声明）；keystone 仅作为可选 `asm` 离线工具（见 §8.3） |

---

## 3. 架构设计（Frida-first）

### 3.1 新子包 `src/game_modifier/inject/`

```
inject/
├── __init__.py        # 导出 + 工具组/子命令清单声明（供 mcp_server/tools_catalog 注册）
├── frida_bridge.py    # frida 懒加载封装：attach(pid)、脚本运行器、rpc、错误映射、生命周期
├── scripts.py         # Frida JS 片段构造：hook_attach/hook_replace/patch_code/nop/skip/log/call/module_load
├── templates.py       # 高级模板 → JS 生成（return_constant/nop_body/skip_call/log_args）
├── resolve.py         # 统一目标解析（复用现有四种定位，零新逻辑）
├── registry.py        # session 级 HookEntry 注册表（数据模型 + 序列化）
└── dryrun.py          # 脚本预检/干跑：不 attach 的前提下校验 JS 语法 + 目标 + 风险分级
```

### 3.2 与既有模块的依赖方向（严格向下，无包间反向依赖）

```
service.py / cli.py / mcp_server.py
        │
   inject/（新，仅消费既有能力 + frida）
     │  依赖：memory（base/windows/types/aob/pointers）、engines（unity_lookup）、
     │        analysis（disasm 用于 apply 后读回验证）、errors、safety、session
     ▼
   MemoryBackend + frida（可选 extra，懒加载）
```

- `frida_bridge` 需要 frida 时 `try: import frida`，缺失抛 `E_DEPENDENCY_MISSING`（hint：`pip install ".[frida]"`）。
- 新增 Win32 绑定需求极低（Frida 自管注入/线程/内存分配）；仅 `apply 后读回验证` 复用 `analysis.disasm` + 既有 `MemoryBackend.read`，**不新增原生 API**。
- **不复制 `_read_span_groups` 教训**：`inject` 不做内存扫描，无此需求。

### 3.3 Session 集成

- `session.py`：`Session` 增加 `hooks: dict[str, HookEntry]`（随快照/恢复序列化；恢复后地址需重新验证，沿用既有约定）。
- `service.py`：新增 `hook_apply / hook_list / hook_remove / hook_call / dll_inject / asm`；**close/detach 时对每个激活 hook：`session.detach()` → frida 自动卸载 → 清 `session.hooks`**。
- 安全门禁（入口统一在 service 层）：`detect_anti_cheat` 命中 → `E_ANTI_CHEAT`（沿用 `find_writers` 的 session 级拒绝模式）；dry-run 默认；可执行代码写入 `confirm_code=true`；每次 apply/remove 记 `audit.jsonl`。

---

## 4. 接口契约

### 4.1 数据模型（`inject/registry.py`）

```python
@dataclass
class HookEntry:
    id: str                  # "hk_ab3f"
    name: str
    target_spec: str         # 原始定位串（回显）
    target: dict             # resolve 结果 {address, module, kind, evidence}
    payload: dict            # {kind: "template"|"script"|"bytes"|"asm", ...}
    frida_script_id: str     # 关联的 frida Script id（frida 侧句柄）
    kind_desc: str           # "template:return_constant" 等
    arch: str
    installed: bool
    created_at: float
```

`to_dict()/from_dict()` 供 session 快照与 MCP 回显。

### 4.2 目标解析（`inject/resolve.py`，全部复用既有实现）

```
resolve_inject_target(session, target_spec, backend) -> dict
# {"address", "module", "kind": "symbol"|"expr"|"il2cpp"|"aob", "evidence"}
```

1. **symbol**：`session.symbols` 命中。
2. **地址表达式 / module+offset / 裸地址**：`memory.pointers.resolve_base`（含地址算术）。
3. **IL2CPP 方法名**（`Namespace.Type::Method` 形状）：`engines.unity_lookup.lookup_rva`（需 session 关联 script.json）→ `module_base + rva`；无 dump → `E_NEEDS_DUMP`。
4. **AOB 特征**（`aob:` 前缀或 hex+`??` 形状）：`memory.aob.aob_scan`；多命中 → `E_AOB_AMBIGUOUS`。

> 定位统一走工具自己的解析，**不**依赖 frida 的 `Module.getExportByName` 等，保证与既有 `read/modify` 的地址语义（含 `module+0x` 基准）完全一致，避免 MCP 地址语义漂移（retrospective §3 教训）。

### 4.3 错误契约（`errors.py` 新增）

- `E_NEEDS_DUMP`（IL2CPP 方法名缺 script.json）、`E_AOB_AMBIGUOUS`、`E_INJECT_SCRIPT_INVALID`（JS 校验失败，带错误行/列）、`E_INJECT_TARGET_UNSAFE`（目标解析成功但 frida 判定不可 hook：如纯数据地址请求 Interceptor 之类）。
- 复用既有：`E_ANTI_CHEAT`、`E_ACCESS_DENIED`（frida attach 权限不足，hint=管理员终端）、`E_DEPENDENCY_MISSING`、`E_PROCESS_EXITED`、`E_SYMBOL_NOT_FOUND`。
- 全部维持 `GameModifierError` + `hint` + `details` + 类级 `DEFAULT_HINT`（decisions/01 D27：错误必须自带下一步）。

---

## 5. 详细设计

### 5.1 frida 桥（`frida_bridge.py`）

```
FridaBridge(session) —— 惰性持有 frida，懒建：
  - attach(): frida.attach(pid)（失败映射 E_ACCESS_DENIED/E_PROCESS_EXITED；受保护进程→E_ANTI_CHEAT 语义提示）
  - run_script(js, *, name, on_message) -> Script：session.create_script + load
  - rpc_call(method, args)：经 script.exports 同步取回结构化结果（JSON 信封，沿用全包 ok/error 形状）
  - detach()：script.unload + session.detach（幂等；detach 即卸载全部 hook，天然"恢复"）
```

**错误映射表**（frida → 本项目错误码，全部在桥内收敛，上层只见本项目错误）：
| frida 异常 | 本项目 |
|---|---|
| `frida.ProcessNotFoundError` | `E_PROCESS_EXITED` |
| `frida.TransportError` / `ProcessNotRespondingError` | `E_PROCESS_EXITED`（hint 重 attach） |
| `frida.PermissionDeniedError` | `E_ACCESS_DENIED`（hint=管理员终端） |
| `frida.InvalidOperationError` | `E_ANTI_CHEAT`（受保护进程，不给绕过） |
| JS 运行时 throw | `E_INJECT_SCRIPT_INVALID`（带 rpc 错误信息） |

### 5.2 JS 脚本构造（`scripts.py` + `templates.py`）

**`hook_apply` 的 payload 四种形态 → JS**：

| payload.kind | 入参 | 生成的 frida 行为 |
|---|---|---|
| `template` | `name=return_constant, value=9999, ret_type` | `Interceptor.replace(target, new NativeCallback((...)-> value))`，或 onEnter/onLeave 改写返回值 |
| `template` | `name=nop_body, return_value?` | `Memory.patchCode(addr, n, ...)` 写 NOP/ret 序列 |
| `template` | `name=skip_call, call_offset/aob` | 定位 call 点，`Memory.patchCode` 覆写 5×NOP |
| `template` | `name=log_args, max_entries` | `Interceptor.attach(target, {onEnter(args){...}})` 记录到 JS 侧 buffer，经 `rpc` 读回 |
| `script` | `js=<agent 完整脚本>` | 原样 `create_script` 执行（最灵活，agent 自写逻辑，可含 x86Writer） |
| `bytes` | `hex="48 C7 C0..."` | `Memory.patchCode(addr, hex)`（直写字节） |
| `asm` | `text="mov eax,9999; ret", arch` | 优先 `x86Writer`（JS 内逐条写）；或离线 keystone 生成字节后走 bytes 路径（见 §8.3） |

**模板语义表**（与 v1 对齐，实现载体从机器码 stub 换成 JS）：

| 模板 | 参数 | 语义 | 对应 frida API |
|---|---|---|---|
| `return_constant` | `value`, `ret_type`(int/ptr/float), `mode=attach\|replace` | 函数恒返回常量 | `Interceptor.replace` + `NativeCallback` / `onLeave` 改写 |
| `nop_body` | `return_value?` | 禁用函数 | `Memory.patchCode` 写 `ret`/`xor;ret` |
| `skip_call` | `call_offset` 或 `call_aob` | 跳过内部调用点 | `Memory.patchCode` 5×NOP |
| `log_args` | `max_entries` | 记录每次调用参数 | `Interceptor.attach` + onEnter → rpc 读回 |

### 5.3 远程调用（`hook_call` → frida `NativeFunction`）

```
hook_call(session, target, *, args=[...], ret_type="int64", timeout, confirm) -> dict
# 构建 frida JS：NativeFunction(ptr(target), ret_type, [arg_types...])(...args)
# 返回值经 rpc 信封同步回传；无手写 callstub、无远程线程、无影子空间处理
```

- frida `NativeFunction` 原生处理 x64/x86 调用约定、多参数、int/float/ptr 返回——**彻底替代 v1 的 `callstub.py`**（v1 最大的实现风险点消失）。
- 超时/异常经 on_message 结构化回传，符合全包 `ok:false` 契约。
- `dll_inject --export` 的导出调用同样走 `NativeFunction`，两处共用同一 JS 构造器。

### 5.4 DLL 注入（`dll_inject` → frida `Module.load`）

```
dll_inject(session, dll_path, *, export=None, args=None, confirm) -> dict
# JS: const mod = Module.load(dll_path) -> 返回模块基址；export 存在则 NativeFunction 调导出
```

- 无需远程 `LoadLibrary` 线程、无需写路径到目标进程——frida `Module.load` 一行解决。
- 审计记录：dll 路径 + 导出名 + 模块基址。

### 5.5 生命周期（`registry.py` + service 集成）

- `hook_apply`：resolve → 构造 JS → **dry-run（不 attach 校验）** → confirm+confirm_code → frida attach → create_script → 登记 `HookEntry`。幂等：同 `target_spec` 已激活 → `E_ALREADY_INSTALLED` 或先 remove。
- `hook_list` / `hook_remove <id>`（卸载 = `script.unload`，frida 自动还原 Interceptor/补丁）。
- `close/detach`：统一 `bridge.detach()` 清场 + 清 `session.hooks`。
- 快照/恢复：hooks 元数据随 session 快照；恢复后地址需重新验证（沿用既有约定）。

### 5.6 安全集成（严格沿用现有模型，不加新授权开关）

| 现有机制 | 本能力如何使用 |
|---|---|
| `detect_anti_cheat`（decisions/02 铁律：禁止弱化） | 所有注入入口硬拒绝 `E_ANTI_CHEAT` |
| dry-run + `--confirm` | **frida 脚本执行新增 dry-run 语义**：`dryrun.py` 在**不 attach** 前提下做 JS 语法校验（`frida.Compiler` 或离线 parse）+ 目标/风险预检 + 回显将执行的脚本；`confirm=true` 才 attach 执行。这是"脚本执行"的干跑模型，需文档明确 |
| `confirm_code`（可执行区=high-risk） | Interceptor/`Memory.patchCode` 属代码级写 → 需 `confirm` + `confirm_code` 双门 |
| `BackupManager` + `audit.jsonl` | Interceptor 场景 frida 自带原指令恢复，不重复备份；**直写 `Memory.patchCode` 场景先经 `MemoryBackend.read` 备份原字节** + 审计 |
| readonly profile | `inject` 组整体不注册（写工具 + 只读 `hook_list`/`asm` 按既有 readonly 划分） |
| `safety.max_write_bytes` | `Memory.patchCode` 单段长度仍受上限约束 |

### 5.7 apply 后验证

- `hook_apply` 成功后，用 `analysis.disasm` 读回目标地址前若干字节反汇编，与预期比对（`verified: true/false`），复刻 `il_verify` 的"补丁后读回"门。

---

## 6. MCP / CLI 接口规格

### 6.1 MCP 新组 `inject`（默认 profile 注册；`tools_catalog` 与 `test_surface_lock.py` 黄金 schema 同步）

| 工具 | 参数 | 返回要点 |
|---|---|---|
| `hook_apply` | `session`, `target`, `payload{kind: template\|script\|bytes\|asm, ...}`, `confirm=false`, `confirm_code=false` | `{ok, hook_id, address, kind_desc, verified}` |
| `hook_list` | `session` | `{hooks: [...]}` |
| `hook_remove` | `session`, `hook_id` | `{ok, restored, address}` |
| `hook_call` | `session`, `target`, `args=[]`, `ret_type`, `timeout`, `confirm` | `{ok, return_value, return_hex}` |
| `dll_inject` | `session`, `dll_path`, `export=null`, `args=[]`, `confirm` | `{ok, module_base, export_result}` |
| `asm` | `arch`, `code`, `base=0` | `{ok, bytes_hex, size}`（离线汇编；keystone 缺失 → `E_DEPENDENCY_MISSING`） |

readonly profile：`hook_list`/`asm` 只读保留；`hook_apply/remove/call/dll_inject` 剔除（与既有 readonly 划分一致）。

### 6.2 CLI 子命令

```
game-modifier inject hook --session <id> --target <spec> --template return_constant --value 9999 --confirm --confirm-code
game-modifier inject hook --session <id> --target "GameAssembly.dll+0x1234" --code "48 C7 C0 0F 27 00 00 C3" --confirm
game-modifier inject hook --session <id> --target "Namespace.Type::Method" --script <file.js> --confirm
game-modifier inject hook --session <id> --target <spec> --asm "mov eax, 9999; ret" --confirm
game-modifier inject list --session <id>
game-modifier inject remove --session <id> --hook-id hk_ab3f --confirm
game-modifier inject call --session <id> --target <spec> --args 1,2 --ret-type int64 --confirm
game-modifier inject dll --session <id> --dll-path C:/Tools/myhook.dll --export Install --confirm
game-modifier inject asm --arch x64 --code "mov eax, 9999; ret"
```

`--target`：symbol / `module+0x` / 裸地址 / `Namespace.Type::Method` / `aob:48 8B ?? ?? 05`。
`--payload` 形态：`--template`、`--script`、`--code`（hex 字节）、`--asm`（汇编文本）。
输出单行 JSON（全包 `{"ok", "command", "data"|"error"}` 契约）。

---

## 7. 测试与文档同步义务（硬约束）

### 7.1 测试计划

**单元（mock frida，`pytest.importorskip("frida")` + `FakeFridaBridge` 替身）**
- `test_inject_bridge.py`：attach/run/rpc/detach 生命周期、frida 异常→本项目错误码映射表、懒加载缺失 `E_DEPENDENCY_MISSING`。
- `test_inject_scripts.py`：四模板 JS 生成断言（关键 API 调用存在 + 参数正确）、bytes→patchCode、asm→x86Writer 序列。
- `test_inject_resolve.py`：symbol / expr / module+offset / IL2CPP 方法名（fake script.json 索引）/ AOB（含 `E_AOB_AMBIGUOUS`）。
- `test_inject_registry.py`：session 快照序列化/恢复、detach 清场、幂等/`E_ALREADY_INSTALLED`。
- `test_inject_safety.py`：readonly profile 剔除、dry-run 不 attach、`confirm_code` 门禁、`E_ANTI_CHEAT` 拒绝、审计条目、`Memory.patchCode` 前原字节备份。
- `test_inject_dryrun.py`：JS 校验失败 `E_INJECT_SCRIPT_INVALID`、目标/风险预检。

**集成冒烟（真实 frida + `samples/target.py`，管理员终端）**
- 对 target 进程的**无害原生函数**（如 `kernel32!Sleep` / `time.sleep` 底层）做：hook_attach → disasm 读回验证 → hook_list → hook_remove 恢复；hook_call 传参读返回值；`samples/` 新增一个导出 `Install/Uninstall` 的最小 DLL 测 `dll_inject`。真实游戏验证留给使用者（文档注明）。

### 7.2 文档同步清单（HANDOVER §5.4 硬约束，缺失=缺陷）

| 文档 | 同步点 |
|---|---|
| `AGENTS.md` | 命令清单 + `inject` 组工具 + 错误码 + 安全契约段（脚本执行 dry-run 语义） |
| `USER_MANUAL.md` | 新增 `inject` 命令参考章节 + 引擎专题补"原生 hook" |
| `AI_AGENT_GUIDE.md` | 工具分组、token 实践（frida JS 脚本承载 payload）、错误码表 |
| `HANDOVER_GUIDE.md` | 能力矩阵更新：限制 #2（无汇编级修改）→ 已支持；长期路线图第 1 条 → 已落地；工具数/分组/测试基线 |
| `INSTALL_GUIDE.md` | `[frida]` extra 说明（已声明，补落地用法） |
| `skills/game-modifier/SKILL.md` | 新工具用法 |
| `README.md` | 功能概览表 + 可选依赖组速查（frida 行从"预留"改"已落地"） |
| `GAME_TECHNIQUES.md` | **§6"诚实边界"重写**：注入/hook/IL2CPP 原生补丁从"不能做"移入"能做"，给决策规则 |
| `docs/decisions/04-对外分享版.md` | 公开立场"不做代码注入、不做 hook"更新 + 决策记录追加（frida 路线落地、keystone 定位） |

### 7.3 回归
- 全量 `pytest` 通过；**`test_surface_lock.py` 黄金 schema 必须随新 MCP 工具同步（否则 CI 红，硬性项）**。
- `test_safety_profiles.py` / `test_write_risk.py` 扩展 inject 用例。
- wheel 重建：新增子包后按 HANDOVER §5.3 **先删 `build/` 与旧 `dist/*.whl`** 再 `python -m build --wheel`，解包确认 `game_modifier/inject/*` 在包内。

---

## 8. 实施顺序（里程碑）

| 里程碑 | 内容 | 完成标志 |
|---|---|---|
| M0 | `inject/frida_bridge.py` 骨架 + `[frida]` extra 接线（已存在，仅确认）+ 错误映射表 + `dryrun.py` | `test_inject_bridge` + `test_inject_dryrun` 绿 |
| M1 | `scripts.py` + `templates.py`（四模板）+ `resolve.py` + `registry.py` + service 接线 + 安全门禁 + apply 后 disasm 验证 | `test_inject_scripts/resolve/registry/safety` 绿 |
| M2 | `hook_call`（NativeFunction）+ `dll_inject`（Module.load） | `test_inject_call_dll` 绿 |
| M3 | MCP 组 `inject` + CLI + `tools_catalog`/`test_surface_lock` 更新 + **§7.2 全量文档同步** + 集成冒烟 | 全量 pytest 绿 + 冒烟通过 |
| M4 | （可选）keystone 离线 `asm` 增强 + 冻结改 hook（HANDOVER 长期第 3 条，作为独立后续项） | 各自测试绿 |

M0–M2 为核心价值（Frida-first 下 detour/call/dll 全是 frida 原生，实现量远小于 v1 手写方案）。

---

## 9. 风险与开放决策

1. **frida 依赖姿态**：frida 是重量级原生依赖，但**项目已预留 `[frida]` extra**，且 D9 优雅降级框架（可选组+懒加载）正是为此设计——姿态与项目一致。真实 frida 在部分受保护进程上 attach 失败：映射为 `E_ANTI_CHEAT`/`E_ACCESS_DENIED`，不提供绕过（02 铁律）。
2. **dry-run 语义迁移**：frida 脚本执行无法"只预览不运行"——dry-run = 离线校验 JS + 目标/风险预检 + 回显脚本，`confirm` 才 attach。这是对既有"写操作 dry-run"模型的新扩展，文档必须讲清。
3. **keystone 的去留（open）**：v1 曾引入 keystone，被 decisions/01 否决（"只读不写"）。Frida-first 下汇编由 `x86Writer` 在 JS 内完成，keystone 仅作为**可选离线** `inject asm` 字节生成器。倾向：**M4 再决定，M0–M3 不引入**（保持与 01 决策一致；若用户坚持要纯汇编文本→字节，再以可选 extra 引入并更新 01 记录）。
4. **`Interceptor.replace` vs `attach` 的语义差异**：模板默认 `replace`（替换实现）或 `attach`（包裹原实现，可调原函数）——工具需在模板参数里显式（`mode=attach|replace`），文档给示例。
5. **游戏更新失效**：AOB/IL2CPP 方法 RVA 定位的 hook 在游戏更新后失效——复用 `check_dump_freshness` 提示；AOB hook 记特征版本。
6. **`test_surface_lock` 与文档漂移**：M3 是硬回归项；文档同步义务（§7.2）纳入完成定义，否则按项目约束视为缺陷。

---

## 10. 后续（不在本次范围，记录备查）

- HANDOVER 长期第 3 条：**冻结机制改用 hook 而非轮询**（以本能力的 Interceptor/onLeave 改写为基础，消除 freeze 闪回）——单独排期。
- HANDOVER 长期第 2 条：结构体识别与自动字段推断（结合 Il2Cpp/UE dump 元数据）——与本能力互补，独立推进。
