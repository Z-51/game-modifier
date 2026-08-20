# game-modifier MCP 服务器深度评审报告

> 评审视角：MCP（Model Context Protocol）服务器实现质量 + 一次真实 Unity Mono 游戏逆向实战
> （Snapshot!：Mono.Cecil 手工补丁、PoliceNPC 视野链定位、trainer 集成、.cmd 编码事故）的对照检验。
> 代码基线：`src/game_modifier/{mcp_server.py, service.py, session.py, cli.py, errors.py, output.py, jobs.py, engines/il_tool.py, safety/*}`。
> 日期：2026-08-19

---

## 0. 架构快照（代码地图）

```
前端层        cli.py（96 个 subcommand，argparse）  ─┐
              mcp_server.py（92 个注册点 ≈65 个唯一工具，FastMCP stdio）─┤ 共享
                                                                         ▼
服务层        ModifierService（service.py，4521 行，无任何锁原语）
              ├─ 会话持久化：SessionStore（session.py，tmp+rename 原子写）
              ├─ 后台任务：JobManager（jobs.py，daemon 线程 + 结果落盘）
              ├─ 审计：audit.jsonl（append-only）
              └─ 安全：confirm 门 + max_write_bytes + 风险分级 + auto_backup + 反作弊签名表
外部进程      il-tool.exe（.NET/Mono.Cecil，每次调用一个子进程）
              Il2CppDumper / radare2 / rizin / x64dbg / windbg / binaryninja（toolchain/registry.py）
引擎抽象      engines/{detect, unity, unreal, nwjs, mono_layout, unity_lookup, ue_introspect}
```

**总体判断**：架构方向正确——单服务核心 + 多前端 + 外部进程桥接 + 类型化错误 + 审计/备份完备。但存在 5 个会真实咬人的短板：**并发无锁、落盘结果无 MCP 读取通道、il-tool 子进程每调用一次、双前端 schema 漂移、文件类工具无路径白名单**。以下按七维度展开。

---

## 1. 架构设计

### 现状（代码依据）
- `mcp_server.py:358` `build_server()`：按 `profile`（default/readonly/dry-run/symbols/limited）与 `groups`（11 组）条件注册工具；`_tool()` 装饰器跳过组外工具（:412-420）。设计克制，`tools_catalog` 常驻帮助 agent 选组。
- `_import_fastmcp()`（:31-57）兼容 mcp v1.x / v2.x / standalone fastmcp 四种导入路径——版本漂移防御意识好。
- `_envelope()`（:60-67）统一异常 → `Result` 信封；`output.py` 定义稳定 JSON 契约。
- CLI 与 MCP 共享 `ModifierService`——职责单一，正确。

### 问题
1. **service 层零并发防护**（`grep Lock|threading|Semaphore` 在 service.py 命中 0）。FastMCP 工具经线程池并发执行，而所有会话操作都是 `load(session) → mutate → save(session)`（如 `service.py:936-943` modify 流程）：两个并发调用同一会话 → 后写覆盖先写（**lost update**）。freeze 守护线程（`freeze_start` 常驻循环）与请求线程同写 session 也存在竞争。`session.py:782` 的 save 本身原子（tmp+replace），但 read-modify-write 不原子。
2. **双前端 schema 手工双份**：CLI 96 subcommand（cli.py `add_parser`）× MCP 92 注册点 × service 方法签名，三处独立维护。改名/加参必漂移（本次会话里 trainer 与 MCP 的 il_* 参数面已不一致：MCP 的 `il_patch(op, method, value, target, out_assembly)` vs 笔记里的 CLI 形态）。
3. **FastMCP 版本未钉**：多版本导入是防御，但没有 CI 矩阵验证 v1/v2 下 schema 生成、并发模型、截断行为一致——升级 mcp 包可能静默改变工具契约。
4. **会话生命周期是"每次全量 load/save"**：候选集已 sidecar 化（`session.py` ScanState.write_candidates_file），但 session.json 仍每操作重写；高频轮询（watch/freeze）路径的写放大值得记账。
5. **MCP resources/prompts 完全未用**：sessions 目录、il dump 产物、mono 索引都是天然 resource；标准工作流（attach→scan→name→modify→verify）应是 prompt 模板。

### 改进建议
- **P0 会话级 RWLock**：service 加 `threading.RLock` per-session 装饰器，写路径（modify/nl/name_*/il_patch/backup/freeze 注册…）串行化；freeze/watch 线程改用"租约+心跳"避免与请求线程互踩。
- **P1 schema 单一来源**：定义一份工具规格（装饰器 + dataclass 参数表），同时生成 argparse parser、MCP tool schema、CLI/MCP 对齐 CI 断言（`set(cli_subcommands) == set(mcp_tools)` 作为测试）。
- **P2 MCP resources**：注册 `game-modifier://session/{id}/**` resources 暴露会话文件；注册 prompts 提供标准逆向工作流，agent 首次 attach 后自动获得操作序列。
- **P2 CI 矩阵**：`pip install mcp==1.x / 2.x / fastmcp` 三档各跑一遍 schema 快照测试。

---

## 2. 功能完整性

### 覆盖良好
内存扫描/精炼/AOB/指针链、watch/freeze/find_writers（硬件断点）、符号表与链、batch/macro/template、UE introspect 三件套、Il2Cpp/Mono 对象读取、IL 全链路（analyze/dump/callers/patch/verify/backup/restore）、存档编辑（rmmz/renpy/unity-encrypted）、会话快照/审计/备注、工具链探测。65 个工具覆盖主流场景，**本次实战的警察链定位（ViewCone→SeesPlayer→BustPlayer）所需的信息全部在工具能力内**。

### 真实缺口（本次实战直接暴露）
1. **【最痛】落盘结果无 MCP 读取通道**：`il_dump`/`il_analyze` 把完整列表写 `sessions/<id>/il/*.json`，内联只回 `instruction_count` 摘要（`service.py:3794-3810`），**MCP 工具面没有任何 file-read 工具**（grep `file_read|results_read` 命中 0）。纯 MCP 客户端（如只挂本服务器的 agent）**拿不到 IL 指令流，却要基于它写补丁**。本次会话我是靠宿主自带 read 工具绕开的——但这是"钻空子"，不是产品能力。
2. **字段引用扫描缺失**：本次手写 PowerShell 全程序集扫 `bustPlayer/viewCone` 的 ldfld/stfld 点。`il_callers` 只扫方法引用。→ 补 `il_fieldrefs(field=, op=all|ldfld|stfld)`（il-tool 的 callers 命令同构，半天工作量）。
3. **无 C# 反编译视图**：`il_dump` 输出 IL 助记符，agent 解读效率低（本次我逐条读 IL 数小时）。→ 集成 ilspycmd（MIT OSS）做 `il_decompile(method)`，控制输出长度（按 token 预算截断 + spill）。
4. **无 ldstr/字符串表检索**：从 UI 文案/日志字符串反查逻辑是常见入口。→ `il_strings(substr, type_filter)`。
5. **无程序集 diff**：本次对比 orig vs 当前 DLL 的方法体差异靠手工。→ `il_diff(assembly_a, assembly_b, method?)` 输出方法级差异摘要。
6. **`il_analyze` 的 member_filter 在客户端过滤**（`service.py:3764-3779`）：先让 il-tool 全量返回再在 Python 过滤，大程序集浪费传输。→ 把 filter 下沉进 il-tool 请求。
7. **方法选择器歧义静默取第一个**：RE 笔记已记录 `il_dump` 对 `ModPhotoLoader` 类误解析（方法同名不同类）。工具应显式返回歧义错误（`E_IL_METHOD_NOT_FOUND` details 携带候选清单），而不是让 agent 猜全限定名。

### 建议
按 P0 补 `results_read(path, offset, limit)`（或让 il_dump 在 ≤200 条指令时内联返回）；P1 补 fieldrefs/strings/diff/decompile；P2 把 member_filter、歧义报错下沉到 il-tool 契约（protocol v1 版本化）。

---

## 3. 性能表现

### 现状
- 扫描：numpy 向量化 + `ThreadPoolExecutor(workers=4)`（memory/scanner.py:493），候选集二进制 sidecar，指纹缓存（strict/lenient 两档，config.py:125）。
- 输出：50,000 字符截断（`_truncate_output` 二分收缩 list 字段，mcp_server.py:87-127），batch 专属 `_compact_batch_output` + `results_file`。
- 长任务：pointer_scan 有 async 通道（jobs.py daemon 线程 + 结果落盘）；scan 同步。

### 瓶颈
1. **【P0】il-tool 每次调用 = 一个子进程**（engines/il_tool.py:107 `subprocess.run`）：spawn + .NET JIT + Cecil 全量 ReadAssembly ≈ 1–3s/调用。agent 交互流程（analyze→dump→patch→verify）几十次调用 = 分钟级等待。这是本次实战延迟的最大来源。
2. **【P0】IL 侧无索引缓存**：mono_dump/il2cpp_dump 有 index+fingerprint 缓存，`il_analyze` 却每次全量重跑（stale_warning 基建已在算文件 hash，直接复用即可缓存 analyze 输出）。
3. **截断只收 list 字段**：dict 型大负载（`dissect` 的 fields、`session_survey`）超限时退化为一句 note，结构信息全丢。→ 通用化 leaf-list 截断 + totals + spill-to-file 三件套。
4. **scan/scan_aob 同步阻塞**：期间占住 MCP 线程；只有 pointer_scan 支持 async。→ scan 也走 jobs.py async 通道（jobs.py 已通用，改动小）。
5. session.save() 每操作全量重写 session.json——与架构节同源，合入 RWLock 方案一并优化（脏标记 + 延迟落盘）。

### 建议
- il-tool 改**常驻 worker**：C# 端已按"stdin 一行请求 / stdout 一行信封"协议工作，改成循环读行即可常驻；Python 侧 keep-alive 子进程 + 请求队列 + 崩溃自动重启。延迟预期降 5–10×。
- analyze 输出按 assembly sha256 缓存到 `sessions/<id>/il/`，指纹变化即失效（复用 `_file_hash_stale_info`）。

---

## 4. 错误处理

### 现状（做得好的部分）
`errors.py` 是亮点：约 40 个稳定 `E_*` 码 + `GameModifierError{message, hint, details}` + 类型化子类 + 类级 `DEFAULT_HINT`；`_il_run` 把 il-tool 的错误码映射为类型化异常（service.py:3726-3745）；确认写失败仍留审计轨迹（il_patch:3890-3899）；`details` 常携带"下一步参数"（如 `NEEDS_SCAN` 提示具体命令）。

### 问题
1. **提示语言混杂**：message 英文、hint 大量中文（errors.py DEFAULT_HINT、service.py 内联 hint）。MCP 契约是跨语言的——agent 解析英文 code 时还要理解中文 hint，且不同 locale 的用户体验割裂。
2. **E_INTERNAL 吞栈**：`_envelope` 只留 `TypeName: message`（mcp_server.py:66-67），远端排障靠猜。→ `config.debug=true` 时附截断 traceback，默认不附（token 友好）。
3. **hint 是自由文本，不是结构化 next-action**：agent 要解析散文决定下一步。→ 在 details 里加 `recovery: {"action": "...", "args": {...}}`，与 hint 并存。
4. **并发冲突无错误码**：同一会话被并发修改没有信号（见架构节），属于"静默丢更新"而非可恢复错误——需要锁而非错误码，但可加 `E_SESSION_BUSY` 兜底。
5. **il-tool 业务错误码透传有限**：仅 IL_PATCH/VERIFY/ASSEMBLY/METHOD 四类透传，其余归 TOOL_FAILED + stderr_tail。→ 契约层增加"il-tool 内部异常码直通"，避免二次映射丢失。

### 建议
P1 双语或纯英文 hint + `recovery` 结构化字段；P1 debug 模式栈；P2 错误码 → 恢复动作的映射表文档化（agent 可缓存为工作流知识）。

---

## 5. 用户体验 / token 效率

### 现状
JSON 契约（紧凑）、50k 截断 + `preview_note` + `totals`、`results_file` 持久化提示、`tools_catalog` + `--groups` 精简上下文、`value_convert` 防算术幻觉、warnings 数组、session_notes 跨请求记笔记——整体 token 意识强。

### 问题
1. **最大体验断裂 = il_dump 内联无内容**（见 2.1）：agent 看到的是"指令数 N"，要改方法却看不到指令——逼着 agent 猜或绕路。
2. **session_survey 一次拉太多**：engine+modules+symbols+freezes+backups+toolchain+health 一锅端，易被截断成碎片。→ 分级（summary/detail）。
3. **无重复读缓存**：同一地址反复 read（agent 循环探索）每次都走 WinAPI。→ 服务端短 TTL（如 200ms）读缓存，仅 read/watch 路径。
4. **上下文保持依赖宿主文件能力**：会话/符号/结果都在磁盘（好），但"如何引导 agent 恢复"没有标准 prompt（见架构 5：MCP prompts）。
5. **命令间数据传递**：symbol 表 + macro + template 已覆盖；`name_chain` 中间符号 temp 机制不错。缺"上次操作结果引用"（如 `$last`）——小事，可不做。

### 建议
P0 修 il_dump 内联；P1 survey 分级 + read 短缓存；P2 prompts 模板（标准工作流 + 恢复流程）。

---

## 6. 安全性

### 现状（分层）
1. **注册门控**：readonly/symbols/limited/dry-run 四个非默认 profile（mcp_server.py:284-332），`WRITE_TOOLS` 集合是回归锚点。
2. **运行时档位**：`safety_set_level('dry_run_only')` 服务端拒 confirm（service.py:320-330），进程内、不落盘。
3. **写门**：confirm 门 + `max_write_bytes=4096` + `require_writable_region` + 风险分级 `_classify_write_risk`（code/data 区域分类）+ auto_backup + 写后读回 verify + audit.jsonl。
4. **文件恢复安全**：`file_restore` 拒绝游戏进程存活时恢复、sha256 复核（service.py:4122-4140）。
5. **反作弊**：`safety/guard.py` 签名表覆盖 15 家主流 AC，attach 默认拒绝 + `allow_anti_cheat` 显式开关（service.py:350-356）。
6. save_edit 的加密 key 仅内存不落盘——正确。

### 问题
1. **【P0】文件类工具无路径白名单**：`file_snapshot(path)` / `file_restore` / `save_edit_modify(path)` / `batch` 的 `file=` 接受**任意路径**，restore 以 tmp+rename 覆盖任何用户可写文件。stdio 本地部署风险可控，但一旦经 HTTP transport 暴露或服务器以高权限运行，就是任意文件覆盖。→ `[safety.allowed_paths]` 白名单（默认游戏目录 + sessions 目录），路径归一化（解析 `..`/symlink）后校验。
2. **高风险单写无 confirm_code**：batch 有 confirm_code 释放高风险；单次 `modify` 写代码区只有 risk 标注（service.py:980）——口径不一致。→ 高危单写也要求 `confirm_code`（与 batch 同款）。
3. **反作弊检测面可补**：仅进程/模块名子串；缺少内核驱动枚举、以及本次实战遇到的"游戏目录 FileSystemWatcher 型软反作弊"启发。→ 可选扩展扫描（不阻断，warnings 提示）。
4. **HTTP transport 无认证**：FastMCP 支持 http；若启用必须带 token/allowlist，并在文档明示风险（当前 stdio 本地假设成立）。
5. `safety_set_level` 仅 default profile 注册（mcp_server.py:1436）——正确；建议文档化"任何 profile 变更必须重启生效"。

### 建议
P0 路径白名单 + 高危单写 confirm_code；P1 AC 检测面扩展（启发式 warnings）；P2 传输层安全文档 + 可选 token。

---

## 7. 扩展性

### 现状
- 工具链 registry（toolchain/registry.py ToolSpec：名称/版本探测/搜索目录）覆盖 radare2/rizin/x64dbg/x32dbg/cdb/windbg/binaryninja/il2cppdumper/il2cppinspector/ue4dumper/ue4ss。
- `xrefs` 双后端：radare2 静态分析 → 缺时纯 Python 内存扫描兜底（memory/xrefs_fallback.py）——**优雅降级范式**。
- 引擎抽象 `engines.detect` 按信号路由；`ue_introspect` 的 "probe→hypothesis→confirm→cache" 模式优秀（引擎布局可学习）。

### 问题
1. **il-tool 是闭源黑盒**：C# 端已知 bug（replace_body 无 body 参数导致方法体变 ret、ModPhotoLoader 类名误解析、patch 整程序集重写改变文件大小）只能外部绕（RE 笔记第 6 节全是绕行记录）。→ 至少把 iltool 源码纳入仓库 + 协议版本化 + 集成测试矩阵；或提供等价 Python 路径（pythonnet/Cecil）。
2. **无插件机制**：新工具/新引擎需改核心代码。→ ToolSpec 扩展点 + 引擎 handler 注册表（`entry_points`），第三方可插拔；`tools_catalog` 自动聚合。
3. **新引擎适配成本**：当前 unity/unreal/nwjs 为主；GameMaker/Godot/自研引擎无运行时布局支持。→ 泛化 ue_introspect 的 probe 模式为"引擎探测 DSL"（结构模式 + 校验 + 缓存），新引擎=写一段探测描述而非核心代码。
4. **工具版本探测已具备**（_query_version）——保持并文档化约定（版本命令格式）。

### 建议
P1 il-tool 开源化 + 契约测试；P2 插件注册表 + 引擎探测 DSL；P3 工具链适配器模板（当前 adapter 是薄封装，可模板化生成）。

---

## 8. 优先级路线图

| 优先级 | 改进项 | 维度 | 工作量 |
|---|---|---|---|
| **P0** | `results_read` 工具 / `il_dump` 内联返回（≤200 指令） | 功能/UX | 0.5d |
| **P0** | service 层 per-session RWLock（freeze/watch 线程租约） | 架构/正确性 | 1d |
| **P0** | il-tool 常驻 worker 进程 + analyze 输出按 sha256 缓存 | 性能 | 2d |
| **P0** | 文件类工具路径白名单 + 高危单写 confirm_code | 安全 | 1d |
| **P1** | schema 单一来源（CLI/MCP/文档三端对齐 CI） | 架构 | 2d |
| **P1** | il_analyze filter 下沉 + 方法歧义显式报错 | 功能/错误 | 1d |
| **P1** | 双语/纯英文 hint + `recovery` 结构化字段 + debug 栈 | 错误/UX | 1d |
| **P1** | scan 走 async 通道 + session_survey 分级 | 性能/UX | 1d |
| **P2** | il_fieldrefs / il_strings / il_diff / il_decompile(ilspycmd) | 功能 | 3d |
| **P2** | MCP resources/prompts + 会话恢复工作流模板 | 架构/UX | 1d |
| **P2** | il-tool 开源化 + protocol v1 契约测试 | 扩展 | 2d |
| **P2** | FastMCP v1/v2 CI 矩阵 + HTTP transport 认证文档 | 架构/安全 | 1d |
| **P3** | 引擎探测 DSL + 插件注册表 | 扩展 | 3d+ |

---

## 9. 附：本次实战经验 ↔ 代码对照表

| 实战教训 | 对应代码/机制 | 评审结论 |
|---|---|---|
| 手工 PowerShell 枚举 police 类型/字段 | 工具链缺 `il_fieldrefs`/类型枚举助手 | 补工具（P2），而非怪 agent |
| `il_dump` 输出噪音（PS 类型字面量报错是我方问题） | il-tool 方法选择器歧义（ModPhotoLoader） | 歧义显式报错（P1） |
| 手工对比 orig/current DLL | 无 `il_diff` | 补工具（P2） |
| .cmd UTF-8 中文乱码事故 | CLI 文档/示例的编码约定 | 属工具链文档，非 MCP 核心；建议 CLI 输出/文档统一 UTF-8 说明 |
| trainer 幂等检测（SHA 交叉验证） | `il_verify` + `_file_hash_stale_info` 模式 | 该模式应推广为所有写操作的标配（batch/il_patch 已有，存档编辑缺 verify 环节） |
| 补丁失败被"副本先行"纪律拦截 | `il_patch` dry-run + 自动 il_backup | 已具备，保持 |
