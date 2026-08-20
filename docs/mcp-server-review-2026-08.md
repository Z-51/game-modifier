# game-modifier MCP 服务器深度审查报告

> 审查日期: 2026-08-11
> 依据: 源码 `src/game_modifier/` 全部核心模块 + 一次真实逆向会话（Hand of Fate 2, Unity 2017.4 Mono x86）
> 会话痛点即真实用户反馈: 扫描覆盖波动、候选枚举受限、cache_stale 频繁、Mono 无工具支持、存档格式不支持

---

## 0. 总体评价

架构骨架（信封协议、错误码体系、会话持久化、profile 分级、工具分组）是同类 MCP 工具中少见的成熟设计。**核心短板集中在「扫描结果的消费链路」**：底层 scanner/aob 实现了完整能力，但 MCP 层只暴露了 20 个 sample 且无分页通道——**agent 在信息上被截断，却要做出定位决策**。本次会话中大量无效搜索（反复验证数据区候选）正是这一断层的直接后果。

---

## 1. 架构设计

### 1.1 工具注册机制 — 重复样板过多

**现状**：`mcp_server.py` 中 65 个工具通过 `@_tool(name)` 装饰器手工注册，每个工具 5-10 行样板；`profile` 系统导致同一工具注册 2-3 遍（default 块 + `dry-run`/`symbols`/`limited` 的 add-on 块，`modify`/`nl`/`batch_run`/`name_set` 等在 972-1083 行重复定义）。逻辑重复 → 维护时容易漂移（本次会话即观察到 dry-run 包装顺序的注释警告）。

**建议**：改为**数据驱动的工具规格表**——每个工具定义为一个 dataclass/spec（name, fn, schema, groups, writable, profiles），`build_server` 遍历规格自动注册。profile 差异收敛为"注册过滤器 + 包装器应用"两条规则，消除 200+ 行重复。

```python
@tool_spec(groups={"scan"}, readonly=True)
def scan(session: str, type: str = "int32", ...) -> dict: ...
```

### 1.2 请求处理 — 无进度通道、全同步阻塞

**现状**：`_envelope` 统一异常→信封（好设计）。但 `scan` 全量扫 1.6GB 时 MCP 调用阻塞数分钟，agent 无任何中间反馈。CLI 有 `--progress` 回调（service.py `progress_cb`），**MCP 层没有把进度接到 FastMCP 的 `McpProgress`/通知机制**。

**建议**：
- scan/scan_aob 增加 `async_run=True` 模式（复用 jobs.py 的 job_status 轮询，pointer_scan 已有先例）
- 或注册 FastMCP 进度处理器，把 `_emit_progress` 桥接到 `server.request_context.session.send_progress_notification()`

### 1.3 会话管理 — 每调用全量 IO、无并发控制

**现状**：`SessionStore.load()` 每次调用读整个 session JSON（`list_sessions` 会对每个 session 全量 load——`session.py:497-504`）；`save()` 每次全量写盘。后台 worker（watch/freeze/jobs）与主进程并发写 session 无锁。

**建议**：
- 服务层加会话内存缓存（TTL + 写穿透）
- `list_sessions` 只读 JSON 头部元数据而非全量反序列化
- 侧车文件写采用 temp+rename（已部分做到）

---

## 2. 功能完整性 — 本次会话的三大断层

### 2.1 候选枚举：只读工具永远只看得到 20 个地址（最高优先级）

**代码证据**：
- `scanner.py:49-60` `ScanResult.to_dict(sample=20)` 硬编码 20 个 sample，**无 offset/page 参数**
- `service.py:397` scan 返回 `res.to_dict()`，透传 20 个
- `aob.py:133` `addresses_hex` 只取 20，但 `addresses` 字段返回全量——**MCP 层被 `_truncate_output`（mcp_server.py:86-126）bisect 截断成 preview，无分页通道**
- `scan_next` 同样只有 20 个

**会话实证**：`scan(int32=10)` 返回 20000+ 候选只能看到 20 个低地址数据区 sample；`scan_aob` 235 个命中只能看 20 个；`scan_candidates.bin` 阈值 5000 以下被删除（`service.py:419-427`），agent 无任何读取完整候选集的路径。**CE 的"看到列表、按地址筛选"在 MCP 层不存在。**

**建议（实现方案）**：
1. `scan`/`scan_next`/`scan_aob` 增加 `offset`/`limit` 参数（batch_run 已有先例，`mcp_server.py:551`）
2. 新增只读工具 `scan_candidates(session, offset, limit, filter_addr_range=None)`——从 session.scan（含侧车加载）分页返回候选 + 值
3. `scan` 返回 `candidates_file` 路径字段，让 agent 可读侧车（二进制格式需要 `array('Q')` 解析说明）

### 2.2 Mono 引擎：检测为一等公民，工具为零

**代码证据**：`detect.py:60-74` 完整检测 `unity-mono`；但 `TOOL_GROUPS`（mcp_server.py:247-270）只有 `ue`/`il2cpp` 两组引擎工具，**没有 mono 组**。`il2cpp_list`/`il2cpp_dict`/`il2cpp_string` 全是 IL2CPP 专用布局（Il2CppString 头 @+0x10/+0x14）。

**会话实证**：Unity 2017.4 Mono 游戏（大量存量作品）——无法解码托管字符串、无法遍历 List/Dictionary、无法定位静态字段（`Player.m_instance` 单例），全程只能用值扫描+结构猜测，最终 stat 本体定位失败。

**建议（最高价值新工具组 `mono_*`）**：
- `mono_string`：Mono System.String 布局（vtable + len@+4 + UTF-16 chars@+8），与 Il2Cpp 仅偏移不同——可复用 `il2cpp_string` 的解码器抽象
- `mono_list`/`mono_dict`：**Mono 与 IL2CPP 的 List<T>（_items/_size）布局相同**，`il2cpp_list` 实现可直接参数化复用
- `mono_static`：定位类静态字段（本次死穴）。实现方案：扫描 mono JIT 代码区中 `ldsfld` 编译产物（x86: `A1 xx xx xx xx` / `8B 0D xx xx xx xx` 直接嵌静态地址），或从 MonoDomain/MonoClass 结构遍历（需要固定结构表，按 mono 版本）
- `mono_heap_scan`：按 vtable 枚举托管堆实例（本次自写 C# 扫描器已验证可行，可作为官方实现）

### 2.3 字符串扫描未暴露

**代码证据**：`scanner.py:161-165, 495-535` 完整支持 string/bytes 类型扫描（`_scan_bytes`），但 `scan` 工具 description 未提及，无 UTF-16 选项。

**会话实证**：本可扫 UI 显示文本（"24"）定位显示源，因工具不可见而未用。

**建议**：`scan(type="string", value="24", encoding="utf16le")` 显式支持；string 候选天然比 int 稀疏，正是 CE 用户定位 UI 值的经典路径。

---

## 3. 性能表现

### 3.1 扫描覆盖波动 — AOB 提前截断是根因

**代码证据**：`aob.py:152-155` 攒满 `max_results` **立即返回**（不扫剩余区域）；`scanner.py:254-257` 同样截断即停。

**会话实证**：AOB 命中密集时只扫了 40MB/50 区域（vs 全量 1.6GB/1600 区域）——低地址数据区噪声把扫描器"截停"在堆区之前，**高地址托管堆永远扫不到**。这是本次 stat 定位失败的第一技术原因。

**建议**：
- `scan_aob` 增加 `min_addr`/`max_addr`/`region_filter`（如 `heap_only=True`）参数——agent 可直接指定堆区间
- 返回 `scanned_bytes`/`scanned_regions` 已做（好），但应在 `truncated=True` 时**明确提示未扫区域占比**（当前 `truncated` 布尔无法表达"只扫了 2%"）

### 3.2 截断机制 — bisect 反复序列化

**代码证据**：`_truncate_output`（mcp_server.py:86-126）用**二分法反复 json.dumps 整个信封**找截断点——O(n log n) 序列化开销，且对"20 个地址 + 20 个值"的字典结构截断粒度粗。

**建议**：改为**按字段预估 + 单次序列化**（按 key 顺序预算字符数），或直接依赖 `_compact_batch_output` 的"摘要 + results_file"模式并推广到 scan（scan 也持久化完整结果文件）。

### 3.3 无区域过滤的全量扫描

**代码证据**：`scanner.py:178-181` 区域过滤仅 `max_region_bytes`（默认 0=不过滤）；`windows.py:460-479` 全量 VirtualQueryEx 遍历。

**建议**：`scan` 暴露 `min_addr`/`max_addr`/`region_type`（PRIVATE/MAPPED/IMAGE）——CE 的"内存区域列表"功能缺失，agent 无法先看区域分布再定向扫描。

### 3.4 并行度

`workers=4` 线程池 + numpy 向量化已好；纯 Python 路径（无 numpy）退化为单线程（GIL）。建议 `multiprocessing` 路径（地址计算纯 CPU）或官方依赖声明 numpy 为必选。

---

## 4. 错误处理

### 4.1 cache_stale 触发过频 — 动态过滤流程的隐形杀手

**代码证据**：`service.py:441-447` fingerprint = 全部 region (base,size) 的哈希；**任何 VirtualAlloc（游戏场景加载/对象分配）都会改变 region 列表** → fingerprint 不匹配 → `cache_stale=True`。scan_next 仍执行，但结果被标记。

**会话实证**：两次 scan_next 全部 cache_stale——CE 标准流程（scan → 游戏内操作 → scan_next）中游戏操作几乎必然伴随内存分配，**stale 是常态而非例外**。且 stale 时仍返回结果（0 候选），agent 无法区分"真 0 候选"与"stale 假 0"。

**建议**：
- fingerprint 改为**宽松指纹**：只哈希堆区/主要 PRIVATE 区域，忽略小分配（<64KB 变化）
- 或返回 stale 时**同时给出"候选集仍有效的置信度"**（如 region 变化只发生在低地址数据区时 confidence 高）
- `scan_next` 支持 `retain_stale=True` 强制用旧候选（明确告知风险）

### 4.2 scan_aob 不写侧车 — 大候选集 JSON 内联爆炸

**代码证据**：`service.py:492-500` AOB 直接构造 ScanState 存 JSON，**不走 `_store_scan_state` 的侧车逻辑**——235+ 候选全量内联进 session JSON，且不能被后续 scan_next 有效复用（addresses 在 JSON 里）。

**建议**：AOB 复用 `_store_scan_state`（含侧车阈值），并支持 `scan_next` 在 type="bytes" 上的 exact/changed 过滤（scanner 已有 `_next_scan_varlen` 支持）。

### 4.3 PatternNotFoundError 语义

AOB 无命中时 raise E_PATTERN_NOT_FOUND（`aob.py:162-167`）——对"模式搜索"场景合理；但 agent 可能想"没找到但扫了多少区域"——details 已含 scanned_regions/bytes（好）。建议保持现状。

---

## 5. 用户体验 / token 效率

### 5.1 20 个 sample 反而浪费 token

**会话实证**：反复返回"0x935f68 数据区地址 ×20"，agent 无法决策 → 无效的验证循环（本次 15+ 次 batch 验证数据区候选）。**低信息量的 sample 比没有更耗 token**。

**建议**：scan 默认返回**结构化摘要**（按地址区间聚合计数：`"low_addr": N, "heap_addr": N`）+ 每区间 3-5 个代表 sample + 明确分页入口。让 agent 先做一次**区域级决策**再下钻。

### 5.2 batch YAML 需手写磁盘文件

**会话实证**：手工写了 15+ 个 `_re_batch_verify*.yaml` 文件，每次都要 Write + batch_run。batch_run 的 `file` 参数是磁盘路径。

**建议**：`batch_run` 支持 `yaml`（内联字符串）参数（macro_run 已有 JSON 内联先例），并增加**只读 `batch_preview(yaml)`** 用于先 dry-run 校验。

### 5.3 AOB 结果无持久化文件

aob 无 results_file（batch 有 `save_batch_result`）。建议 scan/scan_aob 统一持久化完整结果到 `sessions/<id>/scan_results/`，返回路径。

### 5.4 上下文保持

符号表/会话/宏设计良好。建议补：**`session_notes` 工具**（agent 可在会话中存结构化笔记，跨调用保持上下文——本次大量中间结论（vtable 地址、对象结构）只能靠对话上下文携带）。

---

## 6. 安全性

### 6.1 现状（良好）
- 4 级 profile（readonly/dry-run/symbols/limited）+ 运行时 safety level
- 写操作：confirm 门 + 自动备份 + 回读验证（`verified_value`）+ 审计日志（audit.jsonl）+ 风险分级（高风险区需 confirm_code）
- `find_writers`（硬件断点改线程上下文）正确归入 WRITE_TOOLS

### 6.2 建议
- **profile 文档化到工具 description**：agent 在 readonly profile 下调用 modify 得到 E_PROFILE_RESTRICTED 才知道受限——建议 attach/session_info 返回当前 profile
- **批量写限流**：batch_run confirm=true 一次可写数千字节（max_write_bytes 是否对 batch 生效需确认）——建议 batch 独立限额
- **AOB 读保护**：scan_aob 对 PAGE_GUARD 区域已跳过（windows.py 区域过滤）✓

---

## 7. 扩展性

### 7.1 工具链集成 — 纯 Python 兜底缺失

**现状**：`toolchain/registry.py` + radare2/x64dbg/windbg/binaryninja/il2cppdumper 适配器。`xrefs` 依赖 radare2（未装则 E_TOOL_NOT_FOUND——本次 deep analyze 即如此）。

**建议**：
- `xrefs` 增加**纯 Python 兜底**：内存中扫描 4 字节引用（本次自写 FindRefs 已验证，1.6GB 约 10 秒）——不需要 radare2 也能回答"谁引用此地址"
- `analyze(deep=True)` 无 radare2 时应降级为"进程内自省"而非报错

### 7.2 引擎适配矩阵

| 引擎 | 检测 | 工具 | 状态 |
|---|---|---|---|
| Unity IL2CPP | ✓ | dump/lookup/string/list/dict | 完整 |
| Unity Mono | ✓ | **无** | **空白（优先补）** |
| Unreal | ✓ | introspect/actors/fname | 完整 |
| NW.js | ✓ | 无 | 空白 |
| RPG Maker/Ren'Py | ✓ | save_edit | 完整 |
| Defiant 系自定义存档 | ✗ | save_edit_detect 返回空 | 格式插件 API 缺失 |

**建议**：
- **mono_* 工具组**（见 2.2）为最高优先级——复用 il2cpp 解码器抽象（List/Dict 布局相同），成本低收益大
- **存档格式插件化**：定义 `SaveFormat` 抽象基类（detect/parse/modify/backup），Defiant 系自定义二进制格式（字段名标签 + varint + GUID，本次已摸清结构）可作为第一个社区插件——解决"内存改不动、存档改不了"的双重死锁

---

## 8. 优先级路线图

### P0（本次会话直接致困）
1. scan/scan_next/scan_aob 增加 offset/limit 分页 + `scan_candidates` 只读枚举工具
2. scan_aob 增加 min_addr/max_addr 区域过滤（解决低地址噪声截停）
3. scan 默认返回区域聚合摘要（替代 20 个裸 sample）

### P1（能力缺口）
4. `mono_*` 工具组（string/list/dict/static/heap_scan）
5. scan 支持 type="string" + UTF-16（UI 文本定位路径）
6. cache_stale 宽松指纹 + retain 模式

### P2（体验/效率）
7. batch_run 内联 YAML + batch_preview
8. scan/scan_aob 结果持久化 + results_file 返回
9. 会话笔记工具
10. xrefs 纯 Python 兜底

### P3（架构）
11. 工具规格表驱动注册（消除 profile 重复注册）
12. scan 异步模式（复用 jobs 机制）
13. 会话内存缓存 + 并发锁
14. 存档格式插件 API

---

# 第二部分（2026-08-12 增量）：DLL 修改会话的实证与新缺口

> 第二轮真实会话：在内存 stat 定位失败后，改用 **Mono.Cecil 手工脚本修改 Assembly-CSharp.dll** 实现金币 99 / 无限血量 / 攻击速度 ×4，全部成功。**关键事实：整个 DLL 修改流程 100% 绕过了 MCP 工具链**——agent 用 PowerShell + Cecil 脚本完成了一切。这暴露了工具链在「托管 IL 修改域」的完全空白。

## 9. 新会话实证（DLL 修改全流程）

| 步骤 | 本次实际做法 | MCP 是否有对应工具 |
|---|---|---|
| IL 元数据枚举（类型/方法清单） | 手工 Cecil 脚本 | ❌ 无（il2cpp_lookup 仅 IL2CPP RVA） |
| IL 指令 dump（方法体分析） | 手工 Cecil 脚本 | ❌ 无 |
| IL 调用点定位（GetFinalValue/CalculateAttackSpeed 的引用者） | 手工 Cecil 全类型扫描 | ❌ 无（xrefs 仅 radare2 且面向 native） |
| 方法体替换/指令插入 | 手工 Cecil 脚本 | ❌ 无 |
| 补丁后验证（读回 IL 确认） | 手工脚本 | ❌ 无 |
| DLL 文件级备份/回滚 | 手工 Copy-Item（pre99.bak / speed2x-before.bak） | ❌ 无（backup 仅内存字节快照） |
| 倍率调整（2x → 4x 重打） | 改脚本常量重跑 | ❌ 无 |

**结论**：对 Unity Mono 游戏，**DLL 补丁是比内存修改更可靠的最终方案**（本次：内存 stat 定位数小时失败 → IL 分析 30 分钟锁定精确修改点并成功）。而 MCP 的 65 个工具全部位于"内存读写/扫描"域，**托管 IL 域是结构性空白**。

## 10. 新增建议（按优先级）

### 10.1 `il_*` 工具组——托管 IL 分析/补丁（P0，最高价值）

目标：把本次手工 Cecil 流程变成 MCP 工具。服务端需内嵌 Mono.Cecil（.NET 库）——两个实现路线：

**路线 A（推荐，pythonnet 桥）**：`pip install pythonnet`，C# 侧封装 Cecil 操作（读元数据/dump IL/改方法体/写回），Python 侧暴露为工具。封装层约 200 行 C#。
**路线 B（dotnet 子进程）**：打包一个 `il-tool` 控制台程序，工具通过子进程调用（与 il2cpp_dump 调外部 Il2CppDumper 同模式，已有先例 `service.py:il2cpp_dump`）。

工具清单（全部复用 session 机制）：
- `il_analyze(session, assembly, type_filter, member_filter)` — 枚举类型/方法/字段（Cecil 元数据，不加载类型——本次反射 StackOverflow 的教训）
- `il_dump(session, assembly, type, method)` — 方法体 IL 指令流（含 Operand 解析）
- `il_callers(session, assembly, type, method)` — 全程序集引用扫描（Cecil 指令遍历找 call/callvirt/ldftn 指向目标方法者）——**这正是本次"GetFinalValue 被谁调用"的定位工具**，且纯 Python 可做（呼应第 7.1 节 xrefs 兜底建议）
- `il_patch(session, assembly, type, method, op)` — 补丁原语：`replace_body`（方法体整体替换为常量返回）、`insert_before_ret`（ret 前插指令）、`insert_after_call`（指定 call 后插指令，本次 ×4 的形态）
- `il_verify(session, assembly, type, method)` — 读回 IL 与期望模式比对（本次 verify 脚本的功能）
- `il_backup/il_restore(session, assembly)` — **文件级备份与回滚**（DLL 被进程锁定时的替换时序、多版本备份管理、与 audit.jsonl 集成）

**参数化补丁规格**：`il_patch` 的 op 支持参数（如 `{op: "mul_before_ret", value: 4.0}`），倍率调整 = 重打一次，无需改脚本（本次 2x→4x 需手改常量）。

### 10.2 文件级资源管理（P1）

`backup_create` 当前只做内存字节快照（`safety/backup.py`）。游戏目录文件（DLL/存档）的**版本化备份+回滚**是游戏修改的刚需（本次手动 Copy-Item 三次）。建议：
- `file_snapshot(session, path)` — 游戏目录内文件备份（带时间戳、进 audit）
- `file_restore(session, backup_id)` — 回滚（校验游戏未运行）
- 与 Steam 更新检测联动：文件哈希指纹在 session 中记录，更新后 `il_verify` 自动报"补丁失效"

### 10.3 引擎工具的 Mono 对称补齐（P1，承接第一部分 2.2）

| IL2CPP 已有 | Mono 缺失 | 实现备注 |
|---|---|---|
| il2cpp_lookup（RVA→方法名） | `mono_symbol`（Token/MDToken→方法名，或方法→RVA） | Cecil 元数据表即可，无需运行时 |
| il2cpp_dump（script.json 索引） | `mono_dump`（Cecil 全量类型/方法索引，sidecar 缓存） | 与 il_analyze 共享索引 |
| il2cpp_string/list/dict（运行时解码） | mono_string/list/dict（运行时解码） | 见第一部分 2.2（布局相同可复用） |

### 10.4 修改后的工作流差异（对工具设计的启示）

本次 DLL 修改的成功路径是**静态确定性**（IL 层 100% 可验证），而内存修改路径是**动态不确定性**（扫描器覆盖波动+候选噪声）。MCP 工具设计应显式区分两条路径并在 `analyze` 阶段给出**路线建议**：检测到 unity-mono + 托管逻辑 → 提示"DLL 补丁路线（需重启游戏）vs 内存扫描路线"的成本差异，避免 agent 在内存扫描上消耗数小时（本次教训）。

## 11. 更新后的优先级路线图

### P0
1. **`il_*` 工具组**（analyze/dump/callers/patch/verify/backup-restore，参数化补丁规格）
2. scan 分页 + `scan_candidates` 枚举工具
3. scan_aob 区域过滤 + 区域聚合摘要
4. `mono_symbol`/`mono_dump`（Cecil 索引）

### P1
5. `mono_*` 运行时工具组（string/list/dict/static/heap_scan）
6. scan string/UTF-16 + cache_stale 宽松化
7. `file_snapshot`/`file_restore` 文件级资源管理

### P2/P3
（沿用第一部分 8 节，另加）
- analyze 阶段输出"内存 vs DLL"路线建议
- il2cpp_dump 与 mono_dump 索引统一抽象
