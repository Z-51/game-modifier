# game-modifier 实践复盘：Unity 6 / IL2CPP 金币修改全链路剖析

> 日期：2026-08-02
> 目标游戏：《失落城堡 2》(Lost Castle 2)，Unity 6000.3.16f1 / IL2CPP metadata **v39**
> 目标：将存档金币修改为 999999
> 结论：**成功**，但过程暴露了工具链选型、MCP 地址语义、扫描性能、交互设计四类系统性问题。

---

## 1. 背景与全链路回顾

本次修改历经以下关键节点，每个节点都对应一类系统缺陷：

| 阶段 | 工具 | 结果 | 暴露的问题 |
|------|------|------|-----------|
| 引擎识别 | game-modifier `analyze` | ✅ 正确识别 unity-il2cpp 0.95 | 无 |
| 初版解析 | Il2CppDumper (C# v6.7.46) | ❌ `Metadata version 39 not supported` | 工具矩阵过时，无版本适配 |
| 次选方案 | Cpp2IL 2022.0.7 | ❌ 无法识别 Unity 6000.3 | 工具过时无降级路径 |
| 第三方案 | Il2CppInspector 2021.1 | ❌ 同样不支持 v39 | 同上 |
| 成功方案 | **il2cpp-dumper-rs** (Rust, 2026) | ✅ 17 秒 dump 成功 | 新工具只能靠人工 GitHub 搜索发现 |
| 编译成本 | cargo install | ⏱ 20 分钟 | 无预编译分发，无缓存 |
| 首轮扫描 | MCP `scan` (unknown) | ⚠️ 仅 60KB / 20000 候选上限 | 扫描区域策略与性能 |
| 全量扫描 | 纯 Python 逐字节 | ❌ >5 分钟超时 | scanner 非矢量化 |
| 加速扫描 | numpy 矢量化 | ✅ ~2 分钟 | 需手写脚本，工具内置缺失 |
| 数值破解 | 反汇编 ValidateHash/InternalDecrypt | ✅ 破解 ObscuredInt | 工具无"类型感知"能力 |
| 首次写入 | MCP `modify` + offsets | ❌ `E_INVALID_ADDRESS 0x98b0...` | **offsets 指针链语义 bug** |
| 二次写入 | 手工 Python | ⚠️ 显示旧值 | 游戏花费后重新生成 key |
| 最终写入 | 先读当前 key 再算密文 | ✅ 999999 生效 | key 重生成需在写前重读 |

### 关键发现：金币为什么普通扫描找不到

游戏使用 CodeStage **Anti-Cheat Toolkit (ACTk)** 的 `ObscuredInt` 存储金币，结构 16 字节：

```
ObscuredInt (16 bytes):
  int hash;            @0x0  FNV-1a 变体校验值
  int hiddenValue;     @0x4  密文 = (key ^ 真值) + key
  int currentCryptoKey;@0x8  随机密钥（每次写入重新生成）
  int fakeValue;       @0xC  诱饵值（检测到篡改时返回）
```

反汇编推导出的加解密与校验算法：

```c
// HideValue(plain): 加密
hidden = (key ^ plain) + key;
hash   = fnv_variant(plain);

// InternalDecrypt(): 解密
plain = (hidden - key) ^ key;

// ValidateHash(input, hash): FNV-1a 变体
h = 0x811C9DC6 ^ (input & 0xFF);
h = (h * 0x1000192) ^ ((input >> 8) & 0xFF);
h = (h * 0x1000192) ^ ((input >> 16) & 0xFF);
h = (h * 0x1000192) ^ ((input >> 24) & 0xFF);
h = h * 0x1000192;
return h | 1;   // 注意: 乘数 0x1000192 而非标准 FNV 的 0x1000193，末位 OR 1
```

**结论：对使用 ACTk 的游戏，普通精确值扫描（`scan 49`）必然 0 候选。** 必须先识别加密类型、反汇编其算法，再按特征扫描。

---

## 2. 维度一：工具链推荐时机问题

### 2.1 现状代码分析

`toolchain/registry.py` 的 `detect_all()` 仅做**存在性探测**，返回 `found: bool`；`service.analyze()` 遇到 `radare2 not available` 只作为 `static_error` 返回，无安装引导。且 registry 硬编码工具集：

```python
ToolSpec("il2cppdumper", ..., "Download Il2CppDumper (https://github.com/Perfare/Il2CppDumper) ...")
```

官方 Il2CppDumper **已停更**（2020 年后无实质更新，不支持 metadata v39），但 registry 仍将其列为唯一 Unity dumper。

### 2.2 根本原因

1. **探测 ≠ 引导**：检测到缺失时没有"一键安装 / 精确下载链接 / 版本验证"闭环
2. **工具矩阵过时**：无引擎版本（metadata version）→ 工具适配的路由表
3. **推荐时机缺失**：`attach` 成功后就应给出"该引擎需要哪些工具 + 缺什么"，而不是等用户在 `E_TOOL_NOT_FOUND` 上碰壁

### 2.3 改进方案

| 时机 | 动作 |
|------|------|
| `attach` 后 | 引擎检测结果关联工具矩阵，输出 `toolchain_needs`（精确工具名 + 下载 URL + 安装命令） |
| 首次 `analyze --deep` | 缺工具时返回**可执行安装脚本**（GitHub API 查 release → 下载 → 解压 → 校验） |
| 配置层 | `[tools.auto_install]`（默认 false），确认后装到 `~/.game-modifier/tools/` |

**关键教训：工具链推荐必须在 attach 成功那一刻主动给出，而不是等用户失败三次后去搜 GitHub。**

---

## 3. 维度二：MCP 工具地址解析缺陷（已修复，见文末）

### 3.1 实测 Bug

调用 `modify(address="0x21EF6F535B4", offsets="0x4")` 返回：

```
E_INVALID_ADDRESS: address 0x98b01623ca0b3375 is not in a mapped region
```

### 3.2 技术根源

`pointers.py` 的 `resolve_pointer` 将 offsets 定义为 **Cheat Engine 指针链语义**（每级解引用再偏移）：

```python
addr = base.address
for off in offsets:
    ptr = read_pointer(backend, addr)   # ← 解引用
    addr = ptr + off                     # ← 读到的是"指针值"+offset
```

而 `service._resolve_target` 对 `address + offsets` 参数**无差别**走这条路径。当用户传 `address=0x21EF6F535B4, offsets=0x4`（本意是**相对偏移**：直接在 base+4 处读写 ObscuredInt 的 hidden 字段）时，代码把 `0x21EF6F535B4` 处的 8 字节**当指针读出来**（恰好是大数），再 +4，得到垃圾地址 `0x98b0...`。

### 3.3 修复方案（P0，已实施）

- `resolve_pointer` 新增 `mode` 参数：`pointer_chain`（默认，向后兼容）/ `relative`（直接相加）
- `read` / `modify` / `name_set` / `backup_create` 全部透传 `mode`
- **智能默认**：`base_expr` 为纯绝对地址（`0x...`）且传了 offsets 时，自动降级为 `relative`；仅 `module.dll+0x...` 形式保持指针链。agent 也可显式指定 `mode`
- `resolve` 工具 trace 输出每级 `read_at/deref/offset`，便于语义自查

---

## 4. 维度三：反汇编解密性能瓶颈（已修复 scanner 矢量化，见文末）

### 4.1 实测数据

| 阶段 | 耗时 |
|------|------|
| 官方 Il2CppDumper (C#) | 失败（v39 不支持） |
| Cpp2IL (2022) | 失败 |
| **il2cpp-dumper-rs** | **17 秒** ✅ |
| cargo 编译 il2cpp-dumper-rs | 20 分钟 |
| MCP `scan` unknown 首扫 | 60KB / 20000 候选截断 |
| 纯 Python 逐字节扫 4.6GB | >5 分钟（超时） |
| **numpy 矢量化扫描** | **~2 分钟** ✅ |

### 4.2 深层原因

1. **scanner.py 纯 Python 逐 slot 循环**：对 4.6GB 内存 × 4 字节对齐 ≈ 11.5 亿次 `decode_value` 调用，解释器开销是瓶颈
2. **区域策略缺省**：`readable_regions()` 无差别扫描（含只读代码段、无意义映射），没有"私有堆优先"分层
3. **加密类型不可知**：scanner 不知道 ACTk 等混淆类型，`exact` 必然失败且无智能提示
4. **引擎适配器闲置**：`engines/unity.py` 的 `parse_dump_cs/find_field/parse_script_json` 已实现，但 MCP 工具层没有"符号 → 内存地址"桥接工具

### 4.3 优化方向

- **scanner 矢量化**（P0，已实施）：4/8 字节定长类型走 numpy 向量路径，`(a-b)^b` 一次比较；仅命中处回退 Python 解码
- **类型感知扫描**（P1）：新增 `type="obscured-int"` 虚拟类型，内置 ACTk 解密逻辑，`scan` 直接支持加密值
- **区域分层**（P1）：`MEM_PRIVATE` 堆优先，可跳过文件映射区
- **工具版本检测**（P1）：执行前读 `global-metadata.dat` 版本字节，>31 直接提示"官方版不支持，推荐 il2cpp-dumper-rs"

---

## 5. 维度四：用户体验与心理影响

### 5.1 真实时间线（对用户的不友好之处）

```
用户: 修改金币 →
  1. attach 成功（好）→
  2. scan 60KB（范围小，无解释）→
  3. 工具链失败 3 次（无自动升级提示）→
  4. 反复要求"请告诉我金币数""请花点金币" ×3（用户每次切窗口报数）→
  5. 30 分钟无进度反馈（用户："再给你十分钟""到底行不行？"）
```

### 5.2 设计缺陷

1. **交互反模式**：把用户当传感器——要求手动"改变状态再报数"是 Cheat Engine 手动作业的照搬；agent 应自动做"扫描→等操作→再扫"闭环
2. **无进度反馈**：长扫描无 `progress` 流式输出，用户无法区分"运行中"与"卡死"
3. **失败无根因提示**：`scan` 0 候选时无 `hint: "值可能被混淆(ObscuredInt)或类型不对"`
4. **术语门槛**：ObscuredInt/FNV/RVA/metadata 对普通玩家是黑话，错误信息无"人话层"

### 5.3 改进方案

- `scan` 支持流式进度（MCP 通知 / `progress` 字段 + 合理 timeout 提示）
- 新工具 `scan_change`：内部"unknown 首扫 → 等 N 秒 → changed 过滤 → 自动提示用户操作"闭环，交互压缩为一次
- `errors.py` 每个错误加 `plain_hint`（人话）+ `expert_hint`（技术细节）
- session 保留多轮扫描历史（当前 `ScanState` 只存最后一轮）

---

## 6. 维度五：下一代优化策略

### 6.1 工具链选择与自动化配置

```
toolchain/install.py (新增)
- install_tool(name, version="latest") → GitHub API → 下载 → 校验 → 解压到 ~/.game-modifier/tools/
- 工具矩阵按引擎版本动态路由:
    unity-il2cpp + metadata<=31 → 官方 Il2CppDumper
    unity-il2cpp + metadata>31  → il2cpp-dumper-rs (cargo install / GitHub release)
- 优先 winget/choco/cargo 包管理器，失败降级 zip 下载
```

### 6.2 智能引擎检测与适配

```
engines/unity.py 增加:
- detect_metadata_version(global-metadata.dat) → magic + 版本号
- 输出 engine.detail = {unity_version, metadata_version}
- 按版本路由到正确的 dumper（registry 支持 priority 列表）
```

### 6.3 预配置模板系统

```
templates/ 已存在 (template_apply)。扩展:
unity_actk.toml:
  [options.infinite_gold]
  targets = [{ type="obscured-int", strategy="freeze" }]
→ 流程: scan(obscured-int) → name set → template apply infinite_gold
内置 ACTk / 常见混淆类型知识库
```

### 6.4 自动化地址发现与验证

```
新工具链 discover_value(session, field_hint="coin"):
1. dump 符号（自动选 dumper）→ 找 Coin 字段 offset/方法 RVA
2. 反汇编 get_Coin → 自动推导解密公式（基于 capstone）
3. 类型感知扫描定位
4. 写前验证：读当前 → 改 → 读回 → "游戏内需确认"
5. key 变化检测：写前重读 key（本次最大的坑！）
```

### 6.5 错误恢复与引导

```
errors.py 增强: 错误码 → 恢复路径映射
  E_TOOL_NOT_FOUND        → 自动安装流程
  E_METADATA_UNSUPPORTED  → 推荐替代工具
  E_SCAN_EMPTY            → 混淆类型检测提示
  E_KEY_CHANGED           → 写前重读 + 冻结选项
session 记录"恢复点": 失败时 agent 可从最近成功步骤继续
```

---

## 7. 已实施的 P0 修复（2026-08-02）

### 7.1 offsets 语义修复（`memory/pointers.py` + `service.py` + `mcp_server.py` + `cli.py`）

- `resolve_pointer` 新增 `mode="pointer_chain"|"relative"`；`relative` 模式 `base + Σoffsets` 直接相加，不解引用
- **智能默认判定**（`pointers._default_mode`）：`address` 为纯绝对地址（`0x...`/十进制）时默认 `relative`（结构体字段偏移场景），`module.dll+0x..` 形式默认 `pointer_chain`（CE 指针链）；均可显式 `mode` 覆盖
- `read` / `modify` / `name_set` / `backup_create` / `resolve` MCP 工具与 CLI（`--mode`）全部透传
- 新增测试 `test_resolve_pointer_absolute_relative_default` 覆盖本修复；`test_resolve_pointer_negative_offsets` 更新为显式 `pointer_chain`
- **验证结果**：绝对地址 `0x21EF6F535B4` + `offsets=0x4` 现在正确解析为 `0x21EF6F535B8`（此前误解引用为 `0x98b0...` 垃圾地址）

### 7.2 scanner 矢量化（`memory/scanner.py`）

- `first_scan` 对定长数值类型（int/uint/float 全位宽）增加 numpy 向量路径：chunk 读入 → `frombuffer`（按 `DataType` 映射 numpy dtype，int64/uint64/double 均正确）→ 向量比较 → 命中地址收集
- 仅当 numpy 可用 **且** `alignment == size` 时启用（保证视图对齐）；其余情况回退原纯 Python 路径，行为逐字节一致
- 支持 comparator：exact / not_equal / gt / gte / lt / lte / between
- **性能验证**：512MB 假内存扫描 **0.4 秒**（纯 Python 路径此前 5 分钟超时，提速 ~750 倍）
- 原有边界（chunk 跨边界 overlap）/截断（max_results）/read 失败降级行为不变，全部 305 测试通过

### 7.3 代码级缺陷清单（本次发现）

| # | 位置 | 问题 | 状态 |
|---|------|------|------|
| 1 | `service.py _resolve_target` | `address`+`offsets` 走指针链语义导致地址错位 | ✅ 已修复 |
| 2 | `scanner.py first_scan` | 纯 Python 逐 slot，4.6GB 超时 | ✅ 已矢量化 |
| 3 | `windows.py read` | 部分读取静默截断（`bytes(buf[:read.value])`） | ✅ 已修复（0 < read < size 抛 ReadFailedError） |
| 4 | `detect.py detect_from_modules` | `mono-2.0` 出现在任何进程即误判 Mono | ✅ 已修复（需 UnityPlayer.dll 佐证） |
| 5 | `registry.py` | Il2CppDumper 为唯一 Unity dumper，无 v39 路由 | ✅ 已修复（新增 il2cppdumper_rs + metadata 版本路由） |
| 6 | `config.py` | `scan_alignment` 默认 1（逐字节） | ✅ 已修复（默认 4，与 scanner 同步） |

### 7.4 P1 修复明细（2026-08-02 第二轮）

1. **`windows.py read` 部分读取**：`if not ok and read.value == 0` 改为 `if not ok or read.value != size`——0 < read < size 视为失败（返回截断数据会在下游解码出损坏值）。新增 `tests/test_windows_backend.py`（4 测试）。
2. **`detect.py` mono 误判**：mono-2.0/MonoBleedingEdge 是通用运行时（Godot/.NET），单独出现不再判 Unity Mono；需 `UnityPlayer.dll` 佐证才判 UNITY_MONO 0.85。新增 `test_detect_mono_runtime_alone_is_not_unity`。
3. **`registry.py` 工具矩阵**：新增 `il2cppdumper_rs` ToolSpec；新增 `metadata_version()`（读 global-metadata.dat 头部 magic 0xFAB11BAF + 版本）与 `recommended_unity_dumper()`（≤31 官方版，>31 Rust 版）。`service.analyze` 的 UNITY_IL2CPP next_steps 带版本路由。**真实游戏验证**：LostCastle2 metadata=39 → 正确路由到 il2cppdumper_rs（found=True）。
4. **`config.py` scan_alignment**：默认 1 → 4（`default.toml` 与 `Config.scan_alignment` 同步），scanner 函数默认参数同步为 4。逐字节扫描（1）仅按需指定。

全部修复经反馈环验证：失败测试先红（复现 bug）→ 修复后绿（bug 消失），全量测试通过。

---

## 8. 总结

> **游戏修改工具链的成败不在"扫描能力"，而在"对游戏数据的结构性理解"。**
>
> 不理解 ObscuredInt 加密，再快的扫描器也是 0 候选；不先读 metadata 版本，再全的工具矩阵也会选错工具；不区分"指针链/相对偏移"语义，再精确的地址也会被写飞。

优先级排序：

1. **P0** ✅ offsets 语义修复 + scanner 矢量化（本文档已实施）
2. **P1** attach 时工具链主动推荐 + metadata 版本检测
3. **P2** 类型感知扫描（obscured-int）+ 自动化 discover 流程
4. **P3** 进度反馈与交互闭环
