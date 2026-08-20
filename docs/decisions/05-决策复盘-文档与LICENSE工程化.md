# game-modifier 决策复盘（文档与 LICENSE 工程化）

> 面向读者：项目维护者 / 接手者。
> 侧重点：解决"文档数字与实际代码脱节"与"LICENSE 缺失"两项工程债的决策与落地清单。
> 姊妹篇：本文沿用 D1–D32 编号体系，新增 **D33 / D34** 两条决策；历史数字口径见各篇 footer。

---

## 1. 引言

**一句话介绍**：本文记录两项与"工程质量 / 合规"相关的决策——①如何根治文档中的规模数字反复漂移；②如何补上缺失的 LICENSE 文件。

**背景**：项目代码在 8 个阶段演进后规模持续增长，但交接文档（`HANDOVER_GUIDE.md`）与决策复盘（`docs/decisions/01–04`）中的关键数字停留在早期状态：`service.py` 从 810 行涨到 **4,521 行**、MCP 工具从 33 个涨到 **83 个**、测试用例从 408 涨到 **858**、错误码从 34 个涨到 **40** 个、源文件从 51 个涨到 **66** 个。手写数字无法跟上代码演进，且 `README.md` 声明 MIT 但仓库根目录没有 `LICENSE` 文件（分发与合规均不完整）。

**执行范围**（经确认）：仅聚焦上述两项；采用"决策记录 + 同步实施"形态。

---

## 2. 现状指标（以 `scripts/refresh_metrics.py` 输出为准）

> 以下为本次实施时实测值。**代码变化后请重跑 `python scripts/refresh_metrics.py` 并用其输出替换本块**，勿手动改数字。

| 指标 | 数值 |
| --- | --- |
| 源文件（`src/game_modifier`） | 66 个，约 18,297 行 |
| 测试文件 | 66 个（含 conftest 共 67 个），约 15,102 行 |
| 测试用例 | 858 collected / 857 passed / 1 skipped |
| MCP 工具 | 83 个，11 组；readonly profile 53 个，write 工具 30 个 |
| MCP profile 档位 | 5 档（default / readonly / dry-run / symbols / limited） |
| 稳定错误码 | 40 个 `E_*` |
| 反作弊签名 | 16 种防护系统 |
| slash 命令 | 9 个（commands/*.md） |
| 内置模板 | 3 个（rpg / action / strategy） |
| 可选依赖组 | 8 组 extras |
| 单个文件规模 | service.py 4,521 行 / cli.py 947 行 / mcp_server.py 1,477 行 |

---

## 3. D33：文档规模数字工程化（一次性刷新 + metrics 生成脚本）

### 背景 / 痛点

1. `HANDOVER_GUIDE.md` 仍写着"51 个 Python 文件 / 31 个测试文件 408 用例 / service.py 810 行 / MCP 33 个 / 只读 22 个 / 8 个斜杠命令 / 34 个错误码"，与实测（66 / 858 / 4,521 / 83 / 53 / 9 / 40）全部脱节。
2. `docs/decisions/01–04` 的"关键数字口径"停留在 687 用例 / 65 工具 / 35 错误码 / 9 分组。
3. 根因：**没有单一事实来源**——数字散落在各文档里由人手维护，代码一涨就漂。

### 采纳方案

1. **新增 `scripts/refresh_metrics.py`（纯 stdlib）**：从源码静态解析（AST）+ pytest 子进程收集，输出一份 markdown 指标块（源文件数/行数、测试数、MCP 工具与分组、profile 档位、错误码、反作弊签名、slash 命令、内置模板、extras 组数、关键文件行数），可重复运行。
2. **一次性刷新全部 9 篇文档**中的旧数字：`HANDOVER_GUIDE.md`、`docs/decisions/01–04`、`README.md`、`AGENTS.md`、`USER_MANUAL.md`、`AI_AGENT_GUIDE.md`、`INSTALL_GUIDE.md`。
3. 文档统一标注"**以 `scripts/refresh_metrics.py` 输出为准**"，并把重跑脚本写进 PR 检查清单，形成维护约定。

### 备选与否决理由

| 备选 | 否决理由 |
| --- | --- |
| 仅手动改一遍数字 | 治标不治本，下次代码演进必然再漂 |
| 措辞软化、不写任何数字 | 牺牲可读性；headline 数字（规模/测试基线）对交接者仍有价值 |
| 脚本自动替换文档占位符 | 需要每篇文档预留占位符、格式耦合、误替换风险高；收益与成本不成比例 |

### 后果 / 维护约束

- 代码规模变化 → 重跑 `scripts/refresh_metrics.py` → 把指标块贴回本文 §2 与相关文档。
- 测试基线门由脚本收集数为准（当前 **858，不可下降**，与 `INSTALL_GUIDE.md` 口径一致）。
- 新增工具 / 错误码 / 依赖组后，脚本无需改动即可反映新数字（按名称静态解析）。

---

## 4. D34：补全 LICENSE 文件（MIT，版权行占位符）

### 背景 / 痛点

`pyproject.toml` 声明 `license = { text = "MIT" }`，`README.md` 也注明"许可证 MIT（正式 LICENSE 文件待补）"，但仓库根目录**没有 `LICENSE` 文件**——源码分发（sdist/wheel 的 `licenses` 元数据、GitHub 仓库授权展示）不完整。

### 采纳方案

1. **新增根目录 `LICENSE`**：标准 MIT 许可证全文（对应 `pyproject.toml` 的 MIT 声明）。
2. **版权行使用占位符**：`Copyright (c) 2026 <copyright holder>`，由项目所有者后续自行填写（经确认采用占位符方案，避免默认署名造成误导）。
3. 保持 `pyproject.toml` 现有 `license = { text = "MIT" }` 声明不变（与 LICENSE 文件一致）。

### 备选与否决理由

| 备选 | 否决理由 |
| --- | --- |
| 直接写 `game-modifier contributors` | 与作者集体署名习惯不符，可能被误认为已授权署名 |
| 改用其他开源许可证（Apache/GPL） | 与既有 MIT 声明冲突，且超出本次范围 |

### 后果 / 维护约束

- 填写占位符时，建议同步确认 `pyproject.toml` 的 `authors` 字段保持一致。
- 后续若把 `license` 元数据升级为 `license-files`（需 setuptools ≥ 77），可让 LICENSE 进入 wheel 元数据；当前 sdist 已按默认规则收录根目录 LICENSE。

---

## 5. 落地清单（本次已执行）

- [x] 新增 `scripts/refresh_metrics.py` 并实测运行（输出见 §2）
- [x] 新增根目录 `LICENSE`（MIT，版权行占位符）
- [x] 刷新 `HANDOVER_GUIDE.md` 全部旧数字 + 指标块引用
- [x] 刷新 `docs/decisions/01–04` 的关键数字口径（历史阶段基线保留，仅更新"当前值"）
- [x] 刷新 `README.md`（MCP 工具 84→83 / 只读 54→53）
- [x] 核对 `AGENTS.md` / `USER_MANUAL.md` / `AI_AGENT_GUIDE.md` / `INSTALL_GUIDE.md`：无旧 headline 数字，补充指标脚本引用
- [x] 回归验证：`pytest tests/` 全绿（857 passed / 1 skipped）

---

## 6. 附录：本次实测对照表（旧 → 新）

| 指标 | 旧（文档） | 新（实测） |
| --- | --- | --- |
| 源文件数 | 51 | **66** |
| 测试文件 / 用例 | 31 / 408 | **66 / 858**（857 passed / 1 skipped） |
| service.py 行数 | 810 | **4,521** |
| MCP 工具 / 分组 | 33 / 9 | **83 / 11** |
| readonly profile | 22 | **53** |
| 错误码 | 34 | **40** |
| 错误子类 | 19 | **28** |
| 工具链 ToolSpec | 11 | **14**（含 il2cppdumper_rs / dotnet / il_tool） |
| slash 命令 | 8 | **9**（新增 ue） |
| session.py / config.py / errors.py 行数 | 221 / 154 / 219 | **835 / 215 / 313** |
