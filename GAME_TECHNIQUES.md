# GAME_TECHNIQUES — 单机游戏修改技术原理参考（AI Agent 向）

**适用声明**
- 本文档与本项目 **仅限单机 / 离线游戏**。检测到反作弊组件（EAC、BattlEye 等）时 `attach` 直接拒绝（`E_ANTI_CHEAT`），不提供也不讨论任何绕过手段。
- 不涉及联机作弊、网络封包篡改、反作弊对抗。
- 所有写操作 **默认 dry-run**：不加 `--confirm` / `confirm=true` 不落地；每次确认写入自动备份原值并记入 `sessions/<id>/audit.jsonl`。
- 文中所有命令均已对照 `src/game_modifier/cli.py` 核实；MCP 侧工具名同义（下划线形式，权威清单以 `tools_catalog` 为准）。

约定：`<s>` 代表 `--session <id>`，`attach` 成功后获得。

## 0. 能力前提速查表

| 命令 | 用途 |
| --- | --- |
| `attach` | 挂载进程（`--process` / `--pid` / `--exe` / `--title` 窗口标题匹配，多进程游戏用） |
| `analyze [--deep]` | 引擎识别（unity-il2cpp / unity-mono / unreal / nwjs / rpg-maker / renpy…） |
| `scan` / `scan-next` | 首扫（exact/not_equal/gt/gte/lt/lte/between/unknown）+ 渐进过滤（changed/unchanged/increased/decreased） |
| `scan-aob` | AOB 特征码扫描（`??` 通配），版本适配定位 |
| `scan-candidates` | 分页浏览当前扫描候选集（`--offset/--limit/--min-addr/--max-addr`） |
| `read` / `modify` | 读/写值；支持符号、地址表达式（`0x..+/-0x..`）、`--offsets` + `--mode relative/pointer_chain/field_chain` |
| `resolve` | 指针路径解析（`--deref-last/--no-deref-last` 控制 field_chain 末步） |
| `name set/chain/get/clear-temp` | 符号表：固化地址为 `player.gold` 式符号；`chain` 注册多级链中间态 |
| `pointer-scan [--rescan/--async]` | 反向指针链发现；长任务走后台 job（`job status/list/cancel`） |
| `nl` | 中文自然语言修改（"将金币设为9999"） |
| `freeze` | 锁值：`modify --freeze` 注册，`freeze start/stop` 后台强制执行 |
| `batch run` / `macro` | YAML 批量操作 / 参数化可复用宏 |
| `template` | 预置类型模板（`template list/show/apply`） |
| `watch` | 轮询监视地址值变化（`run` 前台 / `start|stop|report` 后台） |
| `find-writers` | 硬件写断点（DR0-3）定位"谁在写这个地址"，**需管理员** |
| `disasm` | capstone 反汇编（只读，需 capstone） |
| `xrefs` | 交叉引用（radare2 优先，缺失时纯 Python 兜底，看 `data.backend`） |
| `dissect` | 结构体自动解剖（单/多实例对比） |
| `layout` | 内存布局分析：`vtables / rtti / class / heap` |
| `ue introspect/actors/fname` | Unreal GObjects/FName 自省（只读） |
| `il2cpp string/list/dict/lookup/dump` | Unity IL2CPP 运行时对象解码 + RVA 反查 + dumper 集成 |
| `il analyze/dump/callers/patch/verify/backup/restore` | Unity Mono IL 分析与补丁（需 .NET 8 运行时） |
| `mono dump/symbol/string/list/dict/static/heap-scan` | Mono 索引、字符串/集合解码、静态字段与堆对象定位 |
| `backup create/list/restore` | 原值备份与回滚；`file snapshot/restore` 针对文件 |
| `save-edit detect/modify` | 存档式游戏（RPG Maker / Ren'Py / Unity 加密存档） |
| `safety level` | 运行时安全档：`normal / dry_run_only` |

**指针模式语义**（`read/modify/resolve/name` 通用）：
- `relative`：偏移即加法（裸地址默认）。
- `pointer_chain`：先解引用再加偏移（CE 式指针路径，模块基址默认）。
- `field_chain`：先加偏移再解引用（嵌套结构体字段逐级下钻）。

## 一、基础物理与状态修改

### 1. 移动速度
**内存原理**：角色结构体中有一个速度乘数字段（float，常态 `1.0`），每帧动画/位移计算读取它。改 `1.0 → 3.0` 即三倍速。

**实现步骤**：
```
game-modifier scan <s> --type float --value 1.0          # 首扫（候选多）
# 游戏中跑动/停住，交替过滤：
game-modifier scan-next <s> --comparator increased       # 跑动瞬间
game-modifier scan-next <s> --comparator unchanged       # 静止时
# 收敛到个位数候选后逐个验证：
game-modifier scan-candidates <s> --limit 20
game-modifier modify <s> --address 0x<addr> --type float --value 3.0            # dry-run
game-modifier modify <s> --address 0x<addr> --type float --value 3.0 --confirm --freeze
game-modifier freeze start <s>                            # 后台锁值
```

**安全/兼容性**：候选过多时多用几轮 unchanged 过滤而非猜测；不同版本乘数默认值可能不是 1.0，先 `read` 验证。锁值后若游戏崩溃说明改错地址，`freeze stop <s>` + `backup restore`。

### 2. 飞天
**内存原理**：角色状态结构体含 `isGrounded`（bool/uint8）与 `Gravity`（float）字段。物理更新每帧检查 grounded 标志决定是否施加重力；置 false / 重力置 0 即悬浮。

**实现步骤**：
```
game-modifier scan <s> --type uint8 --comparator between --value 0 --value2 1   # 布尔候选
# 落地/跳起交替，scan-next changed 反复收敛
game-modifier dissect <s> --address 0x<addr> --size 128    # 解剖周边字段，找 Gravity
game-modifier watch run <s> --address 0x<addr> --type uint8 --iterations 200    # 验证与跳跃同步变化
game-modifier modify <s> --address 0x<addr> --type uint8 --value 0 --confirm --freeze
```

**安全/兼容性**：布尔标志候选极多，务必多轮 changed/unchanged 对比；部分游戏由服务器侧/脚本侧重算状态，锁值可能被覆盖，可尝试改 Gravity 浮点替代。

### 3. 穿墙
**内存原理**：角色或物理组件上的碰撞开关（`Collision` bool / `noclip` 标志位），移动前检查该位决定是否做碰撞解算。

**实现步骤**：
```
# 路线 A（值扫描）：同条目 2 的布尔收敛流程，撞墙/不撞墙交替 scan-next changed
# 路线 B（特征码）：已知旧版本标志位上下文特征时：
game-modifier scan-aob <s> --pattern "80 B9 ?? ?? 00 00 00 74"   # ?? 吸收版本间偏移漂移
# 验证候选：
game-modifier watch run <s> --address 0x<addr> --type uint8
game-modifier modify <s> --address 0x<addr> --type uint8 --value 0 --confirm --freeze
```

**安全/兼容性**：穿墙后可能掉出世界无法返回——先 `name set` 固化坐标符号（见条目 4）以便瞬移救场。AOB 特征码跨版本可能失配（`E_PATTERN_NOT_FOUND` 时放宽通配）。

### 4. 坐标读取与修改
**内存原理**：角色位置为结构体内连续的三个 float（X/Y/Z，相邻偏移如 `+0x70/+0x74/+0x78`）。朝某方向走一步，对应轴单调变化。

**实现步骤**：
```
game-modifier scan <s> --type float --comparator unknown      # 初值未知时
# 向 +X 走一步：
game-modifier scan-next <s> --comparator increased            # X 变大
# 站住：
game-modifier scan-next <s> --comparator unchanged            # 反复 3~5 轮收敛
game-modifier read <s> --address 0x<addr> --type float        # 验证当前坐标
game-modifier read <s> --address "0x<addr>+0x4" --type float  # 相邻轴大概率是 Y
game-modifier name set player.pos_x <s> --base 0x<addr> --type float
game-modifier name set player.pos_y <s> --base "0x<addr>+0x4" --type float
game-modifier name set player.pos_z <s> --base "0x<addr>+0x8" --type float
```

**安全/兼容性**：坐标常在堆上动态分配，重启游戏后地址变化——用 `pointer-scan --address 0x<addr>` 找稳定指针链，再 `name chain` 固化。float 候选海量，坚持 unknown → increased/unchanged 多轮收敛。

### 5. 瞬移
**内存原理**：直接向角色坐标字段写入目标 X/Y/Z。物理帧下一 tick 即按新坐标更新。

**实现步骤**：
```
game-modifier backup create <s> --symbol player.pos_x --label "before-tp"   # 先备份
game-modifier modify <s> --symbol player.pos_x --type float --value 123.5   # dry-run
game-modifier modify <s> --symbol player.pos_x --type float --value 123.5 --confirm
# Y/Z 同理；也可用 batch 一次写三轴（见 batch YAML 样例）
```

**安全/兼容性**：目标坐标必须在合法地形附近，否则卡墙/坠出世界；传送前先 `read` 记录当前值以便返回。写 Y 轴（高度）时建议略高于地面。

### 6. 吸引敌人到身边
**内存原理**：敌人对象与主角共享同一坐标布局（同基类）。枚举敌人对象数组，把每个敌人的 X/Y/Z 批量写为主角坐标。

**实现步骤**：
```
# 枚举敌人对象：
game-modifier ue actors <s> --class Enemy --list          # Unreal
game-modifier layout <s> --what heap --address 0x<vtable> # C++ 堆枚举（vtable 过滤）
game-modifier mono heap-scan <s> --vtable-addr 0x<vt>     # Mono
game-modifier il2cpp list <s> --address 0x<list> --elem-type ptr  # IL2CPP List<T>
# 确认偏移：dissect 一个敌人实例，与条目 4 的坐标偏移对齐
game-modifier dissect <s> --address 0x<enemy0> --size 128
# 批量写入（batch YAML，每个敌人 3 条 modify；或 macro 参数化）：
game-modifier batch run <s> ops/pull_enemies.yaml --confirm
```

**安全/兼容性**：敌人数量多时坐标偏移可能因派生类不同而漂移——多实例 `dissect --addresses a,b,c` 交叉验证。批量写属于高频修改，先小批量试 2~3 个再全量。

## 二、战斗与伤害修改

### 7. 锁血（不会死）
**内存原理**：血量是角色结构体的数值字段（int/float），受伤时由减血逻辑写入。两条路线：直接锁值；或定位写入代码。

**实现步骤（首选值级）**：
```
game-modifier scan <s> --type int32 --value 100        # 当前血量
# 被打一下：
game-modifier scan-next <s> --comparator changed
game-modifier scan-next <s> --comparator exact --value 80
game-modifier modify <s> --address 0x<addr> --type int32 --value 100 --confirm --freeze
game-modifier freeze start <s>
```
**定位减血逻辑（进阶，读侧分析）**：
```
game-modifier find-writers <s> --address 0x<addr> --size 4 --duration 5   # 需管理员；游戏中受击
game-modifier disasm <s> --address 0x<hit_rip>          # 查看写入指令（il2cpp 配合 il2cpp lookup 反查方法名）
```

**安全/兼容性**：**原生汇编级"伤害清零 hook"超出本项目能力**——本项目可定位写入指令但不在游戏内执行注入，后续 patch 需外部工具；**Unity Mono 游戏例外**：可用 `il patch --op insert_before_ret` 做 IL 级补丁（见条目 11 流程）。部分游戏血量为 float 或显示值/真实值分离，两者都试。

### 8. 一击秒杀
**内存原理**：与锁血镜像——敌人血量字段批量归零，或放大伤害结算值。

**实现步骤（值级替代）**：
```
# 单个 Boss：scan 其当前血量 → 受击 changed 收敛 → modify --confirm 写 0/1
# 群体：枚举敌人（同条目 6）后 batch 批量写 0
game-modifier batch run <s> ops/kill_all.yaml --confirm
```
**定位伤害函数**：`watch` 监视敌人血量 + 攻击 → `find-writers` 抓写入 RIP → `xrefs --direction to` 找调用方 → `disasm` 阅读伤害公式。

**安全/兼容性**：原生"伤害乘算 hook"同样超出能力边界，替代路径：
- Unity Mono：`il patch --op mul_before_ret` 对伤害方法返回值乘算（IL 级伤害放大，见条目 11）；
- 其他引擎：值级批量写血量，或定位后结合外部注入工具。
写 0 可能触发"无敌判定"导致打不死，改 1 更稳。

### 9. 角色无敌（状态标志）
**内存原理**：角色状态机中的 `isInvincible` / Buff_Status 位域。无敌判定每帧读该标志，置 1 则伤害被忽略。

**实现步骤**：
```
game-modifier scan <s> --type int32 --comparator between --value 0 --value2 255
# 开启无敌技能 → scan-next changed；关闭 → scan-next changed 再回 unchanged
# 反复对比开/关阶段内存差异收敛到唯一候选
game-modifier watch run <s> --address 0x<addr> --type uint8   # 与技能开关同步验证
game-modifier modify <s> --address 0x<addr> --type uint8 --value 1 --confirm --freeze
```

**安全/兼容性**：Buff 标志可能是位域（bit flag）而非独立字节——若置 1 后异常，`dissect` 查看周边字段判断位布局。部分游戏无敌标志由服务端脚本每帧重刷，锁值无效时改找其来源配置。

### 10. 武器附加特效
**内存原理**：武器实例结构体挂 Buff ID / 附魔字段（int），攻击结算时按 ID 查效果。全局配置表（ID→效果映射）通常在**只读数据段**。

**实现步骤**：
```
game-modifier dissect <s> --address 0x<weapon_obj> --size 256   # 解剖武器实例找 Buff ID
# 换一把带特效的武器对比字段差异（dissect --addresses 双实例对比）
game-modifier modify <s> --address 0x<addr> --type int32 --value 42 --confirm   # 改实例 Buff ID
```

**安全/兼容性**：修改只读区的全局配置表属**高风险写**（需 `--confirm-code` 且易崩），本项目的区域风险分级会拦截提示——优先改**武器实例**的 Buff ID 字段而非配置表。非法 Buff ID 会导致崩溃或空效果，先用游戏中已知存在的 ID。

## 三、游戏机制与逻辑修改

### 11. 经验倍数
**内存原理**：经验结算函数内部形如 `exp = base * multiplier` 的乘算指令；原生实现是在该处注入 `imul` 改写。**该汇编注入超出本项目能力**，如实说明替代路径：

| 路径 | 做法 |
| --- | --- |
| 值级（通用） | 结算后直接改经验/等级数值：`scan --value <结算前>` → 战斗 → `scan-next increased` → `modify --confirm` |
| 配置字段 | 若存在全局倍率字段（部分游戏有 debug 倍率），布尔/浮点扫描定位后改值 |
| IL 级（仅 Unity Mono） | `il patch` 对结算方法做返回值乘算 |

**Unity Mono 实现**：
```
game-modifier mono dump <s>                                  # 建索引
game-modifier mono symbol <s> "AddExp"                       # 找结算方法
game-modifier il dump <s> --method "AddExp" --type "PlayerData"   # 读 IL 确认
game-modifier il patch <s> --op mul_before_ret --method "AddExp" --type "PlayerData" --value 10   # dry-run
game-modifier il patch <s> --op mul_before_ret --method "AddExp" --type "PlayerData" --value 10 --confirm
game-modifier il verify <s> --method "AddExp" --type "PlayerData" --expect "mul,ret"
```

**安全/兼容性**：`il patch` 确认前自动文件备份，`il restore <backup_id> --confirm` 回滚；需要 .NET 8 运行时；IL2CPP 游戏无托管程序集，此路不通，只能值级。整数溢出：倍率 × 基数超 int32 上限会回绕成负数。

### 12. 去掉建筑/研究需求
**内存原理**：需求判定是 `if (material >= cost) goto build` 式条件跳转——改跳转属汇编级，**超出本项目能力**。值级替代：直接满足条件。

**实现步骤**：
```
# 路线 A：改资源数量使其满足需求
game-modifier scan <s> --type int32 --value 35            # 当前材料数
game-modifier modify <s> --address 0x<addr> --type int32 --value 99999 --confirm
# 路线 B：改需求配置字段/已解锁标志位
game-modifier scan <s> --type uint8 --comparator between --value 0 --value2 1   # 解锁标志
game-modifier find-writers <s> --address 0x<material_addr>   # 定位消耗/校验逻辑（读侧分析）
game-modifier xrefs <s> --address 0x<check_func> --direction to
```

**安全/兼容性**：材料数常显示值/真实值分离（显示 ×10 存储），不一致时两值都扫。定位到校验函数后的汇编改写需外部工具；Unity Mono 可评估 `il patch --op replace_body` 让需求检查方法恒返回 true（先 `il dump` 看清签名）。

### 13. 解锁所有技能/科技
**内存原理**：技能树通常是标志位数组（`uint8[N]`，0=未解锁 1=已解锁）或技能点数值。

**实现步骤**：
```
# 技能点/等级直接改值：
game-modifier scan <s> --type int32 --value 3     # 当前点数
game-modifier modify <s> --address 0x<addr> --type int32 --value 99 --confirm
# 标志位数组：解锁一个技能定位数组首址后，批量置 1：
game-modifier scan <s> --type uint8 --value 0
# 学一个技能 → scan-next changed → 收敛到数组元素
# 由元素地址反推数组首址（地址差即索引×元素大小），batch 循环写 1：
game-modifier batch run <s> ops/unlock_skills.yaml --confirm
```

**安全/兼容性**：越界写（数组长度外）会破坏相邻字段——先用 `dissect` 确认数组规模。部分游戏解锁状态存存档而非内存，`E_SAVE_EDIT_REQUIRED` 时转 `save-edit`。

### 14. 任务进度直接完成
**内存原理**：任务状态字段（典型 0=未接取 1=进行中 2=完成），任务管理器按 ID 索引状态表。

**实现步骤**：
```
game-modifier scan <s> --type int32 --comparator unknown   # 状态未知
# 接取任务：
game-modifier scan-next <s> --comparator changed
# 推进一次进度再 changed / 站住 unchanged，反复收敛
game-modifier modify <s> --address 0x<addr> --type int32 --value 2   # dry-run 后 --confirm
```

**安全/兼容性**：跳过中间状态（0→2）可能让任务脚本错过触发器（对话/奖励发放），若任务卡死先 `backup restore` 回原值走正常流程。多个同名任务共享状态值时候选会多，用 between 限定值域辅助收敛。

## 四、社交、派系与NPC修改

### 15. 队友好感度全满
**内存原理**：好感度是隐藏数值（int 0-100 或 float 0.0-1.0），按队友槽位连续存放（数组/结构体数组）。

**实现步骤**：
```
game-modifier scan <s> --type int32 --comparator between --value 0 --value2 100
# 送一次礼：
game-modifier scan-next <s> --comparator increased
# 多送几次反复 increased 收敛
# 找到一个队员的好感度后，队友数组连续存放：
game-modifier read <s> --address "0x<addr>-0x4" --type int32    # 相邻槽位
game-modifier batch run <s> ops/affinity_max.yaml --confirm       # 按偏移批量写满
# 或 macro 参数化：
game-modifier macro run affinity <s> --params "base=0x<addr>,n=4,max=100" --confirm
```

**安全/兼容性**：float 好感（0.0-1.0）用 `--type float`；超出上限的值可能触发剧情异常，写游戏内可达的最大值更稳。

### 16. 任意角色为队友
**内存原理**：角色对象（同基类）都有 TeamID / Faction 字段。AI 与交互逻辑按 `TeamID == 主角TeamID` 判定友军——改这一个字段即可。

**实现步骤**：
```
# 先读主角 TeamID：
game-modifier read <s> --symbol player.team
# 定位目标角色对象（ue actors / heap / mono heap-scan），scan 其 TeamID：
game-modifier scan <s> --type int32 --value 2        # 假设目标原属阵营 2
game-modifier modify <s> --address 0x<npc_addr> --type int32 --value 1 --confirm  # 1=主角阵营
```

**安全/兼容性**：部分游戏队友上限/编队逻辑独立校验，改 TeamID 后角色"不敌对"但不入队属正常。改错对象（把主角 TeamID 改了）会导致全体敌对，先 `backup create`。

### 17. Boss 游玩（操控切换）
**内存原理**：输入/相机系统通过"玩家控制指针"（PlayerController → Pawn/Character 指针）决定操控对象。将该指针改写为 Boss 对象地址即切换操控。

**实现步骤**：
```
game-modifier backup create <s> --address 0x<ctrl_ptr> --size 8 --label "before-possess"
# 定位控制指针：已知主角对象地址时反向找持有者，或 dissect 玩家管理器结构
game-modifier pointer-scan <s> --address 0x<player_obj> --max-depth 3
game-modifier resolve <s> --base "Game.exe+0x<off>" --offsets 0x10,0x28 --mode field_chain
# 读取 Boss 对象地址（ue actors --class Boss / heap 枚举）后写入：
game-modifier modify <s> --address 0x<ctrl_ptr> --type uint64 --value 0x<boss_obj>   # dry-run
game-modifier modify <s> --address 0x<ctrl_ptr> --type uint64 --value 0x<boss_obj> --confirm
```

**安全/兼容性**：**高风险操作**——控制指针写错会立即崩溃，务必先 `backup create`，失败 `backup restore <id>`。Boss 对象缺玩家动画状态机时可能动作异常；切换前先 `freeze stop` 避免锁值干扰。

### 18. 敌人不敌对
**内存原理**：同条目 16——敌对判定基于 Faction 字段对比。把敌人 Faction 改成主角派系或中立派系 ID。

**实现步骤**：
```
# 枚举敌人 + 确认 Faction 字段偏移（dissect 对比敌我实例差异）
game-modifier batch run <s> ops/pacify.yaml --confirm   # 每个敌人一条 modify
```

**安全/兼容性**：中立派系 ID 需要游戏内真实存在（观察其他中立生物的值），凭空造 ID 可能导致 AI 行为未定义。战斗已开始时部分游戏缓存敌对列表，需脱战/重载后生效。

### 19. 敌人自相残杀
**内存原理**：派系两两对比判定敌我（`FactionA != FactionB && 敌对关系表[A][B]`）。给每个敌人写入互不相同的 Faction ID，使其互相视为敌人。

**实现步骤**：
```
# 枚举全部敌人（条目 6 流程）
# macro 参数化批处理：每个敌人分配不同派系 ID
game-modifier macro define faction_split <s> --file ops/faction_split.yaml
game-modifier macro run faction_split <s> --params "base=0x<arr>,n=10" --confirm
```

**安全/兼容性**：派系 ID 需在关系表有效范围内，超界 ID 可能崩溃或被忽略。敌人数量多时 batch 结果读 `results_file`，勿依赖截断的内联预览。

### 20. 幽灵模式
**内存原理**：隐身 = 派系中立（不被索敌）+ 不可见标志位（视觉/AI 感知屏蔽）的组合。

**实现步骤**：
```
# 1) 派系改中立：同条目 18
# 2) 不可见标志：对比隐身技能开/关前后的内存差异
game-modifier scan <s> --type uint8 --comparator between --value 0 --value2 255
# 开隐身 → scan-next changed；关隐身 → scan-next changed 收敛
game-modifier watch run <s> --address 0x<addr> --type uint8    # 验证与隐身状态同步
game-modifier modify <s> --address 0x<addr> --type uint8 --value 1 --confirm --freeze
```

**安全/兼容性**：感知系统分层（视觉/听觉/仇恨），单一标志可能只屏蔽一层；标志由 AI tick 重刷时需 freeze 持续压制。永久隐身可能卡任务对话（NPC 拒绝与"不可见"角色交互）。

## 5. 通用工作流速查

```
定位 ──▶ 固化 ──▶ 修改 ──▶ 回滚
```

| 阶段 | 工具链 |
| --- | --- |
| 值已知 | `scan` → 改变游戏状态 → `scan-next`（changed/increased…）反复收敛 → `scan-candidates` 查看 |
| 值未知 | `scan --comparator unknown` → 多轮 changed/unchanged |
| 找写入代码 | `watch`（轮询观察）→ `find-writers`（硬件断点，管理员）→ `disasm` / `xrefs` 阅读 |
| 解剖结构 | `dissect`（单/多实例）→ `layout`（vtables/rtti/class/heap）→ 引擎自省（`ue actors` / `il2cpp list` / `mono heap-scan`） |
| 版本适配 | `scan-aob` 特征码（`??` 通配）+ `pointer-scan --rescan` 重验指针链 |
| 固化符号 | `name set`（含 `--temp`）、`name chain`（多级链中间态，`--persist` 保留） |
| 修改 | dry-run（默认）→ `--confirm` → `--freeze` + `freeze start`；批量用 `batch run` / `macro run` |
| 回滚 | `backup restore <id>`（值）、`il restore`（IL 补丁）、`file restore`（文件）；审计查 `audit_tail` |
| 出错恢复 | `E_NEEDS_SCAN` 重扫；`E_SYMBOL_NOT_FOUND` 重新 `name set`；`E_PROCESS_EXITED` 重 attach；`E_SCAN_CACHE_STALE` 重新首扫 |

## 6. 诚实边界

**本项目是"值级 + IL 级"修改工具**：

| 能做 | 不能做 |
| --- | --- |
| 扫描/读/写/锁定任意进程内存值 | 任意 x86 汇编注入 / shellcode / DLL 注入 |
| 指针链发现与符号化（跨重启稳定） | 运行时改写可执行代码段（高风险区写入受风险分级拦截） |
| 定位写入代码：watch / find-writers / xrefs / disasm / AOB | 在游戏内执行被定位到的补丁代码（需外部工具衔接） |
| Unity Mono：`il patch` 四种 IL 级补丁（replace_body / mul_before_ret / insert_before_ret / insert_after_call） | IL2CPP / 原生引擎的代码级补丁 |
| 存档文件编辑（RPG Maker / Ren'Py / Unity 加密存档） | 联机数据篡改、反作弊绕过（检测即拒绝，不提供绕过） |

**给 Agent 的决策规则**：遇到"代码注入式"需求（秒杀 hook、条件跳转改写、经验 imul 注入）时：
1. Unity Mono 游戏评估 `il patch`；
2. 用 watch / find-writers / xrefs / disasm 完成**定位**，明确告知注入执行需外部工具；
3. 永远不虚构本项目不存在的注入命令。
