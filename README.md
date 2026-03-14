# NanoLLM4Audit

一个面向日志审计分析与复现的轻量项目。

## 1. 项目定位

- 目标：用更短的链路展示日志审计项目的完整闭环
- 形式：本地数据、本地评分、本地建模、本地图表、本地报告
- 适用场景：仓库阅读、方案说明、结果复核、快速复现实验
- 运行特点：默认只依赖 `pandas`、`numpy`、`matplotlib`、`scikit-learn`

## 2. 目录结构

```text
NanoLLM4Audit/
├─ configs/
│  └─ default.toml
├─ data/
│  └─ demo_logs.csv
├─ docs/
│  ├─ architecture.md
│  └─ review_rounds.md
├─ outputs/
│  ├─ charts/
│  ├─ dashboard.html
│  ├─ events_scored.csv
│  ├─ experiments.csv
│  ├─ metrics.json
│  ├─ report.md
│  ├─ tree_metrics.json
│  └─ tree_rules.txt
├─ scripts/
│  ├─ check_outputs.py
│  └─ run_demo.ps1
├─ requirements.txt
└─ src/
   └─ nanoaudit/
      ├─ cli.py
      ├─ config.py
      ├─ data.py
      ├─ experiments.py
      ├─ ml.py
      ├─ pipeline.py
      ├─ report.py
      ├─ rules.py
      ├─ scoring.py
      └─ visuals.py
```

## 3. 日志审计基础知识

### 3.1 日志是什么

日志记录系统中的动作、时间、账号、主机、来源地址、执行结果。日志审计的工作重点在于从大量普通事件中筛出少量值得复查的高风险事件。

### 3.2 常见日志类型

- 认证日志：登录成功、登录失败、口令校验
- 进程日志：命令执行、脚本启动、系统工具调用
- Web 日志：访问路径、状态码、来源地址
- 系统任务日志：备份、计划任务、服务启动
- 代理日志：文件上传、外联地址、下载行为

### 3.3 常见风险动作

- 凭据获取：例如读取 `lsass`、运行 `mimikatz`
- 执行：例如编码 PowerShell、远程脚本加载
- 持久化：例如创建计划任务
- 横向移动：例如 `wmic`、`psexec`、远程执行
- 数据收集与外传：例如压缩打包后上传到外部地址

### 3.4 阅读日志时最常见的几个字段

- `timestamp`：事件时间
- `host`：主机名
- `user`：账号
- `src_ip`：来源地址
- `event_type`：事件类别
- `status`：成功或失败
- `message`：原始文本内容

### 3.5 为什么需要“规则 + 行为 + 机器学习”三条线

- 规则线：用于抓取高置信特征，适合 `mimikatz`、`powershell -enc` 一类直接痕迹
- 行为线：用于观察夜间执行、失败暴增、跨主机扩散等上下文信号
- 融合线：将两类信号合并成一个风险分数，便于排序和阈值控制
- 机器学习线：在人工设计特征的基础上训练浅层决策树，用图形化方式展示模型如何形成判断

## 4. 简化后的核心流程

### 4.1 数据层

`data/demo_logs.csv` 由固定随机种子生成，包含 334 条样例日志，其中既有稳定业务行为，也有多段攻击链片段。固定种子带来一致的图表与指标输出。样例数据中的风险特征保持清晰，便于快速理解整体链路。

### 4.2 规则层

项目只保留七条高价值规则：

- `R001_MIMIKATZ`
- `R002_POWERSHELL_ENC`
- `R003_SCHTASKS`
- `R004_LOLBIN_REMOTE`
- `R005_LATERAL_MOVE`
- `R006_EXFIL`
- `R007_BRUTE_FORCE`

规则命中后会写出三个关键字段：

- `rule_score`
- `rule_id`
- `rule_description`

### 4.3 行为层

行为分数由五个组件构成：

- 事件稀有度
- 夜间时间窗口
- 单日失败事件聚集度
- 账号跨主机扩散度
- 敏感账号高风险动作

### 4.4 融合层

默认融合公式如下：

```text
risk_score = 0.70 × rule_score + 0.30 × behavior_score
```

当 `risk_score >= 0.62` 时，事件进入高风险候选集。

### 4.5 机器学习层

项目在规则分数和行为分数之外，额外训练一个浅层决策树分类器。模型使用 6 个特征：

- `rule_score`
- `rarity_score`
- `off_hours_score`
- `failure_burst_score`
- `host_spread_score`
- `privileged_account_score`

模型输出以下字段：

- `tree_score`：决策树输出的恶意概率
- `tree_prediction`：决策树预测标签
- `evaluation_split`：训练集或测试集标记

模型产出以下附加文件：

- `outputs/tree_metrics.json`：决策树 Holdout 指标
- `outputs/tree_rules.txt`：文本形式的树规则

### 4.6 输出层

- `outputs/events_scored.csv`：每条日志的详细评分结果
- `outputs/experiments.csv`：五组实验方案指标
- `outputs/metrics.json`：主指标汇总
- `outputs/tree_metrics.json`：决策树模型指标
- `outputs/tree_rules.txt`：决策树规则文本
- `outputs/report.md`：Markdown 结果报告
- `outputs/dashboard.html`：HTML 看板
- `outputs/charts/`：十二张图表

### 4.7 算法设计详解

#### 4.7.1 设计目标

算法设计围绕四个目标展开：

- 对单条日志给出可解释的风险分数
- 对整批日志形成稳定的高风险排序
- 对规则证据和行为证据分别保留明细
- 对实验结果提供可复现的指标与图表

从实现形式来看，这套算法属于“规则评分 + 行为评分 + 融合判定”的三层结构。每条日志都会先经过规则层与行为层，再进入融合层完成最终判定。

#### 4.7.2 输入与输出定义

单条日志事件记为 `e_i`，包含以下字段：

- `timestamp`：事件时间
- `source_type`：日志来源类型
- `host`：主机名
- `user`：账号
- `src_ip`：来源地址
- `event_type`：事件类别
- `status`：执行状态
- `message`：原始文本

算法处理后会新增以下核心输出：

- `rule_score`：规则层分数
- `behavior_score`：行为层分数
- `risk_score`：融合后的总分
- `candidate`：是否进入高风险候选集
- `severity`：风险等级
- `rule_id`：命中的主规则编号
- `behavior_reasons`：行为侧原因说明
- `audit_summary`：结构化摘要

#### 4.7.3 规则评分层

规则层负责识别高置信文本特征。配置文件 `configs/default.toml` 中定义了 7 条规则，每条规则包含 4 个元素：

- `id`：规则编号
- `pattern`：正则表达式
- `score`：规则权重
- `description`：规则说明

对第 `i` 条日志，规则层计算公式如下：

```text
rule_score(i) = max(score_k × I(pattern_k 命中 message_i))
```

其中：

- `score_k` 表示第 `k` 条规则的预设分数
- `I(...)` 为指示函数，命中时取值 `1`，未命中时取值 `0`

如果多条规则同时命中，系统保留分数最高的一条作为主规则，并把对应的 `rule_id` 与 `rule_description` 写入结果表。

当前 7 条规则覆盖的重点风险包括：

- 凭据提取：`mimikatz`、`lsass`
- 编码脚本执行：`powershell -enc`
- 计划任务创建：`schtasks /create`
- 远程脚本加载：`regsvr32`、`rundll32`、`mshta`
- 横向移动：`wmic`、`psexec`、`winrm`
- 压缩与上传：`7z`、`curl -T`、`upload`
- 登录失败密集出现：`4625`、`failed logon`

规则层的特点是解释性强、定位快、适合优先发现文本中已经明确暴露的攻击痕迹。

#### 4.7.4 行为评分层

行为层负责补充上下文信号。实现中共使用 5 个特征，全部在 `src/nanoaudit/scoring.py` 中显式计算。

**1. 事件稀有度 `rarity_score`**

某一事件类别在整批数据中的出现频率越低，分数越高。公式如下：

```text
rarity_score(i) = 1 - freq(event_type_i)
```

该特征适合强调低频高危动作，例如凭据提取、压缩上传、远程脚本加载。

**2. 夜间时间窗口 `off_hours_score`**

依据事件发生小时数进行分段赋值：

```text
hour ∈ [0, 5] 或 [23, 23]  -> 1.0
hour ∈ [6, 7] 或 [20, 22]  -> 0.6
其余时段                      -> 0.1
```

该特征用于放大夜间执行、凌晨外联、非办公时段批量失败等现象。

**3. 单日失败聚集度 `failure_burst_score`**

先按“账号 + 日期”统计失败事件数量，再映射到 `[0, 1]` 区间：

```text
failure_burst_score(i) = min(failures(user_i, date_i) / 8, 1.0)
```

当同一账号在单日内出现大量失败记录时，分数快速升高。该特征适合识别口令尝试、凭据枚举、弱口令扫描。

**4. 账号跨主机扩散度 `host_spread_score`**

统计同一账号涉及的不同主机数量，公式如下：

```text
host_spread_score(i) = min((unique_hosts(user_i) - 1) / 4, 1.0)
```

同一账号在短期内涉及更多主机时，扩散度更高。该特征适合提示横向移动、批量操作、脚本化传播。

**5. 敏感账号高风险动作 `privileged_account_score`**

若日志同时满足以下两个条件，则直接赋值 `0.8`：

- 账号位于敏感账号列表中
- 事件类别位于高风险动作列表中

公式如下：

```text
privileged_account_score(i) =
0.8, if user_i ∈ sensitive_accounts and event_type_i ∈ suspicious_event_types
0.0, otherwise
```

该特征适合强调高权限账号触发执行、持久化、外传等动作时的风险提升。

#### 4.7.5 行为总分计算

五个行为特征按照固定权重组合：

```text
behavior_score(i) =
clip(
  0.30 × rarity_score(i)
+ 0.20 × off_hours_score(i)
+ 0.25 × failure_burst_score(i)
+ 0.15 × host_spread_score(i)
+ 0.10 × privileged_account_score(i),
0, 1
)
```

当前权重体现以下侧重点：

- 稀有度占比最高，强调低频动作的可疑性
- 失败聚集度权重较高，强化口令尝试类信号
- 夜间窗口作为辅助因子，提升时间上下文的敏感度
- 账号扩散度用于反映横向传播趋势
- 敏感账号标签作为增益项，提升关键账号的关注优先级

#### 4.7.6 融合评分与告警判定

规则层和行为层完成打分后，进入融合层。默认融合公式如下：

```text
risk_score(i) =
clip(0.70 × rule_score(i) + 0.30 × behavior_score(i), 0, 1)
```

该设计使规则证据保持主导地位，同时保留行为上下文的补充能力。

判定逻辑如下：

- 当 `risk_score >= 0.62` 时，`candidate = True`
- 当 `behavior_score >= 0.58` 时，`behavior_high = True`

风险等级划分如下：

- `high`：`risk_score >= 0.85`
- `medium`：`0.65 <= risk_score < 0.85`
- `low`：`0.45 <= risk_score < 0.65`
- `info`：`risk_score < 0.45`

为了便于阅读和复核，系统会把融合后的结果进一步写成两类文本：

- `behavior_reasons`：记录行为侧触发原因
- `audit_summary`：记录阶段、风险等级、主规则、行为结论

#### 4.7.7 决策树模型

项目中的机器学习部分使用 `DecisionTreeClassifier`。设计思路强调两点：

- 模型结构保持浅层，便于阅读和可视化
- 输入特征全部来自前面的规则层与行为层，便于理解“模型看到了什么”

模型输入向量可写为：

```text
x_i = [
  rule_score(i),
  rarity_score(i),
  off_hours_score(i),
  failure_burst_score(i),
  host_spread_score(i),
  privileged_account_score(i)
]
```

数据划分方式如下：

```text
train_test_split(
  test_size = 0.30,
  random_state = 7,
  stratify = label
)
```

模型参数如下：

```text
DecisionTreeClassifier(
  max_depth = 4,
  min_samples_leaf = 5,
  class_weight = balanced,
  random_state = 7
)
```

该模型会完成两类工作：

- 在 Holdout 测试集上评估 `precision`、`recall`、`f1`、`accuracy`、`false_positive_rate`
- 在全部样本上重新拟合一棵完整树，用于生成 `tree_score`、树结构图和规则文本

决策树概率输出定义如下：

```text
tree_score(i) = P(y_i = malicious | x_i)
```

阈值判定如下：

```text
tree_prediction(i) = 1, if tree_score(i) >= 0.50
tree_prediction(i) = 0, if tree_score(i) < 0.50
```

决策树模块的价值主要体现在三个方面：

- 用模型方式重新组织人工特征
- 用树结构图直观展示判定路径
- 用特征重要性图显示各个特征对分类结果的贡献

#### 4.7.8 实验设计

为了观察不同策略对结果的影响，项目设计了 7 组实验方案，所有方案统一在 Holdout 测试集上比较：

**1. `rule_only`**

```text
score = rule_score
threshold = 0.75
```

该方案用于观察纯规则策略的精度和召回表现。

**2. `behavior_only`**

```text
score = behavior_score
threshold = 0.60
```

该方案用于观察纯行为策略对低频异常和聚集异常的敏感度。

**3. `fusion_balanced`**

```text
score = risk_score
threshold = 0.62
```

该方案为默认主方案，用于展示规则与行为两条线的平衡效果。

**4. `fusion_sensitive`**

```text
score = 0.55 × rule_score + 0.45 × behavior_score
threshold = 0.55
```

该方案更强调召回能力，适合观察行为信号增强后的变化。

**5. `fusion_precise`**

```text
score = 0.80 × rule_score + 0.20 × behavior_score
threshold = 0.70
```

该方案更强调高置信筛选，适合观察误报率进一步下降时的表现。

**6. `decision_tree`**

```text
score = tree_score
threshold = 0.50
```

该方案用于观察浅层决策树在人工特征上的分类效果。

**7. `fusion_with_tree`**

```text
score = 0.60 × risk_score + 0.40 × tree_score
threshold = 0.58
```

该方案用于观察“规则 + 行为 + 决策树”联合评分的表现。

每组实验均输出以下指标：

- `precision`
- `recall`
- `f1`
- `accuracy`
- `fp_rate`
- `selected_events`
- `true_positive`
- `false_positive`
- `true_negative`
- `false_negative`

#### 4.7.9 算法执行流程

完整执行过程可概括为以下 10 步：

1. 读取或生成样例日志集
2. 对 `message` 执行规则匹配
3. 为每条日志计算 5 个行为特征
4. 计算 `behavior_score`
5. 计算 `risk_score`
6. 按固定比例划分训练集和测试集
7. 训练决策树并计算 `tree_score`
8. 按阈值生成 `candidate`、`severity` 和 `tree_prediction`
9. 运行 7 组实验并统计指标
10. 输出结果表、图表、报告和看板

对应伪代码如下：

```text
for event in events:
    event.rule_score = match_rules(event.message)

compute_global_statistics(events)

for event in events:
    event.rarity_score = rarity(event.event_type)
    event.off_hours_score = off_hours(event.timestamp)
    event.failure_burst_score = failure_burst(event.user, event.date)
    event.host_spread_score = host_spread(event.user)
    event.privileged_account_score = privileged_bonus(event.user, event.event_type)
    event.behavior_score = weighted_sum(...)
    event.risk_score = 0.70 * event.rule_score + 0.30 * event.behavior_score
split train_set, test_set
train decision_tree on train_set features

for event in events:
    event.tree_score = decision_tree_probability(event.features)
    event.candidate = event.risk_score >= 0.62

run_experiments(events)
render_charts(events)
write_report(events)
```

#### 4.7.10 复杂度与复现性

算法复杂度主要来自两部分：

- 规则匹配：约为 `O(N × R)`，其中 `N` 为日志条数，`R` 为规则条数
- 行为统计：主要由分组统计构成，整体规模与 `N` 近似线性相关
- 决策树训练：在当前数据规模下开销较低，适合本地快速迭代与可视化

在当前项目中，`R = 7`，`N = 334`，因此运行开销较低，适合本地快速运行与复核。

复现稳定性来自以下设计：

- 数据生成使用固定随机种子
- 阈值、权重、规则全部写入 `configs/default.toml`
- 全流程仅依赖本地计算
- 输出指标、图表、看板由同一批结果统一生成

## 5. 实验图说明

项目运行后会生成十二张图，覆盖“数据分布、检测效果、阶段覆盖、流程漏斗、方案对比、模型解释”六类视角。

`outputs/report.md` 与 `outputs/dashboard.html` 中会为每张图补充“看图说明”和“当前实验结论”，便于快速理解图表含义。

1. `outputs/charts/01_source_overview.png`：日志来源与标签分布  
   作用：查看不同来源的日志规模，以及恶意事件主要聚集在哪些来源中。
2. `outputs/charts/02_risk_distribution.png`：风险分数分布  
   作用：查看良性事件和恶意事件在风险分数上的分离情况，虚线右侧表示更高优先级的复核区域。
3. `outputs/charts/03_rule_hits.png`：规则命中次数  
   作用：查看哪些规则最常触发，快速定位最显著的攻击痕迹。
4. `outputs/charts/04_host_heatmap.png`：主机与来源风险热力图  
   作用：查看哪些主机在不同日志来源上具有更高平均风险，暖色区域值得优先关注。
5. `outputs/charts/05_attack_timeline.png`：攻击时间线  
   作用：查看风险事件在时间上的聚集窗口，便于定位集中发生的异常时段。
6. `outputs/charts/06_stage_coverage.png`：攻击阶段覆盖情况  
   作用：查看每个攻击阶段的真实恶意数量与检测命中数量是否接近。
7. `outputs/charts/07_confusion_matrix.png`：融合方案混淆矩阵  
   作用：查看真阳性、假阳性、真阴性、假阴性的分布，评估分类稳定性。
8. `outputs/charts/08_experiment_comparison.png`：实验方案对比  
   作用：查看不同方案在 Precision、Recall、F1 上的差异，便于选择更均衡的方案。
9. `outputs/charts/09_funnel.png`：筛选漏斗  
   作用：查看日志从总量到真实命中的逐层收缩过程，理解筛选链路是否清晰。
10. `outputs/charts/10_tree_feature_importance.png`：决策树特征重要性  
    作用：查看决策树更依赖哪些输入特征，数值越大说明贡献越明显。
11. `outputs/charts/11_tree_structure.png`：决策树结构  
    作用：直接查看模型如何沿着条件分裂做判断，顶层条件影响更大。
12. `outputs/charts/12_tree_score_distribution.png`：决策树分数分布  
    作用：查看决策树输出概率对良性和恶意事件的区分情况，重叠越少越容易解释。

### 5.1 图表预览

![来源分布](outputs/charts/01_source_overview.png)

说明：红色占比越高，说明该来源中的恶意事件比例越高。

![风险分布](outputs/charts/02_risk_distribution.png)

说明：两类分布越分开，风险分数越具备区分能力。

![阶段覆盖](outputs/charts/06_stage_coverage.png)

说明：两组柱形越接近，说明检测阶段覆盖越完整。

![方案对比](outputs/charts/08_experiment_comparison.png)

说明：可优先关注 F1 较高且 Precision、Recall 更均衡的方案。

![筛选漏斗](outputs/charts/09_funnel.png)

说明：漏斗越清晰，说明筛选逻辑越容易理解。

![决策树特征重要性](outputs/charts/10_tree_feature_importance.png)

说明：条形越长，说明该特征对模型判定越关键。

![决策树结构](outputs/charts/11_tree_structure.png)

说明：从根节点向下阅读，即可看到模型的完整判断路径。

## 6. 快速开始

### 6.1 运行条件

- Python 版本：`3.11+`
- 已验证版本：`Python 3.12.7`
- 依赖清单：`requirements.txt`
- 运行方式：默认走本地流程，无需额外接入远程模型接口

### 6.2 安装依赖

PowerShell：

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

如需创建独立虚拟环境，可使用以下方式：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 6.3 运行方式

PowerShell：

```powershell
cd <项目目录>
$env:PYTHONPATH = "$PWD\src"
python -m nanoaudit.cli --config configs/default.toml run --rebuild-data
```

一键脚本：

```powershell
cd <项目目录>
powershell -ExecutionPolicy Bypass -File .\scripts\run_demo.ps1
```

### 6.4 单独执行

生成数据：

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m nanoaudit.cli --config configs/default.toml make-data --force
```

查看最近一次指标：

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m nanoaudit.cli --config configs/default.toml summary
```

检查产物完整性：

```powershell
python scripts/check_outputs.py
```

### 6.5 版本说明

`requirements.txt` 锁定了当前已验证通过的核心依赖版本：

- `numpy==1.26.4`
- `pandas==2.2.2`
- `matplotlib==3.9.2`
- `scikit-learn==1.5.1`

如需使用 `pyproject.toml` 中的宽松依赖范围，也可直接执行：

```powershell
python -m pip install -e .
```

## 7. 建议阅读顺序

### 第一段：先看数据

先打开 `data/demo_logs.csv`，观察 `timestamp`、`user`、`host`、`event_type`、`message` 五列，理解每条日志包含的信息。

### 第二段：再看规则

打开 `src/nanoaudit/rules.py`，查看七条规则如何命中关键文本特征。

### 第三段：再看行为

先阅读 `README.md` 中的“4.7 算法设计详解”，再打开 `src/nanoaudit/scoring.py`，查看五个行为分数组件如何形成 `behavior_score`。

### 第四段：再看决策树

打开 `src/nanoaudit/ml.py`，查看决策树使用了哪些特征、如何划分训练集和测试集、如何输出模型概率与规则文本。

### 第五段：最后看图表

打开 `outputs/dashboard.html`，结合十二张图理解模型筛选逻辑与实验结果。

## 8. 稳定复现说明

- 固定随机种子写在 `configs/default.toml`
- 所有结果均可通过单条命令重建
- `scripts/check_outputs.py` 会检查关键输出文件
- `docs/review_rounds.md` 记录了三轮结构与表达优化

## 9. 建议的展示顺序

1. `README.md`
2. `docs/architecture.md`
3. `outputs/dashboard.html`
4. `outputs/report.md`
5. `src/nanoaudit/scoring.py`
