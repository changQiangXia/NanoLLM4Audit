from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


CHART_ORDER = [
    (
        "01_source_overview.png",
        "图 1：日志来源与标签分布",
        "用于观察不同日志来源的总体规模，以及恶意事件主要集中在哪些来源类型中。",
    ),
    (
        "02_risk_distribution.png",
        "图 2：风险分数分布",
        "用于观察良性事件和恶意事件在风险分数上的分离程度，虚线右侧为更值得优先复核的区域。",
    ),
    (
        "03_rule_hits.png",
        "图 3：规则命中次数",
        "用于观察哪些规则命中最频繁，条形越长，说明该类攻击痕迹在数据中越突出。",
    ),
    (
        "04_host_heatmap.png",
        "图 4：主机与来源风险热力图",
        "用于观察哪些主机在特定日志来源上呈现较高平均风险，颜色越暖代表关注优先级越高。",
    ),
    (
        "05_attack_timeline.png",
        "图 5：时间线",
        "用于观察风险事件在时间维度上的聚集情况，峰值越明显，越容易定位集中发生的攻击窗口。",
    ),
    (
        "06_stage_coverage.png",
        "图 6：攻击阶段覆盖情况",
        "用于比较各攻击阶段的真实恶意事件量与检测命中量，两组柱形越接近，说明覆盖越完整。",
    ),
    (
        "07_confusion_matrix.png",
        "图 7：融合方案混淆矩阵",
        "用于观察分类结果的四种情况，左上和右下数值越高，说明整体判定越稳定。",
    ),
    (
        "08_experiment_comparison.png",
        "图 8：实验方案对比",
        "用于横向比较不同方案的 Precision、Recall 和 F1，便于快速选择更均衡的配置。",
    ),
    (
        "09_funnel.png",
        "图 9：筛选漏斗",
        "用于展示日志从总量到规则命中、行为增强、高风险候选、真实命中的逐步收缩过程。",
    ),
    (
        "10_tree_feature_importance.png",
        "图 10：决策树特征重要性",
        "用于观察决策树更依赖哪些输入特征，数值越大，说明该特征对模型判断的贡献越明显。",
    ),
    (
        "11_tree_structure.png",
        "图 11：决策树结构",
        "用于直接查看模型的判定路径，越靠近根节点的分裂条件，对结果的影响越显著。",
    ),
    (
        "12_tree_score_distribution.png",
        "图 12：决策树分数分布",
        "用于观察决策树输出概率对良性与恶意事件的区分程度，重叠越少，区分效果越直观。",
    ),
]


def write_report(scored: pd.DataFrame, experiments: pd.DataFrame, metrics: dict, report_path: Path) -> None:
    stage_summary = (
        scored.groupby("attack_stage")
        .agg(event_count=("event_id", "count"), avg_risk=("risk_score", "mean"), detected=("candidate", "sum"))
        .reset_index()
    )
    chart_conclusions = build_chart_conclusions(scored, experiments, metrics)
    lines = [
        "# NanoLLM4Audit 实验报告",
        "",
        "## 1. 数据概览",
        f"- 事件总量：{metrics['event_count']}",
        f"- 标记为高风险的事件量：{metrics['candidate_count']}",
        f"- 恶意样本量：{metrics['malicious_count']}",
        f"- 融合方案 Precision：{metrics['precision']:.3f}",
        f"- 融合方案 Recall：{metrics['recall']:.3f}",
        f"- 融合方案 F1：{metrics['f1']:.3f}",
        f"- 融合方案误报率：{metrics['false_positive_rate']:.3f}",
        "",
        "## 2. 最佳实验方案",
        f"- 名称：{metrics['best_experiment']['name']}",
        f"- Precision：{metrics['best_experiment']['precision']:.3f}",
        f"- Recall：{metrics['best_experiment']['recall']:.3f}",
        f"- F1：{metrics['best_experiment']['f1']:.3f}",
        f"- 评估范围：{metrics['best_experiment']['evaluation_scope']}",
        "",
        "## 3. 决策树模型",
        f"- 模型：{metrics['decision_tree']['model_name']}",
        f"- 训练集大小：{metrics['decision_tree']['train_size']}",
        f"- 测试集大小：{metrics['decision_tree']['test_size']}",
        f"- Holdout Precision：{metrics['decision_tree']['precision']:.3f}",
        f"- Holdout Recall：{metrics['decision_tree']['recall']:.3f}",
        f"- Holdout F1：{metrics['decision_tree']['f1']:.3f}",
        f"- Holdout Accuracy：{metrics['decision_tree']['accuracy']:.3f}",
        f"- Holdout 误报率：{metrics['decision_tree']['false_positive_rate']:.3f}",
        f"- 树深度：{metrics['decision_tree']['tree_depth']}",
        f"- 叶子节点数：{metrics['decision_tree']['leaf_count']}",
        f"- 决策规则文本：`tree_rules.txt`",
        "",
        "## 4. 阶段汇总",
        "",
        dataframe_to_markdown(stage_summary),
        "",
        "## 5. 实验表",
        "",
        dataframe_to_markdown(experiments),
        "",
        "## 6. 图表索引",
        "",
    ]
    for filename, title, description in CHART_ORDER:
        lines.append(f"- {title}：`charts/{filename}`")
        lines.append(f"  - 说明：{description}")
        lines.append(f"  - 当前实验结论：{chart_conclusions[filename]}")
    lines.extend(
        [
            "",
            "## 7. 图表展示",
            "",
        ]
    )
    for filename, title, description in CHART_ORDER:
        lines.append(f"### {title}")
        lines.append("")
        lines.append(f"- 看图说明：{description}")
        lines.append(f"- 当前实验结论：{chart_conclusions[filename]}")
        lines.append("")
        lines.append(f"![{title}](charts/{filename})")
        lines.append("")
    report_path.write_text("\n".join(lines), encoding="utf-8")


def write_dashboard(experiments: pd.DataFrame, metrics: dict, dashboard_path: Path) -> None:
    chart_conclusions = build_chart_conclusions_from_metrics(experiments, metrics)
    cards = [
        ("事件总量", metrics["event_count"]),
        ("高风险事件", metrics["candidate_count"]),
        ("恶意样本", metrics["malicious_count"]),
        ("Precision", f"{metrics['precision']:.3f}"),
        ("Recall", f"{metrics['recall']:.3f}"),
        ("F1", f"{metrics['f1']:.3f}"),
        ("Tree F1", f"{metrics['decision_tree']['f1']:.3f}"),
        ("Tree Depth", metrics["decision_tree"]["tree_depth"]),
    ]
    experiment_rows = "\n".join(
        "<tr>"
        f"<td>{row['name']}</td>"
        f"<td>{row['precision']:.3f}</td>"
        f"<td>{row['recall']:.3f}</td>"
        f"<td>{row['f1']:.3f}</td>"
        f"<td>{row['fp_rate']:.3f}</td>"
        f"<td>{int(row['selected_events'])}</td>"
        "</tr>"
        for _, row in experiments.iterrows()
    )
    card_html = "\n".join(
        f"<div class='card'><div class='card-title'>{title}</div><div class='card-value'>{value}</div></div>"
        for title, value in cards
    )
    chart_blocks = "\n".join(
        "<section class='chart-block'>"
        f"<h3>{title}</h3>"
        f"<p class='chart-desc'>{description}</p>"
        f"<p class='chart-takeaway'>当前实验结论：{chart_conclusions[filename]}</p>"
        f"<img src='charts/{filename}' alt='{title}'>"
        "</section>"
        for filename, title, description in CHART_ORDER
    )
    content = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>NanoLLM4Audit Dashboard</title>
  <style>
    body {{
      font-family: "Segoe UI", "Microsoft YaHei", sans-serif;
      margin: 0;
      background: #f8fafc;
      color: #0f172a;
    }}
    header {{
      background: #0f172a;
      color: white;
      padding: 24px 32px;
    }}
    main {{
      padding: 24px 32px 40px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .card {{
      background: white;
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    }}
    .card-title {{
      font-size: 13px;
      color: #475569;
      margin-bottom: 6px;
    }}
    .card-value {{
      font-size: 28px;
      font-weight: 700;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: white;
      margin-bottom: 24px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    }}
    th, td {{
      padding: 12px 14px;
      border-bottom: 1px solid #e2e8f0;
      text-align: left;
    }}
    th {{
      background: #e2e8f0;
    }}
    .chart-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 16px;
    }}
    .chart-block {{
      background: white;
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
    }}
    .chart-block img {{
      width: 100%;
      border-radius: 10px;
      border: 1px solid #e2e8f0;
    }}
    .chart-desc {{
      color: #475569;
      line-height: 1.6;
      margin: 0 0 12px;
      font-size: 14px;
    }}
    .chart-takeaway {{
      color: #0f172a;
      line-height: 1.6;
      margin: 0 0 12px;
      font-size: 14px;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <header>
    <h1>NanoLLM4Audit 结果看板</h1>
    <p>聚焦日志审计主链路：数据、规则、行为、融合、图表。</p>
  </header>
  <main>
    <section class="cards">
      {card_html}
    </section>
    <section>
      <h2>实验结果</h2>
      <table>
        <thead>
          <tr>
            <th>方案</th>
            <th>Precision</th>
            <th>Recall</th>
            <th>F1</th>
            <th>误报率</th>
            <th>入选事件</th>
          </tr>
        </thead>
        <tbody>
          {experiment_rows}
        </tbody>
      </table>
    </section>
    <section class="chart-grid">
      {chart_blocks}
    </section>
  </main>
</body>
</html>
"""
    dashboard_path.write_text(content, encoding="utf-8")


def write_metrics(metrics: dict, path: Path) -> None:
    path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")


def dataframe_to_markdown(frame: pd.DataFrame) -> str:
    headers = [str(column) for column in frame.columns]
    separator = ["---"] * len(headers)
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(separator) + " |",
    ]
    for row in frame.itertuples(index=False):
        values = [format_markdown_value(value) for value in row]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def format_markdown_value(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def build_chart_conclusions(scored: pd.DataFrame, experiments: pd.DataFrame, metrics: dict) -> dict[str, str]:
    conclusions = build_chart_conclusions_from_metrics(experiments, metrics)

    malicious_by_source = scored.loc[scored["label"] == 1, "source_type"].value_counts()
    if not malicious_by_source.empty:
        top_source = str(malicious_by_source.index[0])
        top_source_count = int(malicious_by_source.iloc[0])
        conclusions["01_source_overview.png"] = (
            f"恶意事件主要集中在 `{top_source}`，共 {top_source_count} 条，来源分布具备明显聚集性。"
        )

    benign_mean = float(scored.loc[scored["label"] == 0, "risk_score"].mean())
    malicious_mean = float(scored.loc[scored["label"] == 1, "risk_score"].mean())
    malicious_candidate_rate = float(scored.loc[scored["label"] == 1, "candidate"].mean())
    benign_candidate_rate = float(scored.loc[scored["label"] == 0, "candidate"].mean())
    conclusions["02_risk_distribution.png"] = (
        f"恶意事件平均风险分数为 {malicious_mean:.3f}，良性事件为 {benign_mean:.3f}；"
        f"阈值以上的恶意命中率为 {malicious_candidate_rate:.1%}，良性误入率为 {benign_candidate_rate:.1%}。"
    )

    rule_hits = scored.loc[scored["rule_id"] != "", "rule_id"].value_counts()
    if not rule_hits.empty:
        top_rule = str(rule_hits.index[0])
        top_rule_count = int(rule_hits.iloc[0])
        conclusions["03_rule_hits.png"] = (
            f"当前数据中命中最多的规则为 `{top_rule}`，共触发 {top_rule_count} 次。"
        )

    host_heat = (
        scored.groupby(["host", "source_type"], as_index=False)["risk_score"]
        .mean()
        .sort_values("risk_score", ascending=False)
    )
    if not host_heat.empty:
        top_heat = host_heat.iloc[0]
        conclusions["04_host_heatmap.png"] = (
            f"`{top_heat['host']}` 在 `{top_heat['source_type']}` 来源上的平均风险最高，达到 {float(top_heat['risk_score']):.3f}。"
        )

    timeline = scored.assign(hour_bucket=scored["timestamp"].dt.floor("2h")).groupby("hour_bucket").agg(
        candidate_count=("candidate", "sum"),
        malicious_count=("label", "sum"),
    )
    if not timeline.empty:
        peak_row = timeline.sort_values(["candidate_count", "malicious_count"], ascending=False).iloc[0]
        peak_time = timeline.sort_values(["candidate_count", "malicious_count"], ascending=False).index[0]
        conclusions["05_attack_timeline.png"] = (
            f"风险事件最集中的时间窗口为 `{peak_time}`，该窗口内高风险候选 {int(peak_row['candidate_count'])} 条。"
        )

    malicious_stage = scored.loc[scored["label"] == 1].groupby("attack_stage").size()
    detected_stage = scored.loc[(scored["label"] == 1) & (scored["candidate"])].groupby("attack_stage").size()
    if not malicious_stage.empty:
        stage_rate = (detected_stage / malicious_stage).fillna(0.0)
        if float(stage_rate.min()) == 1.0:
            conclusions["06_stage_coverage.png"] = "所有攻击阶段均实现 100% 命中，阶段覆盖保持完整。"
        else:
            weakest_stage = str(stage_rate.sort_values().index[0])
            weakest_rate = float(stage_rate.sort_values().iloc[0])
            conclusions["06_stage_coverage.png"] = (
                f"`{weakest_stage}` 的阶段命中率最低，为 {weakest_rate:.1%}，适合优先关注该阶段的补强空间。"
            )

    confusion = metrics["confusion_matrix"]
    conclusions["07_confusion_matrix.png"] = (
        f"融合方案当前得到 TP={confusion['tp']}、FP={confusion['fp']}、TN={confusion['tn']}、FN={confusion['fn']}，整体判定稳定。"
    )

    total = int(len(scored))
    rule_hit = int((scored["rule_score"] > 0).sum())
    behavior_high = int(scored["behavior_high"].sum())
    candidate = int(scored["candidate"].sum())
    true_positive = int(((scored["candidate"]) & (scored["label"] == 1)).sum())
    conclusions["09_funnel.png"] = (
        f"日志由 {total} 条逐步收缩到规则命中 {rule_hit} 条、行为增强 {behavior_high} 条、最终真实命中 {true_positive} 条。"
    )

    feature_importance = metrics["decision_tree"]["feature_importance"]
    ordered_importance = sorted(feature_importance.items(), key=lambda item: item[1], reverse=True)
    if ordered_importance:
        first_name, first_value = ordered_importance[0]
        second_name, second_value = ordered_importance[1] if len(ordered_importance) > 1 else ("无", 0.0)
        conclusions["10_tree_feature_importance.png"] = (
            f"决策树最依赖 `{first_name}`（{first_value:.3f}），其次为 `{second_name}`（{second_value:.3f}）。"
        )

    conclusions["11_tree_structure.png"] = (
        f"当前树深度为 {metrics['decision_tree']['tree_depth']}，叶子节点数为 {metrics['decision_tree']['leaf_count']}，结构保持浅层，便于人工复核。"
    )

    benign_tree_mean = float(scored.loc[scored["label"] == 0, "tree_score"].mean())
    malicious_tree_mean = float(scored.loc[scored["label"] == 1, "tree_score"].mean())
    conclusions["12_tree_score_distribution.png"] = (
        f"恶意事件平均树分数为 {malicious_tree_mean:.3f}，良性事件为 {benign_tree_mean:.3f}，两类事件具备清晰分离。"
    )

    return conclusions


def build_chart_conclusions_from_metrics(experiments: pd.DataFrame, metrics: dict) -> dict[str, str]:
    ordered = experiments.sort_values(["f1", "precision", "recall"], ascending=False).reset_index(drop=True)
    best = ordered.iloc[0]
    second = ordered.iloc[1] if len(ordered) > 1 else ordered.iloc[0]
    return {
        "01_source_overview.png": "来源分布存在明显聚集，高风险来源适合优先进入复核视角。",
        "02_risk_distribution.png": "风险分数呈现良性与恶意分层，阈值右侧区域具备更高处置优先级。",
        "03_rule_hits.png": "高频规则命中区域可直接对应重点攻击痕迹。",
        "04_host_heatmap.png": "高热区域主机更适合作为排查起点。",
        "05_attack_timeline.png": "时间峰值对应的窗口适合优先回看原始日志。",
        "06_stage_coverage.png": "阶段覆盖图可直接用于检查检测链路是否存在缺口。",
        "07_confusion_matrix.png": (
            f"当前主方案的误报率为 {metrics['false_positive_rate']:.3f}，分类结果整体稳定。"
        ),
        "08_experiment_comparison.png": (
            f"当前最优方案为 `{best['name']}`，F1={float(best['f1']):.3f}；"
            f"次优方案为 `{second['name']}`，F1={float(second['f1']):.3f}。"
        ),
        "09_funnel.png": "漏斗收缩过程清晰，便于理解从海量日志到真实命中的筛选路径。",
        "10_tree_feature_importance.png": "决策树特征重要性能够直接解释模型依赖的核心判断依据。",
        "11_tree_structure.png": (
            f"当前树深度为 {metrics['decision_tree']['tree_depth']}，模型保持浅层结构。"
        ),
        "12_tree_score_distribution.png": "树分数分布呈现分层时，模型的概率输出更容易解释。",
    }
