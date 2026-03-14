from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.tree import plot_tree

from nanoaudit.ml import DecisionTreeRunResult


def generate_all_charts(
    scored: pd.DataFrame,
    experiments: pd.DataFrame,
    tree_result: DecisionTreeRunResult,
    charts_dir: Path,
) -> list[Path]:
    charts_dir.mkdir(parents=True, exist_ok=True)
    return [
        plot_source_overview(scored, charts_dir / "01_source_overview.png"),
        plot_risk_distribution(scored, charts_dir / "02_risk_distribution.png"),
        plot_rule_hits(scored, charts_dir / "03_rule_hits.png"),
        plot_host_heatmap(scored, charts_dir / "04_host_heatmap.png"),
        plot_attack_timeline(scored, charts_dir / "05_attack_timeline.png"),
        plot_stage_coverage(scored, charts_dir / "06_stage_coverage.png"),
        plot_confusion_matrix(scored, charts_dir / "07_confusion_matrix.png"),
        plot_experiment_comparison(experiments, charts_dir / "08_experiment_comparison.png"),
        plot_funnel(scored, charts_dir / "09_funnel.png"),
        plot_tree_feature_importance(tree_result, charts_dir / "10_tree_feature_importance.png"),
        plot_tree_structure(tree_result, charts_dir / "11_tree_structure.png"),
        plot_tree_score_distribution(scored, tree_result, charts_dir / "12_tree_score_distribution.png"),
    ]


def setup_axes(fig, ax) -> None:
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.grid(alpha=0.15)


def plot_source_overview(scored: pd.DataFrame, path: Path) -> Path:
    grouped = scored.groupby(["source_type", "label"]).size().unstack(fill_value=0).rename(columns={0: "benign", 1: "malicious"})
    grouped = grouped.sort_values("malicious", ascending=False)
    fig, ax = plt.subplots(figsize=(11, 6))
    setup_axes(fig, ax)
    ax.bar(grouped.index, grouped["benign"], label="benign", color="#93c5fd")
    ax.bar(grouped.index, grouped["malicious"], bottom=grouped["benign"], label="malicious", color="#ef4444")
    ax.set_title("Event Volume by Source Type")
    ax.set_ylabel("count")
    ax.set_xlabel("source type")
    ax.tick_params(axis="x", rotation=25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_risk_distribution(scored: pd.DataFrame, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(10, 6))
    setup_axes(fig, ax)
    benign = scored.loc[scored["label"] == 0, "risk_score"]
    malicious = scored.loc[scored["label"] == 1, "risk_score"]
    bins = np.linspace(0.0, 1.0, 18)
    ax.hist(benign, bins=bins, alpha=0.7, label="benign", color="#60a5fa")
    ax.hist(malicious, bins=bins, alpha=0.7, label="malicious", color="#ef4444")
    ax.axvline(0.62, color="#111827", linestyle="--", linewidth=1.2, label="candidate threshold")
    ax.set_title("Risk Score Distribution")
    ax.set_xlabel("risk score")
    ax.set_ylabel("count")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_rule_hits(scored: pd.DataFrame, path: Path) -> Path:
    counts = scored.loc[scored["rule_id"] != "", "rule_id"].value_counts().head(8).sort_values()
    fig, ax = plt.subplots(figsize=(10, 6))
    setup_axes(fig, ax)
    ax.barh(counts.index, counts.values, color="#10b981")
    ax.set_title("Rule Hits")
    ax.set_xlabel("count")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_host_heatmap(scored: pd.DataFrame, path: Path) -> Path:
    pivot = scored.pivot_table(index="host", columns="source_type", values="risk_score", aggfunc="mean", fill_value=0.0)
    fig, ax = plt.subplots(figsize=(11, 6))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    image = ax.imshow(pivot.values, cmap="YlOrRd", aspect="auto", vmin=0.0, vmax=max(0.6, float(pivot.values.max())))
    ax.set_title("Average Risk by Host and Source")
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns, rotation=25, ha="right")
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)
    for row_index in range(pivot.shape[0]):
        for column_index in range(pivot.shape[1]):
            ax.text(column_index, row_index, f"{pivot.values[row_index, column_index]:.2f}", ha="center", va="center", fontsize=8)
    fig.colorbar(image, ax=ax, label="risk score")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_attack_timeline(scored: pd.DataFrame, path: Path) -> Path:
    timeline = scored.assign(hour_bucket=scored["timestamp"].dt.floor("2h")).groupby("hour_bucket").agg(
        candidate_count=("candidate", "sum"),
        malicious_count=("label", "sum"),
    )
    fig, ax = plt.subplots(figsize=(12, 6))
    setup_axes(fig, ax)
    ax.plot(timeline.index, timeline["candidate_count"], marker="o", color="#2563eb", label="candidate count")
    ax.plot(timeline.index, timeline["malicious_count"], marker="s", color="#dc2626", label="malicious count")
    ax.set_title("Attack Timeline")
    ax.set_xlabel("time bucket")
    ax.set_ylabel("count")
    ax.tick_params(axis="x", rotation=25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_stage_coverage(scored: pd.DataFrame, path: Path) -> Path:
    malicious = scored.loc[scored["label"] == 1].groupby("attack_stage").size()
    detected = scored.loc[(scored["label"] == 1) & (scored["candidate"])].groupby("attack_stage").size()
    stages = sorted(set(malicious.index) | set(detected.index))
    malicious = malicious.reindex(stages, fill_value=0)
    detected = detected.reindex(stages, fill_value=0)
    x_positions = np.arange(len(stages))
    fig, ax = plt.subplots(figsize=(11, 6))
    setup_axes(fig, ax)
    ax.bar(x_positions - 0.18, malicious.values, width=0.36, color="#fca5a5", label="malicious ground truth")
    ax.bar(x_positions + 0.18, detected.values, width=0.36, color="#14b8a6", label="detected by fusion")
    ax.set_title("Stage Coverage")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(stages, rotation=20, ha="right")
    ax.set_ylabel("count")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_confusion_matrix(scored: pd.DataFrame, path: Path) -> Path:
    y_true = scored["label"].astype(int)
    y_pred = scored["candidate"].astype(int)
    matrix = np.array(
        [
            [int(((y_true == 1) & (y_pred == 1)).sum()), int(((y_true == 1) & (y_pred == 0)).sum())],
            [int(((y_true == 0) & (y_pred == 1)).sum()), int(((y_true == 0) & (y_pred == 0)).sum())],
        ]
    )
    fig, ax = plt.subplots(figsize=(6, 5))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    image = ax.imshow(matrix, cmap="Blues")
    ax.set_title("Fusion Confusion Matrix")
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["predicted alert", "predicted stable"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["actual malicious", "actual benign"])
    for row_index in range(2):
        for column_index in range(2):
            ax.text(column_index, row_index, matrix[row_index, column_index], ha="center", va="center", fontsize=12)
    fig.colorbar(image, ax=ax)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_experiment_comparison(experiments: pd.DataFrame, path: Path) -> Path:
    ordered = experiments.sort_values("f1", ascending=False)
    x_positions = np.arange(len(ordered))
    width = 0.22
    fig, ax = plt.subplots(figsize=(12, 6))
    setup_axes(fig, ax)
    ax.bar(x_positions - width, ordered["precision"], width=width, label="precision", color="#2563eb")
    ax.bar(x_positions, ordered["recall"], width=width, label="recall", color="#f59e0b")
    ax.bar(x_positions + width, ordered["f1"], width=width, label="f1", color="#10b981")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(ordered["name"], rotation=20, ha="right")
    ax.set_ylim(0.0, 1.05)
    ax.set_title("Experiment Comparison")
    ax.set_ylabel("score")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_funnel(scored: pd.DataFrame, path: Path) -> Path:
    stages = {
        "total": len(scored),
        "rule_hit": int((scored["rule_score"] > 0).sum()),
        "behavior_high": int(scored["behavior_high"].sum()),
        "candidate": int(scored["candidate"].sum()),
        "true_positive": int(((scored["candidate"]) & (scored["label"] == 1)).sum()),
    }
    labels = list(stages.keys())
    values = list(stages.values())
    fig, ax = plt.subplots(figsize=(9, 6))
    setup_axes(fig, ax)
    ax.bar(labels, values, color=["#cbd5e1", "#93c5fd", "#fdba74", "#fca5a5", "#14b8a6"])
    ax.set_title("Screening Funnel")
    ax.set_ylabel("count")
    for index, value in enumerate(values):
        ax.text(index, value + 2, str(value), ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_tree_feature_importance(tree_result: DecisionTreeRunResult, path: Path) -> Path:
    importance_map = tree_result.metrics["feature_importance"]
    frame = (
        pd.DataFrame({"feature": list(importance_map.keys()), "importance": list(importance_map.values())})
        .sort_values("importance", ascending=True)
    )
    fig, ax = plt.subplots(figsize=(10, 6))
    setup_axes(fig, ax)
    ax.barh(frame["feature"], frame["importance"], color="#8b5cf6")
    ax.set_title("Decision Tree Feature Importance")
    ax.set_xlabel("importance")
    for index, value in enumerate(frame["importance"]):
        ax.text(value + 0.01, index, f"{value:.3f}", va="center")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def plot_tree_structure(tree_result: DecisionTreeRunResult, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(22, 10))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    plot_tree(
        tree_result.model,
        feature_names=tree_result.feature_names,
        class_names=["benign", "malicious"],
        filled=True,
        rounded=True,
        impurity=False,
        proportion=True,
        ax=ax,
        fontsize=8,
    )
    ax.set_title("Decision Tree Structure")
    fig.tight_layout()
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)
    return path


def plot_tree_score_distribution(scored: pd.DataFrame, tree_result: DecisionTreeRunResult, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(10, 6))
    setup_axes(fig, ax)
    benign = scored.loc[scored["label"] == 0, "tree_score"]
    malicious = scored.loc[scored["label"] == 1, "tree_score"]
    bins = np.linspace(0.0, 1.0, 18)
    ax.hist(benign, bins=bins, alpha=0.7, label="benign", color="#93c5fd")
    ax.hist(malicious, bins=bins, alpha=0.7, label="malicious", color="#a855f7")
    ax.axvline(
        tree_result.metrics["threshold"],
        color="#111827",
        linestyle="--",
        linewidth=1.2,
        label="tree threshold",
    )
    ax.set_title("Decision Tree Score Distribution")
    ax.set_xlabel("tree score")
    ax.set_ylabel("count")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path
