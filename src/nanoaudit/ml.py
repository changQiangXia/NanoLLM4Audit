from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, export_text

from nanoaudit.config import ProjectConfig


TREE_FEATURE_COLUMNS = [
    "rule_score",
    "rarity_score",
    "off_hours_score",
    "failure_burst_score",
    "host_spread_score",
    "privileged_account_score",
]


@dataclass(slots=True)
class DecisionTreeRunResult:
    scored: pd.DataFrame
    holdout_frame: pd.DataFrame
    metrics: dict
    model: DecisionTreeClassifier
    feature_names: list[str]


def run_decision_tree(scored: pd.DataFrame, config: ProjectConfig) -> DecisionTreeRunResult:
    feature_frame = scored[TREE_FEATURE_COLUMNS].astype(float)
    labels = scored["label"].astype(int)

    train_index, test_index = train_test_split(
        scored.index.to_numpy(),
        test_size=config.decision_tree.test_size,
        random_state=config.random_seed,
        stratify=labels.to_numpy(),
    )

    train_features = feature_frame.loc[train_index]
    test_features = feature_frame.loc[test_index]
    train_labels = labels.loc[train_index]
    test_labels = labels.loc[test_index]

    eval_model = build_tree_model(config)
    eval_model.fit(train_features, train_labels)
    test_probability = eval_model.predict_proba(test_features)[:, 1]
    test_prediction = (test_probability >= config.decision_tree.threshold).astype(int)

    full_model = build_tree_model(config)
    full_model.fit(feature_frame, labels)
    full_probability = full_model.predict_proba(feature_frame)[:, 1]
    full_prediction = (full_probability >= config.decision_tree.threshold).astype(int)

    scored_out = scored.copy()
    scored_out["tree_score"] = full_probability
    scored_out["tree_prediction"] = full_prediction.astype(bool)
    scored_out["evaluation_split"] = "train"
    scored_out.loc[test_index, "evaluation_split"] = "test"

    holdout_frame = scored_out.loc[test_index, ["label", "rule_score", "behavior_score", "risk_score"]].copy()
    holdout_frame["tree_score"] = test_probability
    holdout_frame["tree_prediction"] = test_prediction

    metrics = build_tree_metrics(
        config=config,
        test_labels=test_labels.to_numpy(),
        test_prediction=test_prediction,
        test_probability=test_probability,
        train_size=len(train_index),
        test_size=len(test_index),
        model=full_model,
    )

    return DecisionTreeRunResult(
        scored=scored_out,
        holdout_frame=holdout_frame,
        metrics=metrics,
        model=full_model,
        feature_names=list(TREE_FEATURE_COLUMNS),
    )


def build_tree_model(config: ProjectConfig) -> DecisionTreeClassifier:
    class_weight = "balanced" if config.decision_tree.class_weight_balanced else None
    return DecisionTreeClassifier(
        criterion="gini",
        max_depth=config.decision_tree.max_depth,
        min_samples_leaf=config.decision_tree.min_samples_leaf,
        random_state=config.random_seed,
        class_weight=class_weight,
    )


def build_tree_metrics(
    *,
    config: ProjectConfig,
    test_labels: np.ndarray,
    test_prediction: np.ndarray,
    test_probability: np.ndarray,
    train_size: int,
    test_size: int,
    model: DecisionTreeClassifier,
) -> dict:
    tp = int(((test_labels == 1) & (test_prediction == 1)).sum())
    fp = int(((test_labels == 0) & (test_prediction == 1)).sum())
    tn = int(((test_labels == 0) & (test_prediction == 0)).sum())
    fn = int(((test_labels == 1) & (test_prediction == 0)).sum())

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    fp_rate = fp / max(fp + tn, 1)

    return {
        "model_name": "DecisionTreeClassifier",
        "threshold": config.decision_tree.threshold,
        "train_size": train_size,
        "test_size": test_size,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "false_positive_rate": fp_rate,
        "confusion_matrix": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        },
        "tree_depth": int(model.get_depth()),
        "leaf_count": int(model.get_n_leaves()),
        "feature_columns": list(TREE_FEATURE_COLUMNS),
        "feature_importance": {
            feature_name: float(importance)
            for feature_name, importance in zip(TREE_FEATURE_COLUMNS, model.feature_importances_)
        },
        "holdout_score_summary": {
            "mean_probability": float(np.mean(test_probability)),
            "max_probability": float(np.max(test_probability)),
            "min_probability": float(np.min(test_probability)),
        },
    }


def write_tree_outputs(result: DecisionTreeRunResult, metrics_path: Path, rules_path: Path) -> None:
    metrics_path.write_text(json.dumps(result.metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    rules_path.write_text(export_text(result.model, feature_names=result.feature_names), encoding="utf-8")
