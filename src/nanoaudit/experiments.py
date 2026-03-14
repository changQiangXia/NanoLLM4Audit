from __future__ import annotations

from dataclasses import asdict, dataclass

import pandas as pd


@dataclass(slots=True)
class ExperimentResult:
    name: str
    evaluation_scope: str
    support: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    fp_rate: float
    selected_events: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int


def run_experiments(holdout: pd.DataFrame, tree_metrics: dict) -> pd.DataFrame:
    variants = [
        ("rule_only", holdout["rule_score"], 0.75),
        ("behavior_only", holdout["behavior_score"], 0.60),
        ("fusion_balanced", holdout["risk_score"], 0.62),
        ("fusion_sensitive", 0.55 * holdout["rule_score"] + 0.45 * holdout["behavior_score"], 0.55),
        ("fusion_precise", 0.80 * holdout["rule_score"] + 0.20 * holdout["behavior_score"], 0.70),
        ("decision_tree", holdout["tree_score"], tree_metrics["threshold"]),
        ("fusion_with_tree", 0.60 * holdout["risk_score"] + 0.40 * holdout["tree_score"], 0.58),
    ]
    results = [
        evaluate_variant(
            name=name,
            score=score,
            threshold=threshold,
            labels=holdout["label"],
            evaluation_scope="holdout_test",
        )
        for name, score, threshold in variants
    ]
    return pd.DataFrame(asdict(result) for result in results)


def evaluate_variant(
    name: str,
    score: pd.Series,
    threshold: float,
    labels: pd.Series,
    evaluation_scope: str,
) -> ExperimentResult:
    predictions = (score >= threshold).astype(int)
    truth = labels.astype(int)

    tp = int(((predictions == 1) & (truth == 1)).sum())
    fp = int(((predictions == 1) & (truth == 0)).sum())
    tn = int(((predictions == 0) & (truth == 0)).sum())
    fn = int(((predictions == 0) & (truth == 1)).sum())

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    fp_rate = fp / max(fp + tn, 1)

    return ExperimentResult(
        name=name,
        evaluation_scope=evaluation_scope,
        support=len(truth),
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        fp_rate=fp_rate,
        selected_events=int(predictions.sum()),
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )


def build_main_metrics(scored: pd.DataFrame, experiments: pd.DataFrame, tree_metrics: dict) -> dict:
    best = experiments.sort_values(["f1", "precision", "recall"], ascending=False).iloc[0]
    y_true = scored["label"].astype(int)
    y_pred = scored["candidate"].astype(int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    return {
        "event_count": int(len(scored)),
        "candidate_count": int(scored["candidate"].sum()),
        "malicious_count": int(scored["label"].sum()),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fp / max(fp + tn, 1),
        "best_experiment": {
            "name": str(best["name"]),
            "f1": float(best["f1"]),
            "precision": float(best["precision"]),
            "recall": float(best["recall"]),
            "evaluation_scope": str(best["evaluation_scope"]),
        },
        "confusion_matrix": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        },
        "decision_tree": tree_metrics,
    }
