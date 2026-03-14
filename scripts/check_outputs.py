from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd


ROOT = Path(__file__).resolve().parent.parent
EXPECTED = [
    ROOT / "data" / "demo_logs.csv",
    ROOT / "outputs" / "events_scored.csv",
    ROOT / "outputs" / "experiments.csv",
    ROOT / "outputs" / "metrics.json",
    ROOT / "outputs" / "tree_metrics.json",
    ROOT / "outputs" / "tree_rules.txt",
    ROOT / "outputs" / "report.md",
    ROOT / "outputs" / "dashboard.html",
    ROOT / "outputs" / "charts" / "01_source_overview.png",
    ROOT / "outputs" / "charts" / "08_experiment_comparison.png",
    ROOT / "outputs" / "charts" / "09_funnel.png",
    ROOT / "outputs" / "charts" / "10_tree_feature_importance.png",
    ROOT / "outputs" / "charts" / "11_tree_structure.png",
    ROOT / "outputs" / "charts" / "12_tree_score_distribution.png",
]


def main() -> int:
    missing = [str(path) for path in EXPECTED if not path.exists()]
    if missing:
        print("missing_files")
        for item in missing:
            print(item)
        return 1

    metrics = json.loads((ROOT / "outputs" / "metrics.json").read_text(encoding="utf-8"))
    experiments = pd.read_csv(ROOT / "outputs" / "experiments.csv")
    scored = pd.read_csv(ROOT / "outputs" / "events_scored.csv")

    metric_keys = ["precision", "recall", "f1", "false_positive_rate"]
    invalid_metrics = [key for key in metric_keys if not 0.0 <= float(metrics[key]) <= 1.0]
    if invalid_metrics:
        print("invalid_metrics", invalid_metrics)
        return 1

    if scored.empty or experiments.empty:
        print("empty_outputs")
        return 1

    print(
        "outputs_ok "
        f"events={len(scored)} "
        f"candidates={int(scored['candidate'].sum())} "
        f"best={experiments.sort_values('f1', ascending=False).iloc[0]['name']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
