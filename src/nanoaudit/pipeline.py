from __future__ import annotations

import json

from nanoaudit.config import ProjectConfig
from nanoaudit.data import ensure_demo_dataset
from nanoaudit.experiments import build_main_metrics, run_experiments
from nanoaudit.ml import run_decision_tree, write_tree_outputs
from nanoaudit.report import write_dashboard, write_metrics, write_report
from nanoaudit.scoring import score_events
from nanoaudit.visuals import generate_all_charts


class NanoAuditPipeline:
    def __init__(self, config: ProjectConfig):
        self.config = config
        self.config.paths.outputs_dir.mkdir(parents=True, exist_ok=True)
        self.config.paths.charts_dir.mkdir(parents=True, exist_ok=True)

    def run(self, *, rebuild_data: bool = False) -> dict:
        dataset = ensure_demo_dataset(self.config, force=rebuild_data)
        scored = score_events(dataset, self.config)
        tree_result = run_decision_tree(scored, self.config)
        scored = tree_result.scored
        experiments = run_experiments(tree_result.holdout_frame, tree_result.metrics)
        metrics = build_main_metrics(scored, experiments, tree_result.metrics)

        scored.to_csv(self.config.paths.scored_file, index=False, encoding="utf-8")
        experiments.to_csv(self.config.paths.experiments_file, index=False, encoding="utf-8")
        write_metrics(metrics, self.config.paths.metrics_file)
        write_tree_outputs(tree_result, self.config.paths.tree_metrics_file, self.config.paths.tree_rules_file)
        generate_all_charts(scored, experiments, tree_result, self.config.paths.charts_dir)
        write_report(scored, experiments, metrics, self.config.paths.report_file)
        write_dashboard(experiments, metrics, self.config.paths.dashboard_file)
        return {
            "scored": scored,
            "experiments": experiments,
            "metrics": metrics,
        }

    def summary(self) -> dict:
        if not self.config.paths.metrics_file.exists():
            return {"status": "empty"}
        return json.loads(self.config.paths.metrics_file.read_text(encoding="utf-8"))
