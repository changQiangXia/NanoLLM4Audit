from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(slots=True)
class PathsConfig:
    data_file: Path
    outputs_dir: Path
    charts_dir: Path
    scored_file: Path
    metrics_file: Path
    experiments_file: Path
    report_file: Path
    dashboard_file: Path
    tree_metrics_file: Path
    tree_rules_file: Path


@dataclass(slots=True)
class DatasetConfig:
    benign_events: int
    malicious_events: int


@dataclass(slots=True)
class ThresholdConfig:
    candidate: float
    behavior_high: float


@dataclass(slots=True)
class WeightConfig:
    rule: float
    behavior: float


@dataclass(slots=True)
class BehaviorConfig:
    sensitive_accounts: list[str]
    suspicious_event_types: list[str]


@dataclass(slots=True)
class DecisionTreeConfig:
    test_size: float
    max_depth: int
    min_samples_leaf: int
    threshold: float
    class_weight_balanced: bool


@dataclass(slots=True)
class RuleConfig:
    id: str
    pattern: str
    score: float
    description: str


@dataclass(slots=True)
class ExperimentConfig:
    names: list[str]


@dataclass(slots=True)
class ProjectConfig:
    project_name: str
    random_seed: int
    paths: PathsConfig
    dataset: DatasetConfig
    thresholds: ThresholdConfig
    weights: WeightConfig
    behavior: BehaviorConfig
    decision_tree: DecisionTreeConfig
    rules: list[RuleConfig]
    experiments: ExperimentConfig
    project_root: Path


def load_config(path: str | Path) -> ProjectConfig:
    config_path = Path(path).resolve()
    project_root = config_path.parent.parent
    raw = tomllib.loads(config_path.read_text(encoding="utf-8"))

    def resolve(relative_path: str) -> Path:
        return (project_root / relative_path).resolve()

    paths = raw["paths"]
    return ProjectConfig(
        project_name=raw["project_name"],
        random_seed=int(raw["random_seed"]),
        paths=PathsConfig(
            data_file=resolve(paths["data_file"]),
            outputs_dir=resolve(paths["outputs_dir"]),
            charts_dir=resolve(paths["charts_dir"]),
            scored_file=resolve(paths["scored_file"]),
            metrics_file=resolve(paths["metrics_file"]),
            experiments_file=resolve(paths["experiments_file"]),
            report_file=resolve(paths["report_file"]),
            dashboard_file=resolve(paths["dashboard_file"]),
            tree_metrics_file=resolve(paths["tree_metrics_file"]),
            tree_rules_file=resolve(paths["tree_rules_file"]),
        ),
        dataset=DatasetConfig(
            benign_events=int(raw["dataset"]["benign_events"]),
            malicious_events=int(raw["dataset"]["malicious_events"]),
        ),
        thresholds=ThresholdConfig(
            candidate=float(raw["thresholds"]["candidate"]),
            behavior_high=float(raw["thresholds"]["behavior_high"]),
        ),
        weights=WeightConfig(
            rule=float(raw["weights"]["rule"]),
            behavior=float(raw["weights"]["behavior"]),
        ),
        behavior=BehaviorConfig(
            sensitive_accounts=list(raw["behavior"]["sensitive_accounts"]),
            suspicious_event_types=list(raw["behavior"]["suspicious_event_types"]),
        ),
        decision_tree=DecisionTreeConfig(
            test_size=float(raw["decision_tree"]["test_size"]),
            max_depth=int(raw["decision_tree"]["max_depth"]),
            min_samples_leaf=int(raw["decision_tree"]["min_samples_leaf"]),
            threshold=float(raw["decision_tree"]["threshold"]),
            class_weight_balanced=bool(raw["decision_tree"]["class_weight_balanced"]),
        ),
        rules=[
            RuleConfig(
                id=item["id"],
                pattern=item["pattern"],
                score=float(item["score"]),
                description=item["description"],
            )
            for item in raw["rules"]
        ],
        experiments=ExperimentConfig(names=list(raw["experiments"]["names"])),
        project_root=project_root,
    )
