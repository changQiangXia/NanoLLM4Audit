from __future__ import annotations

import json

import numpy as np
import pandas as pd

from nanoaudit.config import ProjectConfig
from nanoaudit.rules import apply_rule_scores, compile_rules


def score_events(events: pd.DataFrame, config: ProjectConfig) -> pd.DataFrame:
    scored = apply_rule_scores(events, compile_rules(config.rules))
    scored["timestamp"] = pd.to_datetime(scored["timestamp"])
    scored["hour"] = scored["timestamp"].dt.hour
    scored["event_date"] = scored["timestamp"].dt.strftime("%Y-%m-%d")
    scored["rarity_score"] = compute_rarity_score(scored)
    scored["off_hours_score"] = scored["hour"].apply(score_off_hours)
    scored["failure_burst_score"] = compute_failure_burst_score(scored)
    scored["host_spread_score"] = compute_host_spread_score(scored)
    scored["privileged_account_score"] = compute_privileged_account_score(scored, config)
    scored["behavior_score"] = np.clip(
        0.30 * scored["rarity_score"]
        + 0.20 * scored["off_hours_score"]
        + 0.25 * scored["failure_burst_score"]
        + 0.15 * scored["host_spread_score"]
        + 0.10 * scored["privileged_account_score"],
        0.0,
        1.0,
    )
    scored["risk_score"] = np.clip(
        config.weights.rule * scored["rule_score"] + config.weights.behavior * scored["behavior_score"],
        0.0,
        1.0,
    )
    scored["candidate"] = scored["risk_score"] >= config.thresholds.candidate
    scored["behavior_high"] = scored["behavior_score"] >= config.thresholds.behavior_high
    scored["severity"] = scored["risk_score"].apply(severity_from_score)
    scored["behavior_reasons"] = scored.apply(build_behavior_reason, axis=1)
    scored["audit_summary"] = scored.apply(build_audit_summary, axis=1)
    scored["evidence_json"] = scored.apply(build_evidence_json, axis=1)
    return scored.drop(columns=["event_date"])


def compute_rarity_score(events: pd.DataFrame) -> pd.Series:
    event_type_freq = events["event_type"].value_counts(normalize=True)
    return (1.0 - events["event_type"].map(event_type_freq).fillna(0.0)).clip(0.0, 1.0)


def score_off_hours(hour: int) -> float:
    if hour <= 5 or hour >= 23:
        return 1.0
    if 6 <= hour <= 7 or 20 <= hour <= 22:
        return 0.6
    return 0.1


def compute_failure_burst_score(events: pd.DataFrame) -> pd.Series:
    merged = events.copy()
    merged["event_date"] = merged["timestamp"].dt.strftime("%Y-%m-%d")
    key_counts = (
        merged.loc[merged["status"] == "failure"]
        .groupby(["user", "event_date"])
        .size()
        .rename("failures_per_day")
        .reset_index()
    )
    merged = merged.merge(key_counts, on=["user", "event_date"], how="left")
    return merged["failures_per_day"].fillna(0.0).div(8.0).clip(0.0, 1.0)


def compute_host_spread_score(events: pd.DataFrame) -> pd.Series:
    host_spread = events.groupby("user")["host"].transform("nunique")
    return ((host_spread - 1).clip(lower=0) / 4.0).clip(0.0, 1.0)


def compute_privileged_account_score(events: pd.DataFrame, config: ProjectConfig) -> pd.Series:
    privileged = events["user"].isin(config.behavior.sensitive_accounts)
    suspicious_event = events["event_type"].isin(config.behavior.suspicious_event_types)
    return pd.Series(np.where(privileged & suspicious_event, 0.8, 0.0), index=events.index)


def severity_from_score(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    if score >= 0.45:
        return "low"
    return "info"


def build_behavior_reason(row: pd.Series) -> str:
    reasons: list[str] = []
    if row["rarity_score"] >= 0.7:
        reasons.append("事件类型出现频率偏低")
    if row["off_hours_score"] >= 0.6:
        reasons.append("时间位于夜间窗口")
    if row["failure_burst_score"] >= 0.6:
        reasons.append("失败事件在单日内集中出现")
    if row["host_spread_score"] >= 0.6:
        reasons.append("同一账号涉及多台主机")
    if row["privileged_account_score"] >= 0.7:
        reasons.append("敏感账号触发高风险动作")
    return "；".join(reasons) if reasons else "行为侧特征稳定"


def build_audit_summary(row: pd.Series) -> str:
    rule_part = row["rule_description"] if row["rule_id"] else "规则未命中高置信特征"
    return (
        f"阶段={row['attack_stage']} | 风险={row['severity']} | "
        f"规则={row['rule_id'] or 'NONE'} | {rule_part} | {row['behavior_reasons']}"
    )


def build_evidence_json(row: pd.Series) -> str:
    payload = {
        "rule_id": row["rule_id"] or None,
        "rule_score": round(float(row["rule_score"]), 4),
        "behavior_score": round(float(row["behavior_score"]), 4),
        "risk_score": round(float(row["risk_score"]), 4),
        "severity": row["severity"],
    }
    return json.dumps(payload, ensure_ascii=False)
