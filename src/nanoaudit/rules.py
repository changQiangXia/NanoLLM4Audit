from __future__ import annotations

from dataclasses import dataclass
import re

import pandas as pd

from nanoaudit.config import RuleConfig


@dataclass(slots=True)
class CompiledRule:
    id: str
    pattern: re.Pattern[str]
    score: float
    description: str


def compile_rules(rules: list[RuleConfig]) -> list[CompiledRule]:
    return [
        CompiledRule(
            id=rule.id,
            pattern=re.compile(rule.pattern, flags=re.IGNORECASE),
            score=rule.score,
            description=rule.description,
        )
        for rule in rules
    ]


def apply_rule_scores(events: pd.DataFrame, rules: list[CompiledRule]) -> pd.DataFrame:
    scored = events.copy()
    scored["rule_score"] = 0.0
    scored["rule_id"] = ""
    scored["rule_description"] = ""

    text = scored["message"].fillna("").astype(str)
    for rule in rules:
        matched = text.str.contains(rule.pattern, na=False)
        better = matched & (rule.score > scored["rule_score"])
        scored.loc[matched, "rule_score"] = scored.loc[matched, "rule_score"].clip(lower=rule.score)
        scored.loc[better, "rule_id"] = rule.id
        scored.loc[better, "rule_description"] = rule.description
    return scored
