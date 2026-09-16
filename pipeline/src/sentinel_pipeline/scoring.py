"""Threat-score fusion: config/scoring.yaml loaded once at startup.

Phase 3 only ever populates the rule_severity term of the fusion formula —
anomaly, classifier, ip_reputation and persistence are all 0 until the phase-4
models and GeoIP enrichment exist. See config/scoring.yaml's header comment for
the full formula this is a (currently one-term) subset of; the weights live in
that file, not here, so they can be tuned later without a code change.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(slots=True)
class ScoringConfig:
    rule_severity_weight: float
    alert_minimum: float
    gap_minutes: float
    max_duration_minutes: float


def load_scoring(path: str | Path) -> ScoringConfig:
    doc = yaml.safe_load(Path(path).read_text())
    return ScoringConfig(
        rule_severity_weight=float(doc["weights"]["rule_severity"]),
        alert_minimum=float(doc["thresholds"]["alert_minimum"]),
        gap_minutes=float(doc["sessioniser"]["gap_minutes"]),
        max_duration_minutes=float(doc["sessioniser"]["max_duration_minutes"]),
    )


def rule_component_score(config: ScoringConfig, max_rule_severity: float) -> float:
    """threat_score, rule term only."""
    return max(0.0, min(100.0, config.rule_severity_weight * max_rule_severity))
