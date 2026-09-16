"""The YAML rule engine.

Loads config/rules/*.yaml at startup and evaluates match.all / match.any clauses
against a session's current features and one event's payload. The two field
namespaces (features.*, payload.*) and the op set (gte, regex) are fixed by the
YAML files themselves — see CLAUDE.md's "Extending the pipeline" section; this
engine has to honour that shape, not invent a new one.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("rules")


@dataclass(slots=True)
class Clause:
    field: str
    op: str
    value: Any


@dataclass(slots=True)
class Rule:
    id: str
    name: str
    severity: float
    enabled: bool
    match_all: list[Clause]
    match_any: list[Clause]
    raw_match: dict[str, Any]


def _parse_clause(d: dict[str, Any]) -> Clause:
    return Clause(field=d["field"], op=d["op"], value=d["value"])


def load_rules(rules_dir: str | Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError:
            log.exception("could not parse rule file %s — skipping", path)
            continue
        match = doc.get("match", {})
        rules.append(
            Rule(
                id=doc["id"],
                name=doc["name"],
                severity=float(doc["severity"]),
                enabled=bool(doc.get("enabled", True)),
                match_all=[_parse_clause(c) for c in match.get("all", [])],
                match_any=[_parse_clause(c) for c in match.get("any", [])],
                raw_match=match,
            )
        )
    log.info("loaded %d rule(s) from %s", len(rules), rules_dir)
    return rules


def _resolve(field: str, features: dict[str, float], payload: dict[str, Any]) -> Any:
    namespace, _, key = field.partition(".")
    if namespace == "features":
        return features.get(key)
    if namespace == "payload":
        return payload.get(key)
    return None


def _clause_matches(clause: Clause, features: dict[str, float], payload: dict[str, Any]) -> bool:
    value = _resolve(clause.field, features, payload)
    if value is None:
        return False
    if clause.op == "gte":
        try:
            return float(value) >= float(clause.value)
        except (TypeError, ValueError):
            return False
    if clause.op == "regex":
        if not isinstance(value, str):
            return False
        return re.search(clause.value, value) is not None
    log.warning("unknown op %r in rule clause — treating as no-match", clause.op)
    return False


def evaluate(rules: list[Rule], features: dict[str, float], payload: dict[str, Any]) -> list[Rule]:
    """Rules matched by this single (features, payload) pair. `payload` is one
    event's payload — payload.* clauses only ever see one event at a time, never
    a session-wide aggregate; that's what features.* is for."""
    matched = []
    for rule in rules:
        if not rule.enabled:
            continue
        if not rule.match_all and not rule.match_any:
            continue  # a rule with no clauses matches nothing, not everything
        if rule.match_all and not all(
            _clause_matches(c, features, payload) for c in rule.match_all
        ):
            continue
        if rule.match_any and not any(
            _clause_matches(c, features, payload) for c in rule.match_any
        ):
            continue
        matched.append(rule)
    return matched


def pattern_summary(rule: Rule) -> str:
    """A compact, human-readable stand-in for the `rules.pattern` column — the
    YAML stays canonical; this just lets the dashboard show *something* without
    re-parsing it."""
    return json.dumps(rule.raw_match, separators=(",", ":"))
