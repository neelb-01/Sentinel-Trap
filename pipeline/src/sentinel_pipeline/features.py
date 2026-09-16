"""Session feature extraction: ~24 numeric features from a session's raw events.

Pure and I/O-free — the sessioniser recomputes this from its own in-memory event
list on every new event, never from Postgres. The character n-gram TF-IDF over the
command sequence that CLAUDE.md also calls for is for the phase-4 classifier, not
here; raw command sequences stay queryable later via
`events WHERE session_id = … AND action = 'command' ORDER BY ts`.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter
from itertools import pairwise

from .events import Event

_CREDENTIAL_ACTIONS = {"login_attempt", "login_success"}
_FILE_ACTIONS = {"file_download", "file_upload"}

# Mirrors the intent (not the exact string) of config/rules/002-malware-dropper.yaml,
# 003-path-traversal.yaml and 004-sqli-probe.yaml — those match a single event's
# payload; these count occurrences across the whole session as a numeric feature.
_FETCH_RE = re.compile(r"(wget|curl|tftp)\s+\S+")
_CHMOD_RE = re.compile(r"chmod\s+(\+x|[0-7]{3,4})")
_SQLI_RE = re.compile(
    r"(?i)('\s*or\s*'?1'?\s*=\s*'?1|union\s+all?\s*select|sleep\(\d+\)|benchmark\()"
)
_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e[/%5c])")


def compute_features(events: list[Event]) -> dict[str, float]:
    """`events` need not be sorted; must be non-empty."""
    if not events:
        return {}

    events = sorted(events, key=lambda e: e.ts)
    started_at = events[0].ts
    ended_at = events[-1].ts
    duration = max((ended_at - started_at).total_seconds(), 0.0)
    duration_minutes = max(duration, 60.0) / 60.0

    intervals = [(b.ts - a.ts).total_seconds() for a, b in pairwise(events)]

    actions = Counter(e.action for e in events)
    credential_events = [e for e in events if e.action in _CREDENTIAL_ACTIONS]
    command_events = [e for e in events if e.action == "command"]
    file_events = [e for e in events if e.action in _FILE_ACTIONS]

    usernames = {e.payload.get("username") or e.payload.get("user") for e in credential_events}
    usernames.discard(None)
    passwords = {e.payload.get("password") or e.payload.get("pass") for e in credential_events}
    passwords.discard(None)

    commands = [e.payload.get("input", "") for e in command_events]
    download_exec = sum(1 for c in commands if _FETCH_RE.search(c) and _CHMOD_RE.search(c))

    sqli_hits = sum(
        1
        for e in events
        for v in (e.payload.get("q"), e.payload.get("user"))
        if isinstance(v, str) and _SQLI_RE.search(v)
    )
    traversal_hits = sum(
        1
        for e in events
        for v in (e.payload.get("path"), e.payload.get("query"), e.payload.get("q"))
        if isinstance(v, str) and _TRAVERSAL_RE.search(v)
    )

    paths = {e.payload.get("path") for e in events if e.payload.get("path")}
    user_agents = {e.payload.get("ua") for e in events if e.payload.get("ua")}

    return {
        # volume
        "event_count": float(len(events)),
        "duration_seconds": duration,
        "distinct_actions": float(len(actions)),
        "events_per_minute": len(events) / duration_minutes,
        # timing
        "mean_interval_seconds": statistics.fmean(intervals) if intervals else 0.0,
        "max_interval_seconds": max(intervals) if intervals else 0.0,
        "stdev_interval_seconds": statistics.pstdev(intervals) if len(intervals) > 1 else 0.0,
        # credentials
        "credential_attempts": float(len(credential_events)),
        "distinct_usernames": float(len(usernames)),
        "distinct_passwords": float(len(passwords)),
        "login_success_count": float(actions.get("login_success", 0)),
        # commands (mostly Cowrie)
        "command_count": float(len(command_events)),
        "distinct_commands": float(len(set(commands))),
        "download_exec_attempts": float(download_exec),
        "file_transfer_count": float(len(file_events)),
        # web payload probing (mostly sentinel-web)
        "path_probe_count": float(actions.get("path_probe", 0)),
        "sensitive_file_probe_count": float(actions.get("sensitive_file_probe", 0)),
        "sqli_indicator_count": float(sqli_hits),
        "traversal_indicator_count": float(traversal_hits),
        "distinct_paths_requested": float(len(paths)),
        # identity
        "distinct_user_agents": float(len(user_agents)),
        "distinct_protocols": float(len({e.protocol for e in events})),
        "distinct_dst_ports": float(len({e.dst_port for e in events if e.dst_port is not None})),
        "distinct_src_ports": float(len({e.src_port for e in events if e.src_port is not None})),
    }
