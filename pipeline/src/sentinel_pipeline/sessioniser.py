"""Consume events.raw, group into sessions, extract features, run the rule
engine, and raise alerts.

Runs as its own Redis Streams consumer group (independent of `writer`'s — no
coordination between them, same "either can crash without the other losing
anything" property). Session state lives in memory, keyed by (src_ip, decoy):
this process already has every event's full contents off the stream itself, so
there's no need to re-query Postgres for a session's own events just to compute
its features.

Crash-safety note: in-memory `open_sessions` does not survive a restart, so a
session that was open at crash time fragments into two rows across the
restart — a known, acceptable limitation, not solved here. Within a run,
`SessionState.seen_event_ids` guards against Redis's at-least-once redelivery
double-counting an event that was already applied before a crash-before-XACK.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import psycopg
import redis
from psycopg.types.json import Jsonb

from .events import Event
from .features import compute_features
from .rules import Rule, evaluate, load_rules, pattern_summary
from .scoring import ScoringConfig, load_scoring, rule_component_score

REDIS_URL = os.environ.get("ST_REDIS_URL", "redis://redis:6379/0")
STREAM = os.environ.get("ST_STREAM", "events.raw")
GROUP = os.environ.get("ST_GROUP", "sessioniser")
CONSUMER = os.environ.get("ST_CONSUMER", os.uname().nodename)
PG_DSN = os.environ["ST_PG_DSN"]
BATCH = int(os.environ.get("ST_BATCH", "200"))
BLOCK_MS = int(os.environ.get("ST_BLOCK_MS", "2000"))
RULES_DIR = os.environ.get("ST_RULES_DIR", "/app/config/rules")
SCORING_CONFIG = os.environ.get("ST_SCORING_CONFIG", "/app/config/scoring.yaml")
SWEEP_INTERVAL_S = int(os.environ.get("ST_SWEEP_INTERVAL_S", "30"))

logging.basicConfig(
    level=os.environ.get("ST_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("sessioniser")

_running = True


def _stop(signum, _frame):
    global _running
    log.info("signal %s — shutting down", signum)
    _running = False


@dataclass(slots=True)
class SessionState:
    session_id: str
    src_ip: str
    decoy: str
    started_at: datetime
    last_ts: datetime
    events: list[Event] = field(default_factory=list)
    triggered_rules: set[str] = field(default_factory=set)
    seen_event_ids: set[str] = field(default_factory=set)


OpenSessions = dict[tuple[str, str], SessionState]


def _ensure_group(client: redis.Redis) -> None:
    try:
        client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        log.info("created consumer group '%s' on '%s'", GROUP, STREAM)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


# ------------------------------------------------------------------------- db


def _sync_rules_table(conn: psycopg.Connection, rules: list[Rule]) -> None:
    with conn.cursor() as cur:
        for r in rules:
            cur.execute(
                """
                INSERT INTO rules (rule_id, name, severity, pattern, enabled)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (rule_id) DO UPDATE SET
                    name = EXCLUDED.name, severity = EXCLUDED.severity,
                    pattern = EXCLUDED.pattern, enabled = EXCLUDED.enabled
                """,
                (r.id, r.name, r.severity, pattern_summary(r), r.enabled),
            )


def _open_session(conn: psycopg.Connection, src_ip: str, decoy: str, started_at: datetime) -> str:
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO sessions (src_ip, decoy, started_at, ended_at, event_count)
               VALUES (%s, %s, %s, %s, 0) RETURNING session_id""",
            (src_ip, decoy, started_at, started_at),
        )
        return str(cur.fetchone()[0])


def _update_session(
    conn: psycopg.Connection, session_id: str, ended_at: datetime, event_count: int, features: dict
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE sessions SET ended_at = %s, event_count = %s, features = %s WHERE session_id = %s",
            (ended_at, event_count, Jsonb(features), session_id),
        )


def _close_session(conn: psycopg.Connection, session_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE sessions SET closed = TRUE WHERE session_id = %s", (session_id,))


def _link_event_to_session(conn: psycopg.Connection, event: Event, session_id: str) -> bool:
    """The writer is an independent consumer group and may not have inserted
    this row yet. A short retry covers the common race; a rare miss just means
    that one event has no session_id — non-fatal."""
    for attempt in range(3):
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE events SET session_id = %s WHERE event_id = %s AND ts = %s",
                (session_id, event.event_id, event.ts),
            )
            if cur.rowcount > 0:
                return True
        if attempt < 2:
            time.sleep(0.2)
    log.warning("event %s never appeared in events — session_id not linked", event.event_id)
    return False


def _increment_rule_hit(conn: psycopg.Connection, rule_id: str) -> None:
    with conn.cursor() as cur:
        cur.execute("UPDATE rules SET hit_count = hit_count + 1 WHERE rule_id = %s", (rule_id,))


def _upsert_alert(
    conn: psycopg.Connection,
    session_id: str,
    threat_score: float,
    triggered_rules: list[str],
    reason: str,
) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT alert_id FROM alerts WHERE session_id = %s", (session_id,))
        row = cur.fetchone()
        if row is None:
            cur.execute(
                """INSERT INTO alerts (session_id, threat_score, triggered_rules, reason)
                   VALUES (%s, %s, %s, %s)""",
                (session_id, threat_score, triggered_rules, reason),
            )
        else:
            cur.execute(
                "UPDATE alerts SET threat_score = %s, triggered_rules = %s, reason = %s WHERE alert_id = %s",
                (threat_score, triggered_rules, reason, row[0]),
            )


# -------------------------------------------------------------------- engine


def _process_event(
    conn: psycopg.Connection,
    event: Event,
    open_sessions: OpenSessions,
    rules: list[Rule],
    scoring: ScoringConfig,
) -> None:
    key = (event.src_ip, event.decoy)
    state = open_sessions.get(key)

    gap = timedelta(minutes=scoring.gap_minutes)
    max_duration = timedelta(minutes=scoring.max_duration_minutes)
    if state is not None and (
        event.ts - state.last_ts > gap or event.ts - state.started_at > max_duration
    ):
        _close_session(conn, state.session_id)
        del open_sessions[key]
        state = None

    if state is None:
        session_id = _open_session(conn, event.src_ip, event.decoy, event.ts)
        state = SessionState(
            session_id=session_id,
            src_ip=event.src_ip,
            decoy=event.decoy,
            started_at=event.ts,
            last_ts=event.ts,
        )
        open_sessions[key] = state

    if event.event_id in state.seen_event_ids:
        return  # redelivered after a crash between the last DB write and XACK
    state.seen_event_ids.add(event.event_id)

    state.events.append(event)
    state.last_ts = max(state.last_ts, event.ts)

    features = compute_features(state.events)
    _update_session(conn, state.session_id, state.last_ts, len(state.events), features)
    _link_event_to_session(conn, event, state.session_id)

    matched = evaluate(rules, features, event.payload)
    new_matches = [r for r in matched if r.id not in state.triggered_rules]
    for r in new_matches:
        state.triggered_rules.add(r.id)
        _increment_rule_hit(conn, r.id)

    if new_matches:
        triggered = [r for r in rules if r.id in state.triggered_rules]
        max_severity = max((r.severity for r in triggered), default=0.0)
        threat_score = rule_component_score(scoring, max_severity)
        if threat_score >= scoring.alert_minimum:
            reason = "Matched: " + ", ".join(f"{r.name} ({r.severity:.2f})" for r in triggered)
            _upsert_alert(
                conn, state.session_id, threat_score, sorted(state.triggered_rules), reason
            )


def _sweep_idle(
    conn: psycopg.Connection, open_sessions: OpenSessions, scoring: ScoringConfig
) -> None:
    """Close sessions no new event will ever extend — nothing else marks a
    session closed when its source simply goes quiet."""
    gap = timedelta(minutes=scoring.gap_minutes)
    now = datetime.now(UTC)
    idle = [k for k, s in open_sessions.items() if now - s.last_ts > gap]
    for k in idle:
        _close_session(conn, open_sessions[k].session_id)
        del open_sessions[k]
    if idle:
        log.debug("swept %d idle session(s)", len(idle))


def _drain(
    client: redis.Redis,
    conn: psycopg.Connection,
    start_id: str,
    open_sessions: OpenSessions,
    rules: list[Rule],
    scoring: ScoringConfig,
) -> str | None:
    response = client.xreadgroup(GROUP, CONSUMER, {STREAM: start_id}, count=BATCH, block=BLOCK_MS)
    if not response:
        return None if start_id == "0" else start_id

    _, entries = response[0]
    if not entries:
        return None if start_id == "0" else start_id

    for entry_id, fields in entries:
        try:
            event = Event.from_stream_fields(fields)
            _process_event(conn, event, open_sessions, rules, scoring)
        except Exception:
            log.exception("failed processing entry %s — acking and moving on", entry_id)

    ack_ids = [entry_id for entry_id, _ in entries]
    client.xack(STREAM, GROUP, *ack_ids)
    return start_id


def main() -> int:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    client = redis.from_url(REDIS_URL, decode_responses=True)
    client.ping()
    _ensure_group(client)

    conn = psycopg.connect(PG_DSN, autocommit=True)
    log.info("consuming '%s' as %s/%s", STREAM, GROUP, CONSUMER)

    rules = load_rules(RULES_DIR)
    scoring = load_scoring(SCORING_CONFIG)
    _sync_rules_table(conn, rules)

    open_sessions: OpenSessions = {}
    cursor_id = "0"
    total = 0
    last_sweep = time.monotonic()
    last_report = time.monotonic()

    while _running:
        try:
            result = _drain(client, conn, cursor_id, open_sessions, rules, scoring)
            if result is None:
                log.info("pending backlog drained — switching to live reads")
                cursor_id = ">"
            total += 1
        except psycopg.OperationalError:
            log.exception("postgres connection lost — reconnecting in 3s")
            conn.close()
            time.sleep(3)
            conn = psycopg.connect(PG_DSN, autocommit=True)
        except redis.ConnectionError:
            log.exception("redis connection lost — retrying in 3s")
            time.sleep(3)

        now = time.monotonic()
        if now - last_sweep >= SWEEP_INTERVAL_S:
            try:
                _sweep_idle(conn, open_sessions, scoring)
            except psycopg.OperationalError:
                log.exception("sweep failed — postgres connection lost")
            last_sweep = now
        if now - last_report >= 60:
            log.info("batches=%d open_sessions=%d", total, len(open_sessions))
            last_report = now

    conn.close()
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
