"""Async Postgres access for the REST API.

Mostly read-only — every event/session/rule write still happens upstream in
the writer or sessioniser. The one exception is triage: `update_alert_status`
and `upsert_human_label` are the API's own writes, because a human clicking
"confirm" in the dashboard has nowhere else to happen. One connection pool is
opened at startup (see main.lifespan) and shared across requests; it is
created with open=False because building it at import time, before the event
loop exists, triggers psycopg_pool's "opened outside an event loop" warning.
"""

from __future__ import annotations

import os

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

PG_DSN = os.environ["ST_PG_DSN"]
POOL_MIN_SIZE = int(os.environ.get("ST_PG_POOL_MIN", "1"))
POOL_MAX_SIZE = int(os.environ.get("ST_PG_POOL_MAX", "10"))

pool = AsyncConnectionPool(PG_DSN, min_size=POOL_MIN_SIZE, max_size=POOL_MAX_SIZE, open=False)

# Keyset pagination on (ts, event_id) rather than OFFSET: the events table is
# append-only and growing at ~50/sec, so an OFFSET page would drift under the
# feed. src_ip uses host() rather than ::text — casting an inet to text keeps
# its netmask (e.g. "172.30.0.1/32"), which host() strips. session_id is cast
# to text so the API never has to decode psycopg's UUID row type itself.
EVENTS_PAGE = """
    SELECT event_id, ts, decoy, protocol, host(src_ip) AS src_ip, src_port,
           dst_port, action, payload, session_id::text AS session_id
    FROM events
    WHERE (%(before_ts)s::timestamptz IS NULL
           OR (ts, event_id) < (%(before_ts)s::timestamptz, %(before_id)s))
      AND (%(decoy)s::text IS NULL OR decoy = %(decoy)s)
      AND (%(src_ip)s::text IS NULL OR src_ip = %(src_ip)s::inet)
    ORDER BY ts DESC, event_id DESC
    LIMIT %(limit)s
"""


async def fetch_events(
    *,
    limit: int,
    before_ts=None,
    before_id: str | None = None,
    decoy: str | None = None,
    src_ip: str | None = None,
) -> list[dict]:
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            EVENTS_PAGE,
            {
                "before_ts": before_ts,
                "before_id": before_id,
                "decoy": decoy,
                "src_ip": src_ip,
                "limit": limit,
            },
        )
        return await cur.fetchall()


# ---------------------------------------------------------------------- alerts

# Joined to the session for src_ip/decoy/timing — the triage queue needs that
# context inline rather than a second round trip per row.
ALERTS_PAGE = """
    SELECT a.alert_id::text AS alert_id, a.session_id::text AS session_id, a.created_at,
           a.threat_score, a.predicted_class, a.confidence, a.anomaly_score,
           a.triggered_rules, a.reason, a.status,
           host(s.src_ip) AS src_ip, s.decoy, s.started_at, s.ended_at, s.event_count
    FROM alerts a
    JOIN sessions s ON s.session_id = a.session_id
    WHERE (%(before_ts)s::timestamptz IS NULL
           OR (a.created_at, a.alert_id) < (%(before_ts)s::timestamptz, %(before_id)s::uuid))
      AND (%(status)s::text IS NULL OR a.status = %(status)s::alert_status)
    ORDER BY a.created_at DESC, a.alert_id DESC
    LIMIT %(limit)s
"""


async def fetch_alerts(
    *,
    limit: int,
    before_ts=None,
    before_id: str | None = None,
    status: str | None = None,
) -> list[dict]:
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            ALERTS_PAGE,
            {"before_ts": before_ts, "before_id": before_id, "status": status, "limit": limit},
        )
        return await cur.fetchall()


async def update_alert_status(alert_id: str, status: str) -> dict | None:
    """None means no such alert_id — the route turns that into a 404."""
    async with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """
            UPDATE alerts SET status = %s::alert_status WHERE alert_id = %s::uuid
            RETURNING alert_id::text AS alert_id, session_id::text AS session_id,
                      status, triggered_rules
            """,
            (status, alert_id),
        )
        return await cur.fetchone()


async def fetch_rule_severities(rule_ids: list[str]) -> dict[str, float]:
    """Looks up severity from the `rules` table (kept in sync by the
    sessioniser from config/rules/*.yaml) rather than duplicating the YAML's
    numbers here."""
    if not rule_ids:
        return {}
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT rule_id, severity FROM rules WHERE rule_id = ANY(%s)", (rule_ids,)
        )
        return {rule_id: severity for rule_id, severity in await cur.fetchall()}


async def upsert_human_label(session_id: str, label: str) -> None:
    """labels' primary key is (session_id, source): a session gets at most one
    human label, and confirming twice just updates it."""
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            """
            INSERT INTO labels (session_id, label, source, labelled_by)
            VALUES (%s::uuid, %s, 'human', %s)
            ON CONFLICT (session_id, source) DO UPDATE SET
                label = EXCLUDED.label, labelled_by = EXCLUDED.labelled_by, labelled_at = now()
            """,
            (session_id, label, "dashboard"),
        )
