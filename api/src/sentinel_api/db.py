"""Async Postgres access for the REST API.

Read-only from here — every write happens upstream in the writer. One
connection pool is opened at startup (see main.lifespan) and shared across
requests; it is created with open=False because building it at import time,
before the event loop exists, triggers psycopg_pool's "opened outside an
event loop" warning.
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
