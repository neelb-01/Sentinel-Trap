"""Consume events.raw and write to TimescaleDB.

Runs as a Redis Streams consumer group, so this process can crash mid-batch and
resume from its last acknowledged ID without losing events. Delivery is
at-least-once, which is why the insert is idempotent on (event_id, ts).

This is the whole reason the stream exists: a decoy writing straight to Postgres
would silently drop everything that arrived while this was down.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time

import psycopg
import redis
from psycopg.types.json import Jsonb

from .events import Event

REDIS_URL = os.environ.get("ST_REDIS_URL", "redis://redis:6379/0")
STREAM = os.environ.get("ST_STREAM", "events.raw")
GROUP = os.environ.get("ST_GROUP", "writer")
CONSUMER = os.environ.get("ST_CONSUMER", os.uname().nodename)
PG_DSN = os.environ["ST_PG_DSN"]
BATCH = int(os.environ.get("ST_BATCH", "200"))
BLOCK_MS = int(os.environ.get("ST_BLOCK_MS", "2000"))

logging.basicConfig(
    level=os.environ.get("ST_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("writer")

INSERT = """
    INSERT INTO events
        (event_id, ts, decoy, protocol, src_ip, src_port, dst_port, action, payload, raw)
    VALUES
        (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (event_id, ts) DO NOTHING
"""

_running = True


def _stop(signum, _frame):
    global _running
    log.info("signal %s — shutting down", signum)
    _running = False


def _ensure_group(client: redis.Redis) -> None:
    try:
        client.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        log.info("created consumer group '%s' on '%s'", GROUP, STREAM)
    except redis.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


def _write(conn: psycopg.Connection, events: list[Event]) -> int:
    rows = [
        (
            e.event_id, e.ts, e.decoy, e.protocol, e.src_ip,
            e.src_port, e.dst_port, e.action, Jsonb(e.payload), e.raw,
        )
        for e in events
    ]
    with conn.cursor() as cur:
        cur.executemany(INSERT, rows)
    conn.commit()
    return len(rows)


def _drain(client: redis.Redis, conn: psycopg.Connection, start_id: str) -> str | None:
    """Read one batch. `start_id` is '0' to reclaim this consumer's pending
    entries after a restart, then '>' for new ones."""
    response = client.xreadgroup(
        GROUP, CONSUMER, {STREAM: start_id}, count=BATCH, block=BLOCK_MS
    )
    if not response:
        # No pending entries left: switch to live reads.
        return None if start_id == "0" else start_id

    _, entries = response[0]
    if not entries:
        return None if start_id == "0" else start_id

    events: list[Event] = []
    for entry_id, fields in entries:
        try:
            events.append(Event.from_stream_fields(fields))
        except Exception:
            # Acknowledge poison entries rather than blocking the group forever.
            log.exception("undecodable entry %s — acking and moving on", entry_id)

    if events:
        written = _write(conn, events)
        log.debug("wrote %d/%d events", written, len(events))

    ack_ids = [entry_id for entry_id, _ in entries]
    client.xack(STREAM, GROUP, *ack_ids)
    return start_id


def main() -> int:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    client = redis.from_url(REDIS_URL, decode_responses=True)
    client.ping()
    _ensure_group(client)

    conn = psycopg.connect(PG_DSN, autocommit=False)
    log.info("consuming '%s' as %s/%s", STREAM, GROUP, CONSUMER)

    # Reclaim anything this consumer had in flight when it last died.
    cursor_id: str = "0"
    total = 0
    last_report = time.monotonic()

    while _running:
        try:
            result = _drain(client, conn, cursor_id)
            if result is None:
                log.info("pending backlog drained — switching to live reads")
                cursor_id = ">"
            total += 1
        except psycopg.OperationalError:
            log.exception("postgres connection lost — reconnecting in 3s")
            conn.close()
            time.sleep(3)
            conn = psycopg.connect(PG_DSN, autocommit=False)
        except redis.ConnectionError:
            log.exception("redis connection lost — retrying in 3s")
            time.sleep(3)

        now = time.monotonic()
        if now - last_report >= 60:
            pending = client.xpending(STREAM, GROUP)
            log.info("batches=%d pending=%s", total, pending.get("pending", 0) if pending else 0)
            last_report = now

    conn.close()
    log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
