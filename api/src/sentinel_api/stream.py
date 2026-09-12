"""Fan out new events from Redis to every connected /ws/live client.

This is a live tail, not a durable consumer: unlike the writer, it reads with
plain XREAD rather than a consumer group, starting at '$' (only events emitted
from now on). Missing a gap across a restart just means the live feed skips a
few rows the dashboard can always re-fetch over REST — nothing here needs
replaying, so the extra bookkeeping a consumer group buys isn't worth it.

Frames are batched every ST_WS_BATCH_MS so `attack-sim/` running at full speed
pushes one WebSocket message per interval instead of one per event, which is
what freezes the browser.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

import redis.asyncio as redis

REDIS_URL = os.environ.get("ST_REDIS_URL", "redis://redis:6379/0")
STREAM = os.environ.get("ST_STREAM", "events.raw")
BATCH_MS = int(os.environ.get("ST_WS_BATCH_MS", "250"))
QUEUE_MAX = int(os.environ.get("ST_WS_QUEUE_MAX", "2000"))

log = logging.getLogger("api.stream")


def _decode(fields: dict[str, str]) -> dict:
    """Redis stream fields -> a JSON-ready dict. Mirrors
    sentinel_pipeline.events.Event.from_stream_fields, kept as a small local
    copy rather than a cross-package dependency since all the API needs is a
    plain dict to hand to the browser, not the full Event dataclass."""
    return {
        "event_id": fields.get("event_id"),
        "ts": fields.get("ts"),
        "decoy": fields.get("decoy"),
        "protocol": fields.get("protocol"),
        "src_ip": fields.get("src_ip"),
        "src_port": int(fields["src_port"]) if fields.get("src_port") else None,
        "dst_port": int(fields["dst_port"]) if fields.get("dst_port") else None,
        "action": fields.get("action"),
        "payload": json.loads(fields["payload"]) if fields.get("payload") else {},
        "session_id": fields.get("session_id") or None,
    }


class Broadcaster:
    """One Redis reader task, fanned out to N per-connection queues."""

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self._client: redis.Redis | None = None

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAX)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers.discard(queue)

    def _publish(self, event: dict) -> None:
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # A stalled client: drop its oldest buffered frame to make
                # room for the newest one instead of blocking the broadcast.
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except asyncio.QueueEmpty:
                    pass

    async def _run(self) -> None:
        self._client = redis.from_url(REDIS_URL, decode_responses=True)
        await self._client.ping()
        log.info("tailing '%s' for live subscribers", STREAM)
        last_id = "$"
        while True:
            try:
                response = await self._client.xread({STREAM: last_id}, block=2000, count=200)
            except redis.ConnectionError:
                log.exception("redis connection lost — retrying in 3s")
                await asyncio.sleep(3)
                continue
            if not response:
                continue
            _, entries = response[0]
            for entry_id, fields in entries:
                last_id = entry_id
                try:
                    self._publish(_decode(fields))
                except Exception:
                    log.exception("undecodable entry %s — skipping", entry_id)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
        if self._client:
            await self._client.aclose()


broadcaster = Broadcaster()


async def stream_frames(queue: asyncio.Queue):
    """Yield lists of events, batched over ST_WS_BATCH_MS. Blocks (no polling)
    when the queue is idle; once one item arrives it drains whatever else
    shows up before the batch deadline."""
    interval = BATCH_MS / 1000
    loop = asyncio.get_event_loop()
    while True:
        batch = [await queue.get()]
        deadline = loop.time() + interval
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(queue.get(), remaining))
            except TimeoutError:
                break
        yield batch
