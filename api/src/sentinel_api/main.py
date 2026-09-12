"""FastAPI service: REST under /api/* for history, /ws/live for the real-time
feed. Binds to 127.0.0.1 only (see docker-compose.yml) — reach it over an SSH
tunnel, same as Postgres and Redis. Models will load in-process here once
phase 4 exists; there is no separate serving hop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import IPvAnyAddress

from . import db
from .stream import broadcaster, stream_frames

CORS_ORIGINS = os.environ.get("ST_CORS_ORIGINS", "http://localhost:3000").split(",")

logging.basicConfig(
    level=os.environ.get("ST_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.pool.open()
    await broadcaster.start()
    log.info("api ready")
    yield
    await broadcaster.stop()
    await db.pool.close()


app = FastAPI(title="SentinelTrap API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/events")
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    before_ts: datetime | None = None,
    before_id: str | None = None,
    decoy: str | None = None,
    src_ip: IPvAnyAddress | None = None,
):
    """Most recent events first. Pass back next_cursor's fields as before_ts /
    before_id to page further into the past."""
    rows = await db.fetch_events(
        limit=limit,
        before_ts=before_ts,
        before_id=before_id,
        decoy=decoy,
        src_ip=str(src_ip) if src_ip else None,
    )
    next_cursor = None
    if len(rows) == limit:
        last = rows[-1]
        next_cursor = {"before_ts": last["ts"].isoformat(), "before_id": last["event_id"]}
    return {"events": rows, "next_cursor": next_cursor}


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await websocket.accept()
    queue = broadcaster.subscribe()

    async def receiver() -> None:
        # The client sends nothing; this exists only to notice a disconnect
        # promptly rather than on the next failed send.
        while True:
            await websocket.receive_text()

    async def sender() -> None:
        async for batch in stream_frames(queue):
            await websocket.send_json({"type": "events", "data": batch})

    recv_task = asyncio.create_task(receiver())
    send_task = asyncio.create_task(sender())
    try:
        done, pending = await asyncio.wait(
            {recv_task, send_task}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in done:
            exc = task.exception()
            if exc and not isinstance(exc, WebSocketDisconnect):
                log.debug("ws_live ended: %r", exc)
    finally:
        broadcaster.unsubscribe(queue)
