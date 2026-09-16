"""FastAPI service: REST under /api/* for history, /ws/live for the real-time
feed. Binds to 127.0.0.1 only (see docker-compose.yml) — reach it over an SSH
tunnel, same as Postgres and Redis. Models will load in-process here once
phase 4 exists; there is no separate serving hop.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from enum import Enum

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, IPvAnyAddress

from . import db
from .stream import broadcaster, stream_frames

CORS_ORIGINS = os.environ.get("ST_CORS_ORIGINS", "http://localhost:3000").split(",")

# Coarse class a confirmed alert's highest-severity triggered rule maps to,
# for the human label triage writes — mirrors config/scoring.yaml's
# class_weights taxonomy so labels line up with what the phase-4 classifier
# will eventually predict.
_RULE_CLASS = {
    "credential-bruteforce": "credential_bruteforce",
    "malware-dropper": "malware_dropper",
    "path-traversal": "web_exploit",
    "sqli-probe": "web_exploit",
}

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
    allow_methods=["GET", "PATCH"],
    allow_headers=["*"],
)


class AlertStatus(str, Enum):
    """What a human can set a triage verdict to — deliberately excludes
    'new', which is only ever the value a fresh alert starts at, never
    something to set it back to."""

    triaged = "triaged"
    confirmed = "confirmed"
    false_positive = "false_positive"


class AlertStatusFilter(str, Enum):
    """All four values `alerts.status` can actually hold — for filtering
    GET /api/alerts, where 'new' is the default and most useful filter."""

    new = "new"
    triaged = "triaged"
    confirmed = "confirmed"
    false_positive = "false_positive"


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


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


@app.get("/api/alerts")
async def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    before_ts: datetime | None = None,
    before_id: str | None = None,
    status: AlertStatusFilter | None = None,
):
    """Most recent alerts first, each joined to its session's src_ip/decoy/timing."""
    rows = await db.fetch_alerts(
        limit=limit,
        before_ts=before_ts,
        before_id=before_id,
        status=status.value if status else None,
    )
    next_cursor = None
    if len(rows) == limit:
        last = rows[-1]
        next_cursor = {"before_ts": last["created_at"].isoformat(), "before_id": last["alert_id"]}
    return {"alerts": rows, "next_cursor": next_cursor}


@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: uuid.UUID, body: AlertStatusUpdate):
    """The triage verdict. `confirmed`/`false_positive` are final verdicts and
    also write a human label; `triaged` alone just means "looked at, no
    verdict yet" and writes nothing further."""
    row = await db.update_alert_status(str(alert_id), body.status.value)
    if row is None:
        raise HTTPException(status_code=404, detail="alert not found")

    if body.status == AlertStatus.false_positive:
        await db.upsert_human_label(row["session_id"], "benign")
    elif body.status == AlertStatus.confirmed:
        severities = await db.fetch_rule_severities(row["triggered_rules"])
        top_rule = max(severities, key=severities.get, default=None)
        label = _RULE_CLASS.get(top_rule, "web_exploit") if top_rule else "web_exploit"
        await db.upsert_human_label(row["session_id"], label)

    return row


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
