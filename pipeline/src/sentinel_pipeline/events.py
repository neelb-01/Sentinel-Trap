"""The normalised event schema.

Every decoy is flattened into this shape *before* anything hits the stream. Downstream code
never sees a Cowrie field or a Dionaea field — only an Event.

`raw` is always kept. It costs little and it is the only honest source for session replay.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32


def ulid() -> str:
    """A ULID: 48-bit millisecond timestamp + 80 bits of randomness, lexicographically sortable."""
    ts = int(time.time() * 1000)
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ts << 80) | rand
    return "".join(_ULID_ALPHABET[(value >> shift) & 0x1F] for shift in range(125, -5, -5))


@dataclass(slots=True)
class Event:
    ts: datetime
    decoy: str
    protocol: str
    src_ip: str
    action: str
    src_port: int | None = None
    dst_port: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    raw: str | None = None
    event_id: str = field(default_factory=ulid)

    def to_stream_fields(self) -> dict[str, str]:
        """Redis stream entries are flat string maps; payload rides as JSON."""
        d = asdict(self)
        d["ts"] = self.ts.astimezone(timezone.utc).isoformat()
        d["payload"] = json.dumps(self.payload, separators=(",", ":"))
        return {k: ("" if v is None else str(v)) for k, v in d.items()}

    @classmethod
    def from_stream_fields(cls, fields: dict[str, str]) -> "Event":
        return cls(
            event_id=fields["event_id"],
            ts=datetime.fromisoformat(fields["ts"]),
            decoy=fields["decoy"],
            protocol=fields["protocol"],
            src_ip=fields["src_ip"],
            action=fields["action"],
            src_port=int(fields["src_port"]) if fields.get("src_port") else None,
            dst_port=int(fields["dst_port"]) if fields.get("dst_port") else None,
            payload=json.loads(fields.get("payload") or "{}"),
            raw=fields.get("raw") or None,
        )


# --------------------------------------------------------------------- normalisers

# Cowrie's eventid -> our action vocabulary. Anything unmapped keeps its Cowrie
# name minus the prefix, so a new Cowrie version degrades to a readable action
# rather than dropping the event.
_COWRIE_ACTIONS = {
    "cowrie.login.success": "login_success",
    "cowrie.login.failed": "login_attempt",
    "cowrie.session.connect": "connect",
    "cowrie.session.closed": "disconnect",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command_failed",
    "cowrie.session.file_download": "file_download",
    "cowrie.session.file_upload": "file_upload",
    "cowrie.client.version": "client_fingerprint",
    "cowrie.direct-tcpip.request": "tunnel_request",
}


def _parse_ts(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def from_cowrie(line: str) -> Event | None:
    """Normalise one line of Cowrie's JSON log."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None

    eventid = d.get("eventid", "")
    if not eventid or "src_ip" not in d:
        return None

    action = _COWRIE_ACTIONS.get(eventid, eventid.removeprefix("cowrie."))

    # Keep the fields that carry signal; drop Cowrie's bookkeeping.
    payload = {
        k: v
        for k, v in d.items()
        if k in ("username", "password", "input", "message", "url", "outfile",
                 "shasum", "filename", "version", "duration", "session", "ttylog")
        and v is not None
    }

    return Event(
        ts=_parse_ts(d.get("timestamp")),
        decoy="cowrie",
        protocol="telnet" if d.get("dst_port") == 2223 else "ssh",
        src_ip=d["src_ip"],
        src_port=d.get("src_port"),
        dst_port=22 if d.get("dst_port") == 2222 else (23 if d.get("dst_port") == 2223 else d.get("dst_port")),
        action=action,
        payload=payload,
        raw=line.rstrip("\n"),
    )


def from_sentinel_web(line: str) -> Event | None:
    """sentinel-web already writes the normalised shape; validate and adopt it."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None

    if "src_ip" not in d or "action" not in d:
        return None

    return Event(
        event_id=d.get("event_id") or ulid(),
        ts=_parse_ts(d.get("ts")),
        decoy=d.get("decoy", "sentinel-web"),
        protocol=d.get("protocol", "http"),
        src_ip=d["src_ip"],
        src_port=d.get("src_port"),
        dst_port=d.get("dst_port"),
        action=d["action"],
        payload=d.get("payload") or {},
        raw=line.rstrip("\n"),
    )


def from_dionaea(line: str) -> Event | None:
    """Dionaea's JSON output. Enable once the decoy is turned on in compose."""
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None

    src_ip = d.get("remote_host") or d.get("src_ip")
    if not src_ip:
        return None

    return Event(
        ts=_parse_ts(d.get("timestamp")),
        decoy="dionaea",
        protocol=d.get("connection_protocol", "unknown"),
        src_ip=src_ip,
        src_port=d.get("remote_port"),
        dst_port=d.get("local_port"),
        action=d.get("connection_type", "connect"),
        payload={k: v for k, v in d.items() if k not in ("remote_host", "remote_port", "local_port")},
        raw=line.rstrip("\n"),
    )


#: Which normaliser handles which log directory, keyed by the subdirectory of ST_LOG_DIR.
NORMALISERS = {
    "cowrie": from_cowrie,
    "sentinel-web": from_sentinel_web,
    "dionaea": from_dionaea,
}
