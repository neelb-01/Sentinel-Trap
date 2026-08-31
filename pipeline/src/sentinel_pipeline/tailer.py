"""Tail every decoy log, normalise each line, XADD it to Redis.

This is the only component that touches a decoy. It reads the shared log volume
read-only and never connects to the honeynet.

Offsets are checkpointed to ST_STATE_DIR so a restart resumes where it stopped
instead of replaying the file. Files are tracked by inode so rotation is handled:
a new inode at a known path is a rotated file and starts from zero.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

import redis

from .events import NORMALISERS, Event

LOG_DIR = Path(os.environ.get("ST_LOG_DIR", "/logs"))
STATE_DIR = Path(os.environ.get("ST_STATE_DIR", "/state"))
REDIS_URL = os.environ.get("ST_REDIS_URL", "redis://redis:6379/0")
STREAM = os.environ.get("ST_STREAM", "events.raw")
MAXLEN = int(os.environ.get("ST_STREAM_MAXLEN", "1000000"))
POLL_SECONDS = float(os.environ.get("ST_POLL_SECONDS", "0.5"))

logging.basicConfig(
    level=os.environ.get("ST_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("tailer")

_running = True


def _stop(signum, _frame):
    global _running
    log.info("signal %s — shutting down", signum)
    _running = False


class Cursor:
    """Byte offset into one log file, checkpointed across restarts."""

    def __init__(self, path: Path, state_path: Path):
        self.path = path
        self.state_path = state_path
        self.offset = 0
        self.inode: int | None = None
        self._load()

    def _load(self) -> None:
        if not self.state_path.exists():
            return
        try:
            state = json.loads(self.state_path.read_text())
            self.offset = state["offset"]
            self.inode = state["inode"]
        except (OSError, ValueError, KeyError):
            log.warning("unreadable cursor %s — starting from 0", self.state_path)

    def save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offset": self.offset, "inode": self.inode}))
        tmp.replace(self.state_path)  # atomic

    def read_new_lines(self) -> list[str]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []

        # Rotation: a different inode, or a file that shrank beneath our offset.
        if self.inode is not None and stat.st_ino != self.inode:
            log.info("%s rotated — restarting at 0", self.path.name)
            self.offset = 0
        elif stat.st_size < self.offset:
            log.info("%s truncated — restarting at 0", self.path.name)
            self.offset = 0

        self.inode = stat.st_ino
        if stat.st_size == self.offset:
            return []

        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self.offset)
            data = fh.read()
            # Only consume through the last newline; a partial trailing line is
            # a half-written record and will be complete on the next poll.
            cut = data.rfind("\n")
            if cut == -1:
                return []
            self.offset += len(data[: cut + 1].encode("utf-8"))
            return data[: cut + 1].splitlines()


def discover() -> dict[Path, str]:
    """Map each decoy log file to the decoy whose normaliser owns it."""
    found: dict[Path, str] = {}
    for decoy in NORMALISERS:
        directory = LOG_DIR / decoy
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json*")):
            if path.is_file() and not path.name.endswith(".tmp"):
                found[path] = decoy
    return found


def main() -> int:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    client = redis.from_url(REDIS_URL, decode_responses=True)

    # Fail loudly at startup rather than silently buffering nothing.
    client.ping()
    log.info("connected to %s, publishing to '%s'", REDIS_URL, STREAM)

    cursors: dict[Path, Cursor] = {}
    published = skipped = 0
    last_report = time.monotonic()

    while _running:
        for path, decoy in discover().items():
            if path not in cursors:
                state_path = STATE_DIR / f"{decoy}__{path.name}.json"
                cursors[path] = Cursor(path, state_path)
                log.info("tailing %s from offset %d", path, cursors[path].offset)

            cursor = cursors[path]
            lines = cursor.read_new_lines()
            if not lines:
                continue

            normalise = NORMALISERS[decoy]
            pipe = client.pipeline(transaction=False)
            batched = 0

            for line in lines:
                if not line.strip():
                    continue
                try:
                    event: Event | None = normalise(line)
                except Exception:  # a malformed line must never kill the tailer
                    log.exception("normaliser %s failed on: %.200s", decoy, line)
                    event = None

                if event is None:
                    skipped += 1
                    continue

                pipe.xadd(STREAM, event.to_stream_fields(), maxlen=MAXLEN, approximate=True)
                batched += 1

            if batched:
                pipe.execute()
                published += batched
                # Checkpoint only after a successful XADD, so a crash re-reads
                # rather than loses. Consumers are idempotent on event_id.
                cursor.save()

        now = time.monotonic()
        if now - last_report >= 60:
            log.info("published=%d skipped=%d files=%d", published, skipped, len(cursors))
            last_report = now

        time.sleep(POLL_SECONDS)

    log.info("stopped. published=%d skipped=%d", published, skipped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
