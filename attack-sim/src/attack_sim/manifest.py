"""The run manifest: the only place a class label is recorded.

Events carry no label — writing one into the event JSON would leak the ground
truth straight into the features. Instead every campaign writes one manifest row
keyed by its synthetic source IP, decoy and time window. Phase 4 joins these to
``sessions`` on ``(src_ip, decoy)`` within the window to build a training set;
phase 5 filters to ``held_out = true`` for the never-trained-on evaluation slice.

Written as JSONL to ``attack-sim/out/`` (gitignored) plus a small JSON summary.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(slots=True)
class CampaignRecord:
    src_ip: str
    held_out: bool
    label: str
    decoy: str
    user_agent: str
    started_at: str
    ended_at: str
    requests_sent: int
    requests_failed: int


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


class Manifest:
    def __init__(self, out_dir: Path, run_id: str, base_url: str, seed: int) -> None:
        self.out_dir = out_dir
        self.run_id = run_id
        self.base_url = base_url
        self.seed = seed
        self.records: list[CampaignRecord] = []

    def add(self, record: CampaignRecord) -> None:
        self.records.append(record)

    def write(self) -> tuple[Path, Path]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        jsonl = self.out_dir / f"manifest-{self.run_id}.jsonl"
        with jsonl.open("w", encoding="utf-8") as fh:
            for r in self.records:
                fh.write(json.dumps(asdict(r), separators=(",", ":")) + "\n")

        summary = self.out_dir / f"summary-{self.run_id}.json"
        by_class: dict[str, dict[str, int]] = {}
        for r in self.records:
            c = by_class.setdefault(r.label, {"campaigns": 0, "requests": 0, "held_out": 0})
            c["campaigns"] += 1
            c["requests"] += r.requests_sent
            c["held_out"] += int(r.held_out)
        summary.write_text(
            json.dumps(
                {
                    "run_id": self.run_id,
                    "base_url": self.base_url,
                    "seed": self.seed,
                    "campaigns": len(self.records),
                    "requests_sent": sum(r.requests_sent for r in self.records),
                    "requests_failed": sum(r.requests_failed for r in self.records),
                    "by_class": by_class,
                },
                indent=2,
            )
        )
        return jsonl, summary
