"""Synthetic source addresses and the train / held-out split.

Every generated campaign gets its own source IP, presented to the decoy via
``X-Forwarded-For``. Addresses come from RFC 5737 documentation ranges, which are
reserved for exactly this — examples and test traffic — so they can never collide
with a real host and they signal "synthetic" to anyone reading the events later:

    training   198.51.100.0/24  (TEST-NET-2)
    held-out   203.0.113.0/24   (TEST-NET-3)

Splitting the held-out set by address range is deliberate: the slice that metrics
may be quoted from is then trivially separable at evaluation time, on top of the
explicit ``held_out`` flag the manifest records.

A source is handed out to at most one campaign per run (sampled without
replacement). Two campaigns sharing an IP inside the sessioniser's 15-minute gap
would merge into one session with two class labels — the one ambiguity that would
quietly poison training — so we simply never reuse an address within a run.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass

TRAINING_NET = ipaddress.ip_network("198.51.100.0/24")
HELDOUT_NET = ipaddress.ip_network("203.0.113.0/24")


@dataclass(frozen=True, slots=True)
class Source:
    ip: str
    held_out: bool


class SourcePool:
    """Hands out unique synthetic source IPs, split into train / held-out."""

    def __init__(self, rng: random.Random, holdout_fraction: float = 0.2) -> None:
        self._rng = rng
        self._holdout_fraction = holdout_fraction
        # Skip network/broadcast; .1 is a plausible gateway, keep it out too.
        self._train = [str(h) for h in TRAINING_NET.hosts()][1:]
        self._heldout = [str(h) for h in HELDOUT_NET.hosts()][1:]
        rng.shuffle(self._train)
        rng.shuffle(self._heldout)

    def take(self) -> Source:
        """One unused source, held-out with probability ``holdout_fraction``."""
        want_holdout = self._rng.random() < self._holdout_fraction
        if want_holdout and self._heldout:
            return Source(self._heldout.pop(), held_out=True)
        if self._train:
            return Source(self._train.pop(), held_out=False)
        if self._heldout:
            return Source(self._heldout.pop(), held_out=True)
        raise RuntimeError(
            "source pool exhausted: more campaigns than documentation addresses "
            "(254 train + 254 held-out). Lower --campaigns or widen the pools."
        )
