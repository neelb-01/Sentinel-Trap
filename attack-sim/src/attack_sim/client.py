"""The per-campaign HTTP client: one synthetic source, jittered timing.

A ``Campaign`` wraps an ``httpx.AsyncClient`` and stamps every request with the
campaign's ``X-Forwarded-For`` so the decoy attributes it to that synthetic
source. It sleeps a jittered interval between requests so sessions have realistic
inter-arrival timing (one of the features the detector leans on) rather than a
machine-gun burst.

Errors are swallowed and counted, never raised: the decoy tarpits repeat
offenders (adds multi-second delays), and a single connection reset must not
abort a whole campaign — the point is the traffic that *did* land.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field

import httpx

from .sources import Source


@dataclass(slots=True)
class Campaign:
    source: Source
    client: httpx.AsyncClient
    rng: random.Random
    min_gap: float
    max_gap: float
    user_agent: str
    sent: int = 0
    failed: int = 0
    _first_request: bool = field(default=True, repr=False)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        json: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        if not self._first_request:
            await asyncio.sleep(self.rng.uniform(self.min_gap, self.max_gap))
        self._first_request = False

        hdrs = {
            "X-Forwarded-For": self.source.ip,
            "User-Agent": self.user_agent,
            **(headers or {}),
        }
        try:
            await self.client.request(
                method, path, params=params, data=data, json=json, headers=hdrs
            )
            self.sent += 1
        except httpx.HTTPError:
            self.failed += 1


@dataclass(slots=True)
class Timing:
    """Inter-request gap range, in seconds, for one class of traffic."""

    min_gap: float
    max_gap: float

    def scaled(self, factor: float) -> Timing:
        return Timing(self.min_gap * factor, self.max_gap * factor)
