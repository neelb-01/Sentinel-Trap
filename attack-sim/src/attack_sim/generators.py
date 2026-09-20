"""One coroutine per traffic class. Each drives a single campaign end to end.

The four classes mirror the corpus table in ``attack-sim/README.md`` and the
``class_weights`` taxonomy in ``config/scoring.yaml``:

    recon_scan            walk many paths, cheap and fast, scanner user-agents
    credential_bruteforce hammer one login endpoint past the rule thresholds
    web_exploit           SQLi / traversal / Log4Shell / Shellshock payloads
    benign                browsers, crawlers and monitors doing normal things

A generator only decides *what requests to make*; timing, the synthetic source
and error handling live in ``Campaign``. Request counts are randomised per
campaign so no two attackers look identical. The credential and exploit
generators are shaped to actually trip the YAML rules (>=20 attempts with
>=10 distinct passwords; ``payload.q`` / ``payload.query`` matching the SQLi and
traversal patterns), so a run produces real alerts, not just events.
"""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from . import wordlists as w
from .client import Campaign, Timing


async def recon_scan(c: Campaign, rng: random.Random) -> None:
    paths = rng.sample(w.RECON_PATHS, k=rng.randint(15, min(35, len(w.RECON_PATHS))))
    for path in paths:
        method = rng.choices(["GET", "HEAD", "OPTIONS"], weights=[85, 10, 5])[0]
        # Scanners rotate tools mid-sweep; vary the UA per request sometimes.
        ua = rng.choice(w.UA_SCANNER) if rng.random() < 0.3 else c.user_agent
        await c.request(method, path, headers={"User-Agent": ua})


async def credential_bruteforce(c: Campaign, rng: random.Random) -> None:
    target = rng.choice(["wordpress", "admin", "api"])
    users = rng.sample(w.USERNAMES, k=rng.randint(1, 3))
    # >=12 distinct passwords, 20-40 attempts: clears the rule (>=20 / >=10).
    passwords = rng.sample(w.PASSWORDS, k=rng.randint(12, min(24, len(w.PASSWORDS))))
    attempts = max(rng.randint(20, 40), len(passwords))
    # Walk every distinct password once before repeating, so the count of
    # *distinct* passwords actually used clears the rule threshold regardless of
    # how the random draws fall. The rest of the attempts are random re-tries.
    schedule = list(passwords) + [rng.choice(passwords) for _ in range(attempts - len(passwords))]
    rng.shuffle(schedule)
    for pwd in schedule:
        user = rng.choice(users)
        if target == "wordpress":
            await c.request("POST", "/wp-login.php", data={"log": user, "pwd": pwd})
        elif target == "admin":
            await c.request("POST", "/admin", data={"username": user, "password": pwd})
        else:
            await c.request("POST", "/api/v1/auth", json={"username": user, "password": pwd})


async def web_exploit(c: Campaign, rng: random.Random) -> None:
    # A quick recon of the injectable endpoint, then a spread of payloads.
    await c.request("GET", "/search", params={"q": "test"})
    n = rng.randint(8, 18)
    for _ in range(n):
        kind = rng.choices(["sqli", "traversal", "header"], weights=[45, 40, 15])[0]
        if kind == "sqli":
            await c.request("GET", "/search", params={"q": rng.choice(w.SQLI_PAYLOADS)})
        elif kind == "traversal":
            payload = rng.choice(w.TRAVERSAL_PAYLOADS)
            # Half via the search box (payload.q), half via an arbitrary path.
            if rng.random() < 0.5:
                await c.request("GET", "/search", params={"q": payload})
            else:
                await c.request("GET", f"/{payload}")
        else:
            header, value = rng.choice(w.EXPLOIT_HEADER_PAYLOADS)
            await c.request("GET", "/", headers={header: value})


async def benign(c: Campaign, rng: random.Random) -> None:
    flavour = rng.choices(["browser", "crawler", "monitor"], weights=[55, 30, 15])[0]
    if flavour == "monitor":
        # A health checker: a couple of hits on the root, nothing else.
        for _ in range(rng.randint(2, 4)):
            await c.request("GET", "/")
        return
    if flavour == "crawler":
        await c.request("GET", "/robots.txt")
        for path in rng.sample(w.BENIGN_PATHS, k=rng.randint(2, 5)):
            await c.request("GET", path)
        return
    # A human with a browser: a few pages, maybe a search, maybe eye a login form.
    for path in rng.sample(w.BENIGN_PATHS, k=rng.randint(2, 5)):
        await c.request("GET", path)
    if rng.random() < 0.6:
        await c.request("GET", "/search", params={"q": rng.choice(w.BENIGN_SEARCH_TERMS)})
    if rng.random() < 0.3:
        await c.request("GET", "/wp-login.php")  # a look, never a POST


@dataclass(frozen=True, slots=True)
class ClassSpec:
    label: str
    generator: Callable[[Campaign, random.Random], Awaitable[None]]
    timing: Timing
    ua_pool: tuple[str, ...]


# Timing is the inter-request gap range in seconds; benign is human-slow, recon
# is fast, exploit/brute sit in between. Runner can scale all of them at once.
REGISTRY: dict[str, ClassSpec] = {
    "recon_scan": ClassSpec(
        "recon_scan", recon_scan, Timing(0.05, 0.4), tuple(w.UA_SCANNER)
    ),
    "credential_bruteforce": ClassSpec(
        "credential_bruteforce", credential_bruteforce, Timing(0.1, 0.6), tuple(w.UA_TOOL)
    ),
    "web_exploit": ClassSpec(
        "web_exploit", web_exploit, Timing(0.15, 0.9), tuple(w.UA_EXPLOIT)
    ),
    "benign": ClassSpec(
        "benign", benign, Timing(0.8, 4.0), tuple(w.UA_BROWSER + w.UA_CRAWLER)
    ),
}
