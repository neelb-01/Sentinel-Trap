"""One coroutine per traffic class. Each drives a single campaign end to end.

The classes mirror the corpus table in ``attack-sim/README.md`` and the
``class_weights`` taxonomy in ``config/scoring.yaml``. Four drive ``sentinel-web``
over HTTP:

    recon_scan            walk many paths, cheap and fast, scanner user-agents
    credential_bruteforce hammer one login endpoint past the rule thresholds
    web_exploit           SQLi / traversal / Log4Shell / Shellshock payloads
    benign                browsers, crawlers and monitors doing normal things

Two drive Cowrie over SSH (via ``SSHCampaign`` and the PROXY protocol):

    ssh_bruteforce        many password guesses over SSH — the SAME class label
                          as credential_bruteforce (a brute is a brute; only the
                          protocol differs), so its generator key differs from
                          its ``label``
    malware_dropper       log in, then run a Mirai-style download-and-execute

A generator only decides *what to do*; timing, the synthetic source and error
handling live in ``Campaign`` / ``SSHCampaign``. Counts are randomised per
campaign so no two attackers look identical. The credential, exploit and dropper
generators are shaped to actually trip the YAML rules (>=20 attempts with
>=10 distinct passwords; SQLi/traversal patterns; a single command line carrying
both a fetch and a chmod), so a run produces real alerts, not just events.
"""

from __future__ import annotations

import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from . import wordlists as w
from .client import Campaign, Timing
from .ssh_client import SSHCampaign


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


async def ssh_bruteforce(c: SSHCampaign, rng: random.Random) -> None:
    # >=20 attempts with >=10 distinct passwords clears 001-credential-bruteforce,
    # counting Cowrie's login.failed AND the occasional AuthRandom login.success.
    users = rng.sample(w.USERNAMES, k=rng.randint(1, 3))
    passwords = rng.sample(w.PASSWORDS, k=rng.randint(14, min(24, len(w.PASSWORDS))))
    attempts = max(rng.randint(24, 36), len(passwords))
    schedule = list(passwords) + [rng.choice(passwords) for _ in range(attempts - len(passwords))]
    rng.shuffle(schedule)
    for pwd in schedule:
        await c.try_login(rng.choice(users), pwd)


async def malware_dropper(c: SSHCampaign, rng: random.Random) -> None:
    # Walk distinct weak credentials until Cowrie's AuthRandom lets one in (it
    # grants the Nth *distinct* pair, N random 2..5), then recon, the
    # download-and-execute one-liner (trips 002-malware-dropper), and cleanup.
    # All commands run in one session -> one src_ip -> one session.
    guesses = rng.sample(w.SSH_WEAK_CREDS, k=min(10, len(w.SSH_WEAK_CREDS)))
    recon = rng.sample(w.MALWARE_RECON_COMMANDS, k=rng.randint(3, 6))
    commands = [*recon, w.dropper_oneliner(rng)]
    if rng.random() < 0.6:
        commands.extend(rng.sample(w.MALWARE_CLEANUP_COMMANDS, k=rng.randint(1, 2)))
    await c.run_dropper(guesses, commands)


CampaignT = Campaign | SSHCampaign


@dataclass(frozen=True, slots=True)
class ClassSpec:
    label: str  # the ground-truth class written to the manifest (see scoring.yaml)
    decoy: str  # "sentinel-web" | "cowrie" — which decoy this drives
    transport: str  # "http" | "ssh" — picks the campaign/client the runner builds
    generator: Callable[[CampaignT, random.Random], Awaitable[None]]
    timing: Timing
    # Per-request user-agents (http) or per-campaign client-version banners (ssh).
    fingerprints: tuple[str, ...]


# Timing is the inter-op gap range in seconds; benign is human-slow, recon is
# fast, the rest sit in between. Runner can scale all of them at once. The dict
# KEY is the generator/selector name (used by --only and the presets); the
# ``label`` is the taxonomy class — they differ only for ssh_bruteforce.
REGISTRY: dict[str, ClassSpec] = {
    "recon_scan": ClassSpec(
        "recon_scan",
        "sentinel-web",
        "http",
        recon_scan,
        Timing(0.05, 0.4),
        tuple(w.UA_SCANNER),
    ),
    "credential_bruteforce": ClassSpec(
        "credential_bruteforce",
        "sentinel-web",
        "http",
        credential_bruteforce,
        Timing(0.1, 0.6),
        tuple(w.UA_TOOL),
    ),
    "web_exploit": ClassSpec(
        "web_exploit",
        "sentinel-web",
        "http",
        web_exploit,
        Timing(0.15, 0.9),
        tuple(w.UA_EXPLOIT),
    ),
    "benign": ClassSpec(
        "benign",
        "sentinel-web",
        "http",
        benign,
        Timing(0.8, 4.0),
        tuple(w.UA_BROWSER + w.UA_CRAWLER),
    ),
    "ssh_bruteforce": ClassSpec(
        "credential_bruteforce",
        "cowrie",
        "ssh",
        ssh_bruteforce,
        Timing(0.1, 0.7),
        tuple(w.SSH_CLIENT_VERSIONS),
    ),
    "malware_dropper": ClassSpec(
        "malware_dropper",
        "cowrie",
        "ssh",
        malware_dropper,
        Timing(0.3, 1.5),
        tuple(w.SSH_CLIENT_VERSIONS),
    ),
}
