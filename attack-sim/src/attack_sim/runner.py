"""Orchestrates a run: build campaigns, drive them concurrently, write manifest.

    python -m attack_sim --preset quick
    python -m attack_sim --preset full --base-url http://127.0.0.1:8080
    python -m attack_sim --only web_exploit,credential_bruteforce --scale 2

Each campaign is one synthetic source running one class generator. Campaigns run
concurrently under a semaphore so the decoy sees interleaved sources — the same
picture the sessioniser would get from many real hosts — while a bounded pool
keeps the tarpit from stalling the whole run.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .client import Campaign
from .generators import REGISTRY
from .manifest import CampaignRecord, Manifest, now_iso
from .sources import Source, SourcePool
from .ssh_client import SSHCampaign

# Campaigns per class. Tuned so --full lands near the corpus targets in the
# README (recon ~1200, brute ~1500, exploit ~1000, benign ~800 requests).
PRESETS: dict[str, dict[str, int]] = {
    "quick": {
        "recon_scan": 6,
        "credential_bruteforce": 6,
        "web_exploit": 6,
        "benign": 10,
        "ssh_bruteforce": 4,
        "malware_dropper": 4,
    },
    "full": {
        "recon_scan": 48,
        "credential_bruteforce": 50,
        "web_exploit": 72,
        "benign": 160,
        "ssh_bruteforce": 40,
        "malware_dropper": 30,
    },
}

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_SSH_HOST = "127.0.0.1"
# Cowrie's PROXY-protocol-wrapped SSH endpoint (docker maps 127.0.0.1:2224 ->
# container 2224). The plain :22 endpoint drops our PROXY header, so target 2224.
DEFAULT_SSH_PORT = 2224


async def _run_campaign(
    spec_name: str,
    source: Source,
    base_url: str,
    ssh_host: str,
    ssh_port: int,
    rng: random.Random,
    timing_scale: float,
    sem: asyncio.Semaphore,
    manifest: Manifest,
) -> None:
    spec = REGISTRY[spec_name]
    timing = spec.timing.scaled(timing_scale)
    fingerprint = rng.choice(spec.fingerprints)
    async with sem:
        started = now_iso()
        if spec.transport == "ssh":
            campaign: Campaign | SSHCampaign = SSHCampaign(
                source=source,
                host=ssh_host,
                port=ssh_port,
                rng=rng,
                min_gap=timing.min_gap,
                max_gap=timing.max_gap,
                client_version=fingerprint,
            )
            await spec.generator(campaign, rng)
        else:
            limits = httpx.Limits(max_connections=1)
            async with httpx.AsyncClient(
                base_url=base_url, timeout=30.0, limits=limits, follow_redirects=False
            ) as client:
                campaign = Campaign(
                    source=source,
                    client=client,
                    rng=rng,
                    min_gap=timing.min_gap,
                    max_gap=timing.max_gap,
                    user_agent=fingerprint,
                )
                await spec.generator(campaign, rng)
        manifest.add(
            CampaignRecord(
                src_ip=source.ip,
                held_out=source.held_out,
                label=spec.label,
                decoy=spec.decoy,
                fingerprint=fingerprint,
                started_at=started,
                ended_at=now_iso(),
                requests_sent=campaign.sent,
                requests_failed=campaign.failed,
            )
        )


async def run(args: argparse.Namespace) -> int:
    mix = dict(PRESETS[args.preset])
    if args.only:
        wanted = {s.strip() for s in args.only.split(",") if s.strip()}
        unknown = wanted - REGISTRY.keys()
        if unknown:
            print(f"unknown class(es): {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"known: {', '.join(REGISTRY)}", file=sys.stderr)
            return 2
        mix = {k: v for k, v in mix.items() if k in wanted}
    mix = {k: int(v * args.scale) for k, v in mix.items()}

    rng = random.Random(args.seed)
    pool = SourcePool(rng, holdout_fraction=args.holdout_fraction)
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    manifest = Manifest(Path(args.out), run_id, args.base_url, args.seed)

    # Pre-allocate one source per campaign so no address is reused within the run.
    plan: list[tuple[str, Source]] = []
    for spec_name, count in mix.items():
        for _ in range(count):
            plan.append((spec_name, pool.take()))
    rng.shuffle(plan)  # interleave classes so sources arrive mixed, not in blocks

    print(
        f"run {run_id}: {len(plan)} campaigns "
        f"({', '.join(f'{k}={v}' for k, v in mix.items())}) "
        f"-> {args.base_url}  seed={args.seed}",
        file=sys.stderr,
    )

    # Fail fast if a decoy we need is not reachable, rather than logging N
    # failures. Probe only the transports actually in the plan.
    transports = {REGISTRY[name].transport for name, _ in plan}
    if "http" in transports:
        try:
            async with httpx.AsyncClient(base_url=args.base_url, timeout=5.0) as probe:
                await probe.get("/robots.txt")
        except httpx.HTTPError as exc:
            print(f"cannot reach sentinel-web at {args.base_url}: {exc}", file=sys.stderr)
            print("is the stack up (make up) and the port published?", file=sys.stderr)
            return 1
    if "ssh" in transports:
        try:
            await asyncio.to_thread(
                lambda: socket.create_connection(
                    (args.ssh_host, args.ssh_port), timeout=5.0
                ).close()
            )
        except OSError as exc:
            print(
                f"cannot reach Cowrie SSH at {args.ssh_host}:{args.ssh_port}: {exc}",
                file=sys.stderr,
            )
            print("is the stack up (make up) and port 22 published?", file=sys.stderr)
            return 1

    sem = asyncio.Semaphore(args.concurrency)
    await asyncio.gather(
        *(
            _run_campaign(
                name,
                source,
                args.base_url,
                args.ssh_host,
                args.ssh_port,
                random.Random(rng.random()),
                args.timing_scale,
                sem,
                manifest,
            )
            for name, source in plan
        )
    )

    jsonl, summary = manifest.write()
    sent = sum(r.requests_sent for r in manifest.records)
    failed = sum(r.requests_failed for r in manifest.records)
    held = sum(r.held_out for r in manifest.records)
    print(
        f"done: {sent} requests sent, {failed} failed, "
        f"{held}/{len(manifest.records)} campaigns held out",
        file=sys.stderr,
    )
    print(f"manifest: {jsonl}", file=sys.stderr)
    print(f"summary:  {summary}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="attack-sim", description=__doc__)
    p.add_argument(
        "--preset",
        choices=PRESETS,
        default="quick",
        help="campaign counts per class (default: quick)",
    )
    p.add_argument("--only", default="", help="comma-separated subset of classes to run")
    p.add_argument("--scale", type=float, default=1.0, help="multiply every class's campaign count")
    p.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"sentinel-web base URL (default: {DEFAULT_BASE_URL})",
    )
    p.add_argument(
        "--ssh-host",
        default=DEFAULT_SSH_HOST,
        help=f"Cowrie SSH host (default: {DEFAULT_SSH_HOST})",
    )
    p.add_argument(
        "--ssh-port",
        type=int,
        default=DEFAULT_SSH_PORT,
        help=f"Cowrie SSH port (default: {DEFAULT_SSH_PORT})",
    )
    p.add_argument(
        "--concurrency", type=int, default=20, help="max campaigns running at once (default: 20)"
    )
    p.add_argument(
        "--timing-scale",
        type=float,
        default=1.0,
        help="multiply inter-request gaps (>1 slower, <1 faster)",
    )
    p.add_argument(
        "--holdout-fraction",
        type=float,
        default=0.2,
        help="fraction of campaigns drawn from the held-out source range",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=random.randint(0, 2**31 - 1),
        help="RNG seed (default: random; printed for reproducibility)",
    )
    p.add_argument(
        "--out",
        default=str(Path(__file__).resolve().parents[2] / "out"),
        help="manifest output directory (default: attack-sim/out)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
