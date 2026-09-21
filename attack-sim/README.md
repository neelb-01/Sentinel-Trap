# attack-sim — phase 3

Synthetic attack-traffic generator. This is a first-class deliverable, not a test
fixture: running locally means there are no real attackers, so this module
produces everything the detection layer trains and demos on.

It drives the live decoys exactly as a real client would. Each generated
*campaign* is one synthetic attacker with its own source address, so the
sessioniser splits traffic by origin the same way it would for many real hosts.
The source is spoofed per protocol: HTTP campaigns present it via
`X-Forwarded-For` (`sentinel-web` honours it when `ST_TRUST_XFF=1`); SSH campaigns
prefix each connection with a HAProxy **PROXY-protocol v1** header, which Cowrie
attributes the session to when its listener is a `haproxy:` endpoint. Both are set
in `docker-compose.yml` for the local sim only — a public VPS must keep the plain
endpoints (see the compose comments), or a real client could spoof its own origin
and, for SSH, real scanners that send no PROXY header would be dropped.

## What's built

The four **web** classes, driving `sentinel-web`:

| Class | Shape | Trips |
|---|---|---|
| `recon_scan` | walks ~15–35 paths (admin panels, `.env`, `.git`, backups), scanner UAs, fast | — (recon has no rule yet; it's a distinct-path / sensitive-probe signal for phase 4) |
| `credential_bruteforce` | 20–40 login POSTs, ≥12 distinct passwords, against one of `/wp-login.php`, `/admin`, `/api/v1/auth` | `001-credential-bruteforce` |
| `web_exploit` | SQLi in `/search?q=`, LFI/traversal via query and path, Log4Shell / Shellshock in headers | `004-sqli-probe`, `003-path-traversal` |
| `benign` | browsers, crawlers and monitors doing normal things — the negatives | nothing (class weight 0.0) |

And the two **SSH** classes, driving Cowrie (via `paramiko` over the PROXY
protocol):

| Class | Shape | Trips |
|---|---|---|
| `ssh_bruteforce` | 24–36 SSH logins, ≥14 distinct passwords, one connection each | `001-credential-bruteforce` (fires, but severity 0.6 → 24 < 25 `alert_minimum`, so no alert on its own — same as the web credential class) |
| `malware_dropper` | walk distinct weak creds until Cowrie's `AuthRandom` grants a shell, then recon + a Mirai-style `wget/curl/tftp … ; chmod +x … ; ./…` one-liner + cleanup | `002-malware-dropper` (severity 0.95 → alert, score 38) |

`ssh_bruteforce`'s manifest **label** is `credential_bruteforce` — a brute is that
class regardless of protocol; only the generator key differs. The dropper's fetch
and `chmod` share one command line on purpose: `002` matches a single event's
`payload.input`, and Cowrie logs an exec'd line whole before splitting it.

The credential, exploit and dropper generators are deliberately shaped to clear
the rule thresholds, so a run produces real **alerts**, not just events.

Still **not** built (see the root `CLAUDE.md`): a Telnet brute class (Cowrie's
telnet listener is also PROXY-wrapped, but `telnetlib` was removed in Python 3.13,
so it needs a hand-rolled client) and any real external tool
(`nmap`/`hydra`/`sqlmap`/…), which the generators can shell out to later where one
is on `$PATH`.

## Target corpus

| Class | Generated with | Volume |
|---|---|---|
| `recon_scan` | path sweeps (+ `nmap`/`masscan`/`nikto` when available) | ~1200 |
| `credential_bruteforce` | login POST floods (+ `hydra` for SSH later) | ~1500 |
| `web_exploit` | SQLi / LFI / traversal / Log4Shell / Shellshock (+ `sqlmap` later) | ~1000 |
| `malware_dropper` | scripted Cowrie sessions replaying Mirai-style transcripts | ~600 |
| `benign` | crawlers, health checks, monitoring probes, stray browser visits | ~800 |

Vary timing, wordlists and source addresses so the model learns behaviour rather
than memorising one machine.

## Labels and the held-out set

**No class label is ever written into an event** — that would leak the ground
truth straight into the features (the fatal flaw of this project class). Labels
live only in the run **manifest**, keyed to the synthetic source IP, decoy and
time window, to be joined against `sessions` on `(src_ip, decoy)` after the fact.

Sources come from RFC 5737 documentation ranges, which can never collide with a
real host: training campaigns draw from `198.51.100.0/24`, held-out campaigns from
`203.0.113.0/24`. **Hold out a slice that is never trained on and hand-label it** —
that set (`held_out: true` in the manifest, and trivially separable by IP range)
is the only thing metrics may be quoted from. See the labelling note in the root
README.

Each run writes to `attack-sim/out/` (gitignored):
`manifest-<runid>.jsonl` (one row per campaign) and `summary-<runid>.json`.

## Running it

Needs the stack up (`make up`) and two dependencies (`httpx`, `paramiko`):

```sh
cd attack-sim
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m attack_sim --preset quick                       # a fast demo, all six classes
python -m attack_sim --preset full                         # near the corpus targets
python -m attack_sim --only web_exploit --scale 2          # just one class, doubled
python -m attack_sim --only ssh_bruteforce,malware_dropper # just the Cowrie classes
python -m attack_sim --preset quick --seed 42              # reproducible; the seed is printed either way
```

Useful flags: `--base-url` (default `http://127.0.0.1:8080`) and `--ssh-host` /
`--ssh-port` (default `127.0.0.1:2224`, Cowrie's localhost-only PROXY-protocol SSH endpoint — the
public `:22` stays plain for manual `ssh`) for the two decoys;
`--concurrency`, `--holdout-fraction` (default `0.2`), `--timing-scale` (`>1`
slower, `<1` faster; `0` fires as fast as possible). The runner probes only the
transports a run actually needs, so an HTTP-only `--only` doesn't require SSH up.
After a run, watch it land with `make sessions`, `make logs-sessioniser`, and the
triage queue at `curl 127.0.0.1:8000/api/alerts` or the dashboard.
