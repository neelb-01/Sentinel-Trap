# SentinelTrap

A web-based honeypot with a real-time detection pipeline and live dashboard.

Three decoy services pretend to be vulnerable. Everything they log is normalised into a single event
stream, grouped into sessions, scored by a layered detection stack — rules, anomaly detection, and a
supervised classifier — and rendered live in a browser as it happens.

> **Status: early.** The scaffold runs and the ingest path works end to end. The detection layers and
> dashboard are not built yet. See [Roadmap](#roadmap).

---

## Why this exists

Most honeypot projects stop at "we collected some logs." The interesting problem is what happens
next: turning raw decoy output into sessions, extracting features that actually separate a scripted
scanner from a hands-on-keyboard intruder, and producing an alert a human can act on and audit.

That middle layer is the point of this project. The decoys themselves are deliberately boring —
two are off-the-shelf, and the third is the one worth writing.

## Architecture

```
  DECOY TIER          INGEST            PROCESSING              STORAGE        SERVING
┌────────────┐
│ Cowrie     │ 22,23  ─┐
├────────────┤         │   Redis      enricher → sessioniser   TimescaleDB    FastAPI
│ sentinel-  │ 80,8080 ├─→ Streams →  → detection engine    →  + Redis     →  REST + WS
│ web        │         │   events.raw  (rules · IForest ·       + artifacts/   → Next.js
├────────────┤         │               LightGBM · HDBSCAN)                     dashboard
│ Dionaea    │ 21,445  ─┘
└────────────┘   ↑ JSONL to a shared volume, tailed line by line
```

One language boundary: Python owns everything from the decoys to the API, TypeScript owns the
browser.

| Layer | Choice | Built or configured |
|---|---|---|
| SSH / Telnet decoy | [Cowrie](https://github.com/cowrie/cowrie) | configured |
| Web decoy | `sentinel-web` (FastAPI) | **built here** |
| FTP / SMB / MySQL decoy | [Dionaea](https://github.com/DinoTools/dionaea) | configured |
| Event bus | Redis Streams | consumer groups, at-least-once |
| Store | PostgreSQL + TimescaleDB | `events` hypertable |
| Detection | scikit-learn, LightGBM, HDBSCAN | **built here** |
| API | FastAPI + WebSocket | **built here** |
| Dashboard | Next.js + React | **built here** |
| Runtime | Docker Compose | two isolated networks |

### Why a message broker for ~50 events/second

Because the decoys must never write straight to Postgres. When the analyser crashes, a direct-write
design silently drops every event that arrived while it was down. With a Redis Stream and a consumer
group the analyser restarts, resumes from its last acknowledged ID, and catches up. Consumers are
idempotent on `event_id`, so at-least-once delivery is safe.

## Isolation

The decoys are deliberately attackable, so containment is part of the design rather than an
afterthought:

- The decoy containers sit on their own bridge subnet (`172.30.0.0/24`) with **outbound traffic
  dropped** in the `DOCKER-USER` chain. Inbound published ports still work; egress does not.
- They are **never attached to the platform network**. The only channel between the two halves is a
  log volume, mounted read-only on the platform side.
- Only decoy ports are published. Redis, Postgres, the API and the dashboard bind to `127.0.0.1`.
- Every decoy runs unprivileged and read-only, with all capabilities dropped, `no-new-privileges`,
  a PID limit and a memory cap.
- Captured samples are stored by SHA-256 and **never executed**.

Apply the egress rule before exposing anything:

```sh
sudo ./scripts/honeynet-egress.sh
```

## Quick start

Requires Docker with Compose v2.

```sh
cp .env.example .env      # then edit POSTGRES_PASSWORD
make up                   # build and start the stack
make logs                 # follow the tailer
```

Then knock on the SSH decoy and watch the event arrive:

```sh
ssh -p 22 root@localhost          # password: anything
make psql
```
```sql
SELECT ts, decoy, src_ip, action, payload FROM events ORDER BY ts DESC LIMIT 5;
```

`make help` lists the rest.

## Layout

```
decoys/sentinel-web/   the web honeypot — fake logins, injectable-looking endpoints, tarpit
decoys/cowrie/         Cowrie configuration
pipeline/              log tailer, event schema, sessioniser, detection engine
api/                   FastAPI REST + WebSocket        (phase 2)
dashboard/             Next.js dashboard               (phase 2)
attack-sim/            traffic generator                (phase 3)
db/init/               schema, hypertable, indexes
config/                scoring weights and detection rules
scripts/               host-side setup
```

## Roadmap

| Phase | Scope | State |
|---|---|---|
| 1 | Compose skeleton, Cowrie logging, hypertable, tailer → Redis → Postgres | in progress |
| 2 | Web decoy endpoints, REST + `/ws/live`, live feed in the browser | next |
| 3 | Sessionisation, 25-feature extractor, enrichment, YAML rule engine | |
| 4 | Isolation Forest, LightGBM classifier, HDBSCAN campaigns, retraining | |
| 5 | Evaluation on a hand-labelled held-out set, session replay, auth | |

### On evaluation, up front

This runs locally, so there are no real attackers — traffic is generated by `attack-sim/`. That is a
real limitation and it will be stated plainly alongside any metric published here.

Two rules keep the numbers honest:

- Rule-derived labels and human labels are stored separately (`labels.source`). If the classifier
  trains on labels its own rule engine produced, it is just an expensive reimplementation of those
  regexes.
- Metrics are reported **only** on a hand-labelled held-out set, per class, as precision/recall and
  macro-F1 — never plain accuracy, which class imbalance makes meaningless here.

The number that matters most is not F1: it is how many attacks the anomaly layer caught that no rule
fired on.

## Licence

MIT — see [LICENSE](LICENSE).
