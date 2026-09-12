# api

FastAPI service: REST under `/api/*` for history, `/ws/live` for the real-time feed. Built and
verified end-to-end — real `sentinel-web` traffic reaches a connected WebSocket client as batched
frames, independently of the writer's own Postgres path.

- **`GET /api/events`** — most recent events first, keyset-paginated on `(ts, event_id)` rather than
  `OFFSET` (the table is append-only and growing, so an `OFFSET` page would drift under the feed).
  Filter with `decoy` / `src_ip`; page further back with the `before_ts` / `before_id` fields
  `next_cursor` hands back.
- **`GET /health`** — used by the compose healthcheck.
- **`WS /ws/live`** — a live tail, not a durable consumer: it reads the `events.raw` stream with a
  plain `XREAD` from `$` rather than a consumer group, since a gap on restart just means the
  dashboard re-fetches over REST. Frames are batched every `ST_WS_BATCH_MS` (default 250ms) — see
  `src/sentinel_api/stream.py` — so `attack-sim/` running at full speed pushes one message per
  interval instead of one per event, which is what freezes the browser.

**Binds to `127.0.0.1` only.** Reach it over an SSH tunnel; it is never published. CORS defaults to
`http://localhost:3000` (`ST_CORS_ORIGINS`) for the dashboard once that exists.

The models will load in-process here once phase 4 exists — same Python runtime as the detection
code, so there is no separate model-serving hop.
