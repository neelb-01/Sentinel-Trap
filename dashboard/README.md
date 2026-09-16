# dashboard — phase 2

Next.js 16 / React 19, TypeScript, Tailwind v4. Scaffolded with
`create-next-app@latest . --typescript --tailwind --app --eslint`.

## Built so far

**Live feed** (`app/page.tsx`, `app/components/LiveFeed.tsx`) — the first of the eight views, and
per the build order the one that had to come before anything else: one event flowing
decoy -> Redis -> Postgres -> WebSocket -> a row in the browser. It:

- Loads the 50 most recent events over `GET /api/events` on mount (`app/lib/events.ts`).
- Subscribes to `/ws/live` (`app/lib/useLiveFeed.ts`) and prepends new batched frames as they
  arrive, newest first.
- Caps the client buffer at ~500 rows, dropping from the tail — the invariant CLAUDE.md flags as
  unenforced until the dashboard existed.
- Auto-reconnects the WebSocket on close.

No TanStack Query, shadcn/ui, Recharts, or react-simple-maps yet — none of those are needed until a
later view (overview, map) pulls them in. Keep it that way until a view actually needs them.

## Running it

```sh
cp .env.local.example .env.local   # points at the api container; defaults to localhost:8000
npm install
npm run dev
```

Needs `make up` running so `st-api` (127.0.0.1:8000) and the decoys are reachable. `ST_CORS_ORIGINS`
on the `api` service already defaults to `http://localhost:3000`.

## Remaining views, in priority order

| # | View | Priority |
|---|------|----------|
| 1 | Live feed | **done** |
| 2 | Overview (KPIs, volume timeline, severity breakdown) | must |
| 3 | Attack map | must |
| 4 | Alert triage — this is also the labelling UI | must |
| 5 | Session replay (xterm.js, original keystroke timing) | high |
| 6 | IP profile | high |
| 7 | Campaigns | nice |
| 8 | Model health | nice |

Pre-bundle the TopoJSON for the map. No tile server, no runtime downloads — the map must render
with no internet.
