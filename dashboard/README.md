# dashboard — phase 2

Next.js + React, TypeScript, Tailwind, shadcn/ui, Recharts, react-simple-maps.
TanStack Query for REST, native WebSocket for the live feed.

Not built yet. Scaffold it at the start of phase 2:

```sh
npx create-next-app@latest . --typescript --tailwind --app --eslint
```

**Build the live feed first** — not the login page, not a settings screen. Get one
event flowing decoy -> Redis -> Postgres -> WebSocket -> a line of text in the
browser. Every other view is a variation on a path already proved.

Eight views, in priority order:

| # | View | Priority |
|---|------|----------|
| 1 | Live feed | must |
| 2 | Overview (KPIs, volume timeline, severity breakdown) | must |
| 3 | Attack map | must |
| 4 | Alert triage — this is also the labelling UI | must |
| 5 | Session replay (xterm.js, original keystroke timing) | high |
| 6 | IP profile | high |
| 7 | Campaigns | nice |
| 8 | Model health | nice |

Pre-bundle the TopoJSON for the map. No tile server, no runtime downloads — the
map must render with no internet.
