# api — phase 2

FastAPI service: REST under `/api/*` for history, `/ws/live` for the real-time feed.

Not built yet. It lands in phase 2, alongside the first dashboard view.

Two constraints worth knowing before starting:

- **Batch the WebSocket** into ~250 ms server-side frames and cap the client buffer
  at ~500 rows, dropping from the tail. Pushing one frame per event freezes the
  browser the moment `attack-sim/` runs at full speed.
- **Bind to `127.0.0.1` only.** Reach it over an SSH tunnel; it is never published.

The models load in-process here — same Python runtime as the detection code, so
there is no separate model-serving hop.
