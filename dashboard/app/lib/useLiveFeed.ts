"use client";

import { useEffect, useState } from "react";
import { fetchRecentEvents, liveFeedUrl, type SentinelEvent } from "./events";

// Cap the buffer at ~500 rows, dropping from the tail (oldest) — see
// CLAUDE.md's WebSocket batching invariant. Newest event is index 0.
const MAX_ROWS = 500;
const RECONNECT_DELAY_MS = 2000;

export type ConnectionStatus = "connecting" | "open" | "closed";

type WireFrame = { type: "events"; data: SentinelEvent[] };

export function useLiveFeed() {
  const [events, setEvents] = useState<SentinelEvent[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");

  // incoming must be oldest-first (matches the order WS batches arrive in);
  // REST replies newest-first, so callers reverse that before passing it in.
  // Dedupes purely against `prev` (no outside ref) — React 19 Strict Mode
  // double-invokes setState updaters in dev, so a ref mutated inside here
  // would look like everything's a duplicate on the second call.
  function addEvents(incoming: SentinelEvent[]) {
    if (incoming.length === 0) return;
    setEvents((prev) => {
      const seen = new Set(prev.map((e) => e.event_id));
      const fresh = incoming.filter((e) => !seen.has(e.event_id));
      if (fresh.length === 0) return prev;
      return [...fresh.slice().reverse(), ...prev].slice(0, MAX_ROWS);
    });
  }

  useEffect(() => {
    let cancelled = false;
    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    fetchRecentEvents(50)
      .then((initial) => {
        // REST replies newest-first; addEvents wants oldest-first.
        if (!cancelled) addEvents(initial.slice().reverse());
      })
      .catch((err) => console.error("initial fetch failed", err));

    function connect() {
      setStatus("connecting");
      ws = new WebSocket(liveFeedUrl());

      ws.onopen = () => setStatus("open");

      ws.onmessage = (msg) => {
        const frame = JSON.parse(msg.data as string) as WireFrame;
        if (frame.type === "events") addEvents(frame.data);
      };

      ws.onclose = () => {
        setStatus("closed");
        if (!cancelled) reconnectTimer = setTimeout(connect, RECONNECT_DELAY_MS);
      };

      ws.onerror = () => ws?.close();
    }

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, []);

  return { events, status };
}
