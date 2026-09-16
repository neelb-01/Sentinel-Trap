export type SentinelEvent = {
  event_id: string;
  ts: string;
  decoy: string;
  protocol: string;
  src_ip: string;
  src_port: number | null;
  dst_port: number | null;
  action: string;
  payload: Record<string, unknown>;
  session_id: string | null;
};

type EventsResponse = {
  events: SentinelEvent[];
  next_cursor: { before_ts: string; before_id: string } | null;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export async function fetchRecentEvents(limit = 50): Promise<SentinelEvent[]> {
  const res = await fetch(`${API_BASE}/api/events?limit=${limit}`);
  if (!res.ok) throw new Error(`GET /api/events failed: ${res.status}`);
  const body = (await res.json()) as EventsResponse;
  return body.events;
}

export function liveFeedUrl(): string {
  const url = new URL(API_BASE);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/ws/live";
  return url.toString();
}
