export type Alert = {
  alert_id: string;
  session_id: string;
  created_at: string;
  threat_score: number;
  predicted_class: string | null;
  confidence: number | null;
  anomaly_score: number | null;
  triggered_rules: string[];
  reason: string | null;
  status: "new" | "triaged" | "confirmed" | "false_positive";
  src_ip: string;
  decoy: string;
  started_at: string;
  ended_at: string | null;
  event_count: number;
};

type AlertsResponse = {
  alerts: Alert[];
  next_cursor: { before_ts: string; before_id: string } | null;
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export async function fetchAlerts(status?: string): Promise<Alert[]> {
  const url = new URL(`${API_BASE}/api/alerts`);
  url.searchParams.set("limit", "100");
  if (status) url.searchParams.set("status", status);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET /api/alerts failed: ${res.status}`);
  const body = (await res.json()) as AlertsResponse;
  return body.alerts;
}

export async function patchAlertStatus(
  alertId: string,
  status: "triaged" | "confirmed" | "false_positive"
): Promise<void> {
  const res = await fetch(`${API_BASE}/api/alerts/${alertId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error(`PATCH /api/alerts/${alertId} failed: ${res.status}`);
}
