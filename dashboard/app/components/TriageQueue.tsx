"use client";

import { useCallback, useEffect, useState } from "react";
import { fetchAlerts, patchAlertStatus, type Alert } from "../lib/alerts";
import { AlertRow } from "./AlertRow";

const STATUS_FILTERS = ["new", "triaged", "confirmed", "false_positive", "all"] as const;

export function TriageQueue() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [filter, setFilter] = useState<(typeof STATUS_FILTERS)[number]>("new");
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await fetchAlerts(filter === "all" ? undefined : filter);
      setAlerts(rows);
    } catch {
      setError("Could not load alerts.");
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    // Deferred a microtask so the fetch's loading-state updates aren't
    // synchronous within the effect body itself (react-hooks/set-state-in-effect).
    void Promise.resolve().then(load);
  }, [load]);

  async function act(alertId: string, status: "triaged" | "confirmed" | "false_positive") {
    setBusyId(alertId);
    try {
      await patchAlertStatus(alertId, status);
      await load();
    } catch {
      setError("Could not update that alert.");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-2 pb-3 text-sm">
        {STATUS_FILTERS.map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`rounded px-2.5 py-1 text-xs font-mono ${
              filter === f
                ? "bg-zinc-900 text-zinc-50 dark:bg-zinc-100 dark:text-zinc-900"
                : "bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-400"
            }`}
          >
            {f}
          </button>
        ))}
        <span className="ml-auto text-zinc-400">
          {loading ? "loading…" : `${alerts.length} alert${alerts.length === 1 ? "" : "s"}`}
        </span>
      </div>

      {error && <p className="pb-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 bg-zinc-50 dark:bg-zinc-900 text-left text-xs uppercase tracking-wide text-zinc-400">
            <tr>
              <th className="py-2 pr-4 pl-3 font-medium">Time</th>
              <th className="py-2 pr-4 font-medium">Src IP</th>
              <th className="py-2 pr-4 font-medium">Decoy</th>
              <th className="py-2 pr-4 font-medium">Score</th>
              <th className="py-2 pr-4 font-medium">Reason</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-3 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <AlertRow key={a.alert_id} alert={a} busy={busyId === a.alert_id} onAction={(s) => act(a.alert_id, s)} />
            ))}
          </tbody>
        </table>
        {!loading && alerts.length === 0 && (
          <p className="p-4 text-sm text-zinc-400">No alerts in this queue.</p>
        )}
      </div>
    </div>
  );
}
