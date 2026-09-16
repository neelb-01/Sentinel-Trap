import type { Alert } from "../lib/alerts";

const STATUS_TONE: Record<Alert["status"], string> = {
  new: "text-amber-600 dark:text-amber-400",
  triaged: "text-blue-600 dark:text-blue-400",
  confirmed: "text-red-600 dark:text-red-400",
  false_positive: "text-zinc-400 dark:text-zinc-500",
};

function scoreTone(score: number): string {
  if (score >= 60) return "text-red-600 dark:text-red-400";
  if (score >= 40) return "text-amber-600 dark:text-amber-400";
  return "text-zinc-600 dark:text-zinc-300";
}

function formatTime(ts: string): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function AlertRow({
  alert,
  onAction,
  busy,
}: {
  alert: Alert;
  onAction: (status: "triaged" | "confirmed" | "false_positive") => void;
  busy: boolean;
}) {
  return (
    <tr className="border-b border-zinc-100 dark:border-zinc-800 text-sm align-top">
      <td className="py-2 pr-4 whitespace-nowrap text-zinc-400 dark:text-zinc-500 font-mono">
        {formatTime(alert.created_at)}
      </td>
      <td className="py-2 pr-4 whitespace-nowrap font-mono">{alert.src_ip}</td>
      <td className="py-2 pr-4 whitespace-nowrap">{alert.decoy}</td>
      <td className={`py-2 pr-4 whitespace-nowrap font-mono font-semibold ${scoreTone(alert.threat_score)}`}>
        {alert.threat_score.toFixed(0)}
      </td>
      <td className="py-2 pr-4 max-w-sm">{alert.reason}</td>
      <td className={`py-2 pr-4 whitespace-nowrap font-mono ${STATUS_TONE[alert.status]}`}>
        {alert.status}
      </td>
      <td className="py-2 pr-3 whitespace-nowrap">
        <div className="flex gap-1.5">
          {alert.status !== "confirmed" && (
            <button
              disabled={busy}
              onClick={() => onAction("confirmed")}
              className="rounded border border-red-200 dark:border-red-900 px-2 py-1 text-xs text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950 disabled:opacity-40"
            >
              Confirm
            </button>
          )}
          {alert.status !== "false_positive" && (
            <button
              disabled={busy}
              onClick={() => onAction("false_positive")}
              className="rounded border border-zinc-200 dark:border-zinc-700 px-2 py-1 text-xs text-zinc-500 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800 disabled:opacity-40"
            >
              False positive
            </button>
          )}
          {alert.status === "new" && (
            <button
              disabled={busy}
              onClick={() => onAction("triaged")}
              className="rounded border border-blue-200 dark:border-blue-900 px-2 py-1 text-xs text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-950 disabled:opacity-40"
            >
              Mark reviewed
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}
