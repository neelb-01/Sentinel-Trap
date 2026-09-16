"use client";

import { useLiveFeed } from "../lib/useLiveFeed";
import { EventRow } from "./EventRow";

const STATUS_LABEL: Record<string, string> = {
  connecting: "connecting…",
  open: "live",
  closed: "reconnecting…",
};

const STATUS_DOT: Record<string, string> = {
  connecting: "bg-amber-400",
  open: "bg-emerald-500",
  closed: "bg-red-500",
};

export function LiveFeed() {
  const { events, status } = useLiveFeed();

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-2 pb-3 text-sm text-zinc-500 dark:text-zinc-400">
        <span className={`inline-block h-2 w-2 rounded-full ${STATUS_DOT[status]}`} />
        {STATUS_LABEL[status]}
        <span className="ml-auto">{events.length} event{events.length === 1 ? "" : "s"}</span>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 bg-zinc-50 dark:bg-zinc-900 text-left text-xs uppercase tracking-wide text-zinc-400">
            <tr>
              <th className="py-2 pr-4 pl-3 font-medium">Time</th>
              <th className="py-2 pr-4 font-medium">Decoy</th>
              <th className="py-2 pr-4 font-medium">Src IP</th>
              <th className="py-2 pr-4 font-medium">Action</th>
              <th className="py-2 pr-4 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody className="pl-3">
            {events.map((ev) => (
              <EventRow key={ev.event_id} event={ev} />
            ))}
          </tbody>
        </table>
        {events.length === 0 && (
          <p className="p-4 text-sm text-zinc-400">Waiting for events…</p>
        )}
      </div>
    </div>
  );
}
