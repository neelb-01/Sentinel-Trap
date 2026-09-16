import type { SentinelEvent } from "../lib/events";

const ACTION_TONE: Record<string, string> = {
  login_attempt: "text-amber-600 dark:text-amber-400",
  login_page_view: "text-zinc-500 dark:text-zinc-400",
  sensitive_file_probe: "text-red-600 dark:text-red-400",
  path_probe: "text-zinc-500 dark:text-zinc-400",
  search_query: "text-zinc-500 dark:text-zinc-400",
  connect: "text-emerald-600 dark:text-emerald-400",
  disconnect: "text-zinc-500 dark:text-zinc-400",
};

function summarizePayload(ev: SentinelEvent): string {
  const p = ev.payload ?? {};
  // sentinel-web: user/pass; cowrie: username/password
  const user = p.user ?? p.username;
  if (typeof user === "string") {
    const pass = p.pass ?? p.password;
    return `${user}${typeof pass === "string" && pass ? ` / ${pass}` : ""}`;
  }
  if (typeof p.input === "string") return p.input; // cowrie command
  if (typeof p.q === "string" && p.q) return `q=${p.q}`; // sentinel-web search term
  if (typeof p.path === "string") return p.path; // sentinel-web: present on every event
  return "";
}

export function EventRow({ event }: { event: SentinelEvent }) {
  const tone = ACTION_TONE[event.action] ?? "text-zinc-500 dark:text-zinc-400";
  const time = new Date(event.ts).toLocaleTimeString(undefined, {
    hour12: false,
    minute: "2-digit",
    hour: "2-digit",
    second: "2-digit",
  });

  return (
    <tr className="border-b border-zinc-100 dark:border-zinc-800 font-mono text-sm">
      <td className="py-1.5 pr-4 whitespace-nowrap text-zinc-400 dark:text-zinc-500">{time}</td>
      <td className="py-1.5 pr-4 whitespace-nowrap">{event.decoy}</td>
      <td className="py-1.5 pr-4 whitespace-nowrap">{event.src_ip}</td>
      <td className={`py-1.5 pr-4 whitespace-nowrap ${tone}`}>{event.action}</td>
      <td className="py-1.5 pr-4 truncate max-w-xs text-zinc-600 dark:text-zinc-300">
        {summarizePayload(event)}
      </td>
    </tr>
  );
}
