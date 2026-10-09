import type { SecurityEvent } from "../types/api";

const ICON: Record<string, string> = { safe: "✓", unsafe: "✕", error: "!" };

export default function EventsTable({ items }: { items: SecurityEvent[] }) {
  return (
    <div className="overflow-x-auto border border-edge bg-panel/75 shadow-[0_8px_24px_rgba(15,65,78,0.045)]">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-table-head text-table-head-text">
          <tr>{["Time (UTC)", "Request ID", "Stage", "Classification", "Category", "Action", "Latency"].map((h) => (
            <th key={h} scope="col" className="px-3 py-3 text-[10px] font-medium uppercase">{h}</th>))}</tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.event_id} className="border-t border-edge/80 transition-colors hover:bg-table-hover">
              <td className="whitespace-nowrap px-3 py-3 text-xs text-mute">{e.timestamp.replace("T", " ").slice(0, 19)}</td>
              <td className="px-3 py-3 font-mono text-xs text-text">{e.request_id}</td>
              <td className="px-3 py-3 text-xs uppercase">{e.stage}</td>
              <td className="px-3 py-3">{ICON[e.label] ?? "?"} {e.label}</td>
              <td className="px-3 py-3 text-xs">{e.categories.length ? e.categories.join(", ") : "—"}</td>
              <td className="px-3 py-3 text-xs font-medium">{e.action}</td>
              <td className="px-3 py-3 text-xs">{e.latency_ms} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
