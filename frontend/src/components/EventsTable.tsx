import type { SecurityEvent } from "../types/api";

const ICON: Record<string, string> = { safe: "✓", unsafe: "✕", error: "!" };

export default function EventsTable({ items }: { items: SecurityEvent[] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-edge">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-node text-mute">
          <tr>{["Time (UTC)", "Request ID", "Stage", "Classification", "Category", "Action", "Latency"].map((h) => (
            <th key={h} scope="col" className="px-3 py-2 font-medium">{h}</th>))}</tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.event_id} className="border-t border-edge">
              <td className="px-3 py-2 whitespace-nowrap">{e.timestamp.replace("T", " ").slice(0, 19)}</td>
              <td className="px-3 py-2 font-mono text-xs">{e.request_id}</td>
              <td className="px-3 py-2">{e.stage}</td>
              <td className="px-3 py-2">{ICON[e.label] ?? "?"} {e.label}</td>
              <td className="px-3 py-2">{e.categories.length ? e.categories.join(", ") : "—"}</td>
              <td className="px-3 py-2">{e.action}</td>
              <td className="px-3 py-2">{e.latency_ms} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
