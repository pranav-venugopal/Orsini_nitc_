import type { SecurityEvent } from "../types/api";
import { motion, useReducedMotion } from "motion/react";

const ICON: Record<string, string> = { safe: "✓", unsafe: "✕", error: "!" };

export default function EventsTable({ items }: { items: SecurityEvent[] }) {
  const reducedMotion = useReducedMotion() ?? false;
  return (
    <div className="surface-glass overflow-x-auto rounded-[22px] border border-edge/55">
      <table className="w-full min-w-[720px] text-left text-sm">
        <thead className="bg-table-head text-table-head-text">
          <tr>{["Time (UTC)", "Request ID", "Stage", "Classification", "Category", "Action", "Latency"].map((h) => (
            <th key={h} scope="col" className="px-3 py-3 text-[10px] font-medium uppercase">{h}</th>))}</tr>
        </thead>
        <tbody>
          {items.map((e, index) => (
            <motion.tr
              key={e.event_id}
              initial={reducedMotion ? false : { opacity: 0, y: 7 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.2 }}
              transition={{ duration: 0.36, delay: Math.min(index * 0.018, 0.18) }}
              className="border-t border-edge/65 transition-colors hover:bg-table-hover"
            >
              <td className="whitespace-nowrap px-3 py-3 text-xs text-mute">{e.timestamp.replace("T", " ").slice(0, 19)}</td>
              <td className="px-3 py-3 font-mono text-xs text-text">{e.request_id}</td>
              <td className="px-3 py-3 text-xs uppercase">{e.stage}</td>
              <td className="px-3 py-3">{ICON[e.label] ?? "?"} {e.label}</td>
              <td className="px-3 py-3 text-xs">{e.categories.length ? e.categories.join(", ") : "—"}</td>
              <td className="px-3 py-3 text-xs font-medium">{e.action}</td>
              <td className="px-3 py-3 text-xs">{e.latency_ms} ms</td>
            </motion.tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
