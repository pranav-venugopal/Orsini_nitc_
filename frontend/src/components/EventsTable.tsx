import { useState } from "react";
import type { SecurityEvent } from "../types/api";
import { motion, useReducedMotion } from "motion/react";
import { AlertTriangle, Eye, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import EventInspectorModal from "./EventInspectorModal";

const ICON: Record<string, string> = { safe: "✓", unsafe: "✕", error: "!" };

export default function EventsTable({ items }: { items: SecurityEvent[] }) {
  const reducedMotion = useReducedMotion() ?? false;
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  return (
    <>
      <div className="surface-glass overflow-x-auto rounded-[22px] border border-edge/55 shadow-sm">
        <table className="w-full min-w-[880px] text-left text-sm">
          <thead className="bg-table-head text-table-head-text">
            <tr>
              {[
                "Time (UTC)",
                "Request ID",
                "Stage",
                "User Prompt",
                "Classification",
                "Category",
                "Action",
                "Latency",
                "Inspection",
              ].map((h) => (
                <th key={h} scope="col" className="px-3.5 py-3 text-[10px] font-medium uppercase tracking-wider">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {items.map((e, index) => {
              const isBypassedInputBlockedOutput =
                e.stage === "output" && (e.action === "blocked_output" || e.label === "unsafe");

              return (
                <motion.tr
                  key={e.event_id}
                  initial={reducedMotion ? false : { opacity: 0, y: 7 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.2 }}
                  transition={{ duration: 0.36, delay: Math.min(index * 0.018, 0.18) }}
                  onClick={() => setSelectedEvent(e)}
                  className={`cursor-pointer border-t border-edge/65 transition-colors hover:bg-table-hover ${
                    isBypassedInputBlockedOutput ? "bg-rose-500/5 hover:bg-rose-500/10" : ""
                  }`}
                >
                  {/* Time */}
                  <td className="whitespace-nowrap px-3.5 py-3 text-xs text-mute">
                    {e.timestamp.replace("T", " ").slice(0, 19)}
                  </td>

                  {/* Request ID */}
                  <td className="px-3.5 py-3 font-mono text-xs text-text">
                    <span className="truncate" title={e.request_id}>
                      {e.request_id.slice(0, 14)}…
                    </span>
                  </td>

                  {/* Stage */}
                  <td className="px-3.5 py-3 text-xs">
                    <span
                      className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium uppercase ${
                        e.stage === "input"
                          ? "border border-cyan-500/30 bg-cyan-500/10 text-cyan-600 dark:text-cyan-400"
                          : e.stage === "tool"
                          ? "border border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400"
                          : e.stage === "context"
                          ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                          : "border border-purple-500/30 bg-purple-500/10 text-purple-600 dark:text-purple-400"
                      }`}
                    >
                      {e.stage}
                    </span>
                  </td>

                  {/* User Prompt snippet */}
                  <td className="max-w-[200px] px-3.5 py-3">
                    {e.user_prompt ? (
                      <p className="truncate font-mono text-xs text-text" title={e.user_prompt}>
                        {e.user_prompt}
                      </p>
                    ) : (
                      <span className="text-xs text-mute">—</span>
                    )}
                  </td>

                  {/* Classification */}
                  <td className="px-3.5 py-3">
                    <span
                      className={`inline-flex items-center gap-1 text-xs font-medium ${
                        e.label === "safe"
                          ? "text-emerald-500"
                          : e.label === "unsafe"
                          ? "text-rose-500"
                          : "text-amber-500"
                      }`}
                    >
                      {ICON[e.label] ?? "?"} {e.label}
                    </span>
                  </td>

                  {/* Categories */}
                  <td className="max-w-[140px] px-3.5 py-3 text-xs">
                    {e.categories.length ? (
                      <span className="truncate block" title={e.categories.join(", ")}>
                        {e.categories.join(", ")}
                      </span>
                    ) : (
                      <span className="text-mute">—</span>
                    )}
                  </td>

                  {/* Action */}
                  <td className="px-3.5 py-3 text-xs">
                    {isBypassedInputBlockedOutput ? (
                      <div className="flex flex-col gap-0.5">
                        <span className="font-semibold text-rose-500">{e.action}</span>
                        <span className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-400">
                          <AlertTriangle size={10} /> Intercepted AI
                        </span>
                      </div>
                    ) : e.action === "blocked_hallucination" ? (
                      <div className="flex flex-col gap-0.5">
                        <span className="font-semibold text-rose-400">{e.action}</span>
                        <span className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-400">
                          <ShieldAlert size={10} /> Factuality Guard
                        </span>
                      </div>
                    ) : e.action === "blocked_tool" ? (
                      <div className="flex flex-col gap-0.5">
                        <span className="font-semibold text-rose-400">{e.action}</span>
                        <span className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-400">
                          <ShieldAlert size={10} /> Tool Blocked
                        </span>
                      </div>
                    ) : e.action === "review_required" ? (
                      <div className="flex flex-col gap-0.5">
                        <span className="font-semibold text-amber-400">{e.action}</span>
                        <span className="inline-flex items-center gap-1 rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-400">
                          <AlertTriangle size={10} /> Approval Needed
                        </span>
                      </div>
                    ) : (
                      <span className="font-medium">{e.action}</span>
                    )}
                  </td>

                  {/* Latency */}
                  <td className="whitespace-nowrap px-3.5 py-3 text-xs text-mute">
                    {e.latency_ms} ms
                  </td>

                  {/* Inspect Action */}
                  <td className="whitespace-nowrap px-3.5 py-3 text-xs">
                    <button
                      type="button"
                      onClick={(evt) => {
                        evt.stopPropagation();
                        setSelectedEvent(e);
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-edge/80 bg-panel/80 px-2.5 py-1 text-xs font-medium text-mute transition-colors hover:border-cyan-600 hover:text-text hover:shadow-sm"
                      title="Inspect user prompt and model response"
                    >
                      <Eye size={13} />
                      Inspect
                    </button>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Forensic Inspector Modal */}
      {selectedEvent && (
        <EventInspectorModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </>
  );
}
