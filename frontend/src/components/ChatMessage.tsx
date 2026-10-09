import type { Msg } from "../hooks/useChat";
import { ShieldCheck } from "lucide-react";
import SecurityDetails from "./SecurityDetails";
import SecurityStatus from "./SecurityStatus";

export default function ChatMessage({ m }: { m: Msg }) {
  const user = m.role === "user";
  const r = m.response;
  const tone = user ? "bg-brand text-white ring-cyan-700 shadow-[0_12px_28px_rgba(8,39,58,0.14)]" : m.clientError || r?.status === "error" ? "surface-glass text-text ring-rose-300" : r?.status === "blocked" || r?.action === "redacted" ? "surface-glass text-text ring-amber-300" : "surface-glass text-text ring-edge shadow-[0_12px_28px_rgba(27,77,92,0.08)]";
  return (
    <div className={`flex items-end gap-3 ${user ? "justify-end" : "justify-start"}`}>
      {!user && <div className="mb-1 hidden size-8 shrink-0 place-items-center border border-edge bg-panel/75 text-accent sm:grid"><ShieldCheck size={17} /></div>}
      <article className={`max-w-[88%] rounded-lg px-4 py-3 ring-1 md:max-w-[75%] ${tone}`}>
        {r && r.status !== "completed" && (
          <p className={`mb-1 text-xs font-semibold ${r.status === "error" ? "text-status-error" : "text-status-warn"}`}>
            {r.status === "blocked" ? "Blocked by safety check" : r.status === "error" ? "Safety check error" : "Needs review"}
          </p>
        )}
        {r?.action === "redacted" && <p className="mb-1 text-xs font-semibold text-status-warn">Sensitive output redacted by gateway</p>}
        {m.clientError && <p className="mb-1 text-xs font-semibold text-status-error">Request failed</p>}
        {/* Plain text only: React escapes it, nothing is rendered as HTML. */}
        <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{m.text}</p>
        {r && (
          <div className="mt-3 space-y-1">
            <SecurityStatus r={r} />
            <SecurityDetails r={r} />
          </div>
        )}
      </article>
    </div>
  );
}
