import type { Msg } from "../hooks/useChat";
import { ShieldCheck } from "lucide-react";
import SecurityDetails from "./SecurityDetails";
import SecurityStatus from "./SecurityStatus";

export default function ChatMessage({ m, isAdmin = false }: { m: Msg; isAdmin?: boolean }) {
  const user = m.role === "user";
  const r = m.response;
  const tone = user ? "bg-brand text-white ring-cyan-700 shadow-[0_12px_28px_rgba(8,39,58,0.14)]" : m.clientError || r?.status === "error" ? "surface-glass text-text ring-rose-300" : r?.status === "blocked" || r?.action === "redacted" ? "surface-glass text-text ring-amber-300" : "surface-glass text-text ring-edge shadow-[0_12px_28px_rgba(27,77,92,0.08)]";
  return (
    <div className={`flex items-end gap-3 ${user ? "justify-end" : "justify-start"}`}>
      {!user && <div className="brand-mark mb-1 hidden size-8 shrink-0 place-items-center rounded-xl sm:grid"><ShieldCheck size={16} /></div>}
      <article className={`max-w-[92%] rounded-[22px] px-4 py-3.5 ring-1 sm:max-w-[88%] md:max-w-[78%] ${tone}`}>
        {r && r.status !== "completed" && isAdmin && (
          <p className={`mb-1 text-xs font-semibold ${r.status === "error" ? "text-status-error" : "text-status-warn"}`}>
            {r.status === "blocked" ? "Blocked by safety check" : r.status === "error" ? "Safety check error" : "Needs review"}
          </p>
        )}
        {r?.action === "redacted" && isAdmin && <p className="mb-1 text-xs font-semibold text-status-warn">Sensitive output redacted by gateway</p>}
        {r?.low_confidence && isAdmin && (
          <div className="mb-1.5 inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-xs font-medium text-amber-300">
            <span className="size-1.5 rounded-full bg-amber-400 animate-pulse" />
            <span>Low confidence</span>
            {r.unsupported_claims && r.unsupported_claims.length > 0 && (
              <span className="text-[10px] text-amber-300/80">({r.unsupported_claims.length} unverified)</span>
            )}
          </div>
        )}
        {m.clientError && <p className="mb-1 text-xs font-semibold text-status-error">Request failed</p>}
        {/* Plain text only: React escapes it, nothing is rendered as HTML. */}
        <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">{m.text}</p>
        {r && isAdmin && (
          <div className="mt-3 space-y-1">
            <SecurityStatus r={r} />
            <SecurityDetails r={r} />
          </div>
        )}
      </article>
    </div>
  );
}
