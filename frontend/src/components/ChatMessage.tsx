import type { Msg } from "../hooks/useChat";
import SecurityDetails from "./SecurityDetails";
import SecurityStatus from "./SecurityStatus";

export default function ChatMessage({ m }: { m: Msg }) {
  const user = m.role === "user";
  const r = m.response;
  const tone = user ? "bg-node ring-edge" : m.clientError || r?.status === "error" ? "bg-panel ring-amber-400/50" : r?.status === "blocked" ? "bg-panel ring-amber-400/30" : r?.action === "redacted" ? "bg-panel ring-amber-400/30" : "bg-panel ring-edge";
  return (
    <div className={`flex ${user ? "justify-end" : "justify-start"}`}>
      <article className={`max-w-[88%] rounded-2xl px-4 py-3 ring-1 md:max-w-[75%] ${tone}`}>
        {r && r.status !== "completed" && (
          <p className="mb-1 text-xs font-medium text-amber-200">
            {r.status === "blocked" ? "✕ Blocked by safety check" : r.status === "error" ? "! Safety check error" : "Needs review"}
          </p>
        )}
        {r?.action === "redacted" && <p className="mb-1 text-xs font-medium text-amber-200">Sensitive output redacted by gateway</p>}
        {m.clientError && <p className="mb-1 text-xs font-medium text-amber-200">! Request failed</p>}
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
