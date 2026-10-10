import type { ChatResponse, Check } from "../types/api";

const fmt = (c: Check | null) => (c === null ? "Not run" : `${c.label}${c.categories.length ? ` (${c.categories.join(", ")})` : ""}`);

export default function SecurityDetails({ r }: { r: ChatResponse }) {
  return (
    <details className="mt-3 border-t border-current/10 pt-2 text-xs text-current/65">
      <summary className="cursor-pointer select-none font-medium hover:text-cyan-800">Security details</summary>
      <dl className="mt-2 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1">
        <dt>Request ID</dt><dd className="break-all">{r.request_id}</dd>
        <dt>Mode</dt><dd>{r.mode}</dd>
        <dt>Status</dt><dd>{r.status}</dd>
        <dt>Action</dt><dd>{r.action}</dd>
        <dt>Input check</dt><dd>{fmt(r.input_check)}</dd>
        <dt>Output check</dt><dd>{fmt(r.output_check)}</dd>
        <dt>Factuality guard</dt>
        <dd>
          {r.action === "blocked_hallucination" ? (
            <span className="font-semibold text-rose-400">Blocked (Contradiction detected)</span>
          ) : r.low_confidence ? (
            <span className="font-semibold text-amber-400">Low confidence (Ungrounded claims)</span>
          ) : r.check_skipped ? (
            <span>Skipped</span>
          ) : (
            <span className="text-emerald-400">Verified & Grounded</span>
          )}
        </dd>
        {r.unsupported_claims && r.unsupported_claims.length > 0 && (
          <>
            <dt>Unverified claims</dt>
            <dd>
              <ul className="list-disc pl-4 space-y-0.5 text-[11px] text-amber-300/90">
                {r.unsupported_claims.map((claim, i) => (
                  <li key={i}>{claim}</li>
                ))}
              </ul>
            </dd>
          </>
        )}
        {r.dropped_context && r.dropped_context.length > 0 && (
          <>
            <dt>Indirect injection</dt>
            <dd className="font-semibold text-rose-400">
              {r.dropped_context.length} hostile document(s) neutralized and dropped
            </dd>
          </>
        )}
        <dt>Latency</dt><dd>{r.latency_ms} ms</dd>
      </dl>
      <p className="mt-2 text-[11px]">Guards enforce prompt injection, canary leakage, hallucination checks, and tool safety.</p>
    </details>
  );
}
