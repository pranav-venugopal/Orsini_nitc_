import type { ChatResponse, Check } from "../types/api";

const fmt = (c: Check | null) => (c === null ? "Not run" : `${c.label}${c.categories.length ? ` (${c.categories.join(", ")})` : ""}`);

export default function SecurityDetails({ r }: { r: ChatResponse }) {
  return (
    <details className="mt-2 text-xs text-mute">
      <summary className="cursor-pointer select-none hover:text-text">Security details</summary>
      <dl className="mt-2 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1">
        <dt>Request ID</dt><dd className="break-all">{r.request_id}</dd>
        <dt>Mode</dt><dd>{r.mode}</dd>
        <dt>Status</dt><dd>{r.status}</dd>
        <dt>Action</dt><dd>{r.action}</dd>
        <dt>Input check</dt><dd>{fmt(r.input_check)}</dd>
        <dt>Output check</dt><dd>{fmt(r.output_check)}</dd>
        <dt>Latency</dt><dd>{r.latency_ms} ms</dd>
      </dl>
      <p className="mt-2">Labels are a classifier's judgment, not proof that content is completely safe.</p>
    </details>
  );
}
