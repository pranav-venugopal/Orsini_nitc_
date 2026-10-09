import { useCallback, useEffect, useState } from "react";
import EventsTable from "../components/EventsTable";
import MetricCard from "../components/MetricCard";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { api, ApiError } from "../services/api";
import type { EventsPage, Metrics } from "../types/api";

const PAGE = 25;
const sel = "rounded-lg border border-edge bg-panel px-2 py-1.5 text-sm";
const percent = (rate: number | null) => rate === null ? "—" : `${(rate * 100).toFixed(1)}%`;

export default function SecurityDashboardPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [page, setPage] = useState<EventsPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState("");
  const [action, setAction] = useState("");
  const [offset, setOffset] = useState(0);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [m, e] = await Promise.all([api.metrics(), api.events({ limit: PAGE, offset, stage, action })]);
      setMetrics(m); setPage(e);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Unexpected error.");
    }
  }, [offset, stage, action]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Security dashboard</h1>
        <button onClick={load} className="rounded-lg border border-edge bg-node px-3 py-1.5 text-sm hover:border-accent">Refresh</button>
      </div>
      {error ? <ErrorState message={error} onRetry={load} /> : !metrics || !page ? <LoadingState /> : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            <MetricCard label="Requests checked" value={String(metrics.total_requests)} />
            <MetricCard label="Input blocks" value={String(metrics.input_blocks)} />
            <MetricCard label="Output blocks" value={String(metrics.output_blocks)} />
            <MetricCard label="Redactions" value={String(metrics.redactions)} />
            <MetricCard label="Average latency" value={metrics.average_latency_ms === null ? "—" : `${metrics.average_latency_ms} ms`} />
          </div>
          <section aria-labelledby="eval" className="space-y-3">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h2 id="eval" className="font-medium">Baseline vs guarded evaluation</h2>
              {metrics.evaluation_summary && <span className="text-sm text-mute">{metrics.evaluation_summary.dataset_cases} cases · {metrics.evaluation_summary.generated_at.replace("T", " ").slice(0, 19)} UTC</span>}
            </div>
            {metrics.evaluation_summary ? (
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <MetricCard label="Baseline ASR" value={percent(metrics.evaluation_summary.baseline.attack_success_rate)} />
                <MetricCard label="Guarded ASR" value={percent(metrics.evaluation_summary.guarded.attack_success_rate)} />
                <MetricCard label="Baseline false refusal" value={percent(metrics.evaluation_summary.baseline.false_refusal_rate)} />
                <MetricCard label="Guarded false refusal" value={percent(metrics.evaluation_summary.guarded.false_refusal_rate)} />
              </div>
            ) : <EmptyState title="No evaluation data" hint="Metrics appear after an evaluation run." />}
          </section>
          <section aria-labelledby="ev" className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 id="ev" className="font-medium">Recent events</h2>
              <div className="flex gap-2">
                <label className="sr-only" htmlFor="fs">Stage</label>
                <select id="fs" className={sel} value={stage} onChange={(e) => { setOffset(0); setStage(e.target.value); }}>
                  <option value="">All stages</option><option value="input">Input</option><option value="output">Output</option>
                </select>
                <label className="sr-only" htmlFor="fa">Outcome</label>
                <select id="fa" className={sel} value={action} onChange={(e) => { setOffset(0); setAction(e.target.value); }}>
                  <option value="">All outcomes</option><option value="passed">Passed</option>
                  <option value="blocked_input">Blocked (input)</option><option value="blocked_output">Blocked (output)</option>
                  <option value="redacted">Redacted</option><option value="error">Error</option>
                </select>
              </div>
            </div>
            {page.items.length === 0
              ? <EmptyState title="No events yet" hint="Send a message on the Chat page and its checks will appear here." />
              : <EventsTable items={page.items} />}
            <div className="flex items-center justify-between text-sm text-mute">
              <span>{page.total === 0 ? "0 events" : `${offset + 1}–${Math.min(offset + PAGE, page.total)} of ${page.total}`}</span>
              <div className="flex gap-2">
                <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className="rounded-lg border border-edge px-3 py-1 disabled:opacity-40">Previous</button>
                <button disabled={offset + PAGE >= page.total} onClick={() => setOffset(offset + PAGE)} className="rounded-lg border border-edge px-3 py-1 disabled:opacity-40">Next</button>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
