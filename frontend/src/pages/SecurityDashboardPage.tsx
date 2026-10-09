import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, RefreshCw } from "lucide-react";
import EventsTable from "../components/EventsTable";
import MetricCard from "../components/MetricCard";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { api, ApiError } from "../services/api";
import type { EventsPage, Metrics } from "../types/api";

const PAGE = 25;
const CyberHeadScene = lazy(() => import("../components/CyberHeadScene"));
const sel = "rounded-xl border border-edge/70 bg-panel/65 px-4 py-2.5 text-sm text-text shadow-sm outline-none backdrop-blur-lg transition-colors focus:border-cyan-600";
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
    <div className="page-enter mx-auto max-w-6xl space-y-8 px-4 py-6 md:px-8 md:py-9">
      <div className="grid gap-4 border-b border-edge pb-5 lg:grid-cols-[minmax(0,0.88fr)_minmax(0,1.12fr)] lg:items-center">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="mb-2 text-[10px] uppercase text-mute">Live telemetry / policy outcomes</p>
            <h1 className="font-display text-5xl uppercase leading-none text-text md:text-6xl">Security monitor</h1>
          </div>
          <button onClick={load} className="inline-flex h-11 items-center gap-2 rounded-full bg-brand px-5 text-sm font-medium text-white shadow-lg shadow-cyan-950/15 hover:bg-brand-hover"><RefreshCw size={15} /> Refresh</button>
        </div>
        <Suspense fallback={<div className="cyber-scene h-[220px] w-full sm:h-[250px] md:h-[300px]"><img src="/HEAD.jpg" alt="" className="size-full object-cover object-[55%_42%]" /></div>}>
          <CyberHeadScene className="h-[220px] sm:h-[250px] md:h-[300px]" />
        </Suspense>
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
          <section aria-labelledby="eval" className="space-y-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-l-2 border-cyan-500 pl-3">
              <h2 id="eval" className="font-display text-3xl uppercase text-text">Baseline vs guarded evaluation</h2>
              {metrics.evaluation_summary && <span className="text-xs text-mute">{metrics.evaluation_summary.dataset_cases} cases · {metrics.evaluation_summary.generated_at.replace("T", " ").slice(0, 19)} UTC</span>}
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
          <section aria-labelledby="ev" className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 id="ev" className="border-l-2 border-cyan-500 pl-3 font-display text-3xl uppercase text-text">Recent events</h2>
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
              <div className="flex gap-1">
                <button aria-label="Previous page" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))} className="grid size-9 place-items-center border border-edge bg-panel/75 text-text hover:border-cyan-600 disabled:opacity-40"><ChevronLeft size={17} /></button>
                <button aria-label="Next page" disabled={offset + PAGE >= page.total} onClick={() => setOffset(offset + PAGE)} className="grid size-9 place-items-center border border-edge bg-panel/75 text-text hover:border-cyan-600 disabled:opacity-40"><ChevronRight size={17} /></button>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
