import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { Activity, ChevronLeft, ChevronRight, RefreshCw, ShieldAlert } from "lucide-react";
import { useOutletContext } from "react-router-dom";
import EventsTable from "../components/EventsTable";
import MetricCard from "../components/MetricCard";
import RobustnessTab from "../components/RobustnessTab";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import { api, ApiError } from "../services/api";
import type { EventsPage, Metrics, ModelDiagnostics, RuntimeDiagnostics, SessionUser } from "../types/api";

const PAGE = 25;
const SectionScene = lazy(() => import("../components/SectionScene"));
const sel = "rounded-xl border border-edge/70 bg-panel/65 px-4 py-2.5 text-sm text-text shadow-sm outline-none backdrop-blur-lg transition-colors focus:border-cyan-600";
const percent = (rate: number | null) => rate === null ? "—" : `${(rate * 100).toFixed(1)}%`;

function ModelStatus({ title, model }: { title: string; model: RuntimeDiagnostics }) {
  const placement = model.device_map
    ? Object.entries(model.device_map).map(([name, device]) => `${name}: ${device}`).join(", ")
    : "Not loaded yet";
  return (
    <div className="min-w-0 rounded-2xl border border-edge/70 bg-panel/60 p-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-medium text-text">{title}</h3>
        <span className={model.loaded ? "text-xs text-emerald-500" : "text-xs text-mute"}>
          {model.loaded ? "Loaded" : "Not loaded"}
        </span>
      </div>
      <p className="mt-2 break-all text-xs text-mute">{model.model_id}</p>
      <p className="mt-2 break-words text-xs text-mute">{placement}</p>
      {model.dtype && <p className="mt-1 text-xs text-mute">Data type: {model.dtype}</p>}
      {model.last_error && <p className="mt-2 text-xs text-amber-500">Last load error: {model.last_error}</p>}
    </div>
  );
}

export default function SecurityDashboardPage() {
  const { user } = useOutletContext<{ user?: SessionUser }>() ?? {};
  const isAdmin = user?.role === "admin";
  const [activeTab, setActiveTab] = useState<"telemetry" | "robustness">("telemetry");

  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [page, setPage] = useState<EventsPage | null>(null);
  const [diagnostics, setDiagnostics] = useState<ModelDiagnostics | null>(null);
  const [diagnosticsError, setDiagnosticsError] = useState<string | null>(null);
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

  const loadDiagnostics = useCallback(async () => {
    setDiagnosticsError(null);
    try {
      setDiagnostics(await api.modelDiagnostics());
    } catch (err) {
      setDiagnosticsError(err instanceof ApiError ? err.message : "Unable to load model diagnostics.");
    }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadDiagnostics(); }, [loadDiagnostics]);

  return (
    <div className="page-enter mx-auto max-w-6xl space-y-8 px-4 py-6 md:px-8 md:py-9">
      <div className="grid gap-4 border-b border-edge pb-5 lg:grid-cols-[minmax(0,0.88fr)_minmax(0,1.12fr)] lg:items-center">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="mb-2 text-[10px] uppercase text-mute">Live telemetry / policy outcomes</p>
            <h1 className="display-title font-display text-5xl uppercase leading-[1.02] text-text md:text-6xl">Security monitor</h1>
          </div>
          <button onClick={() => { load(); loadDiagnostics(); }} className="inline-flex h-11 items-center gap-2 rounded-full bg-brand px-5 text-sm font-medium text-white shadow-lg shadow-cyan-950/15 hover:bg-brand-hover"><RefreshCw size={15} /> Refresh</button>
        </div>
        <Suspense fallback={<div className="section-scene section-scene-monitor h-[190px] w-full rounded-[28px] sm:h-[220px] md:h-[270px]" />}>
          <SectionScene mode="monitor" />
        </Suspense>
      </div>

      {isAdmin && (
        <div className="flex items-center gap-2 border-b border-edge/60 pb-1">
          <button
            type="button"
            onClick={() => setActiveTab("telemetry")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-medium transition-all ${
              activeTab === "telemetry"
                ? "bg-accent/15 text-accent border border-accent/30 shadow-sm"
                : "text-mute hover:bg-panel/60 hover:text-text"
            }`}
          >
            <Activity size={15} />
            <span>Telemetry & Events</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("robustness")}
            className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-medium transition-all ${
              activeTab === "robustness"
                ? "bg-accent/15 text-accent border border-accent/30 shadow-sm"
                : "text-mute hover:bg-panel/60 hover:text-text"
            }`}
          >
            <ShieldAlert size={15} />
            <span>Robustness</span>
            <span className="rounded bg-accent/20 px-1.5 py-0.5 text-[9px] font-mono text-accent">Metamorphic</span>
          </button>
        </div>
      )}

      {activeTab === "robustness" && isAdmin ? (
        <RobustnessTab />
      ) : (
        <>
          {diagnosticsError && <p role="alert" className="rounded-2xl border border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-500">Model diagnostics unavailable: {diagnosticsError}</p>}
          {diagnostics?.model_mode === "local" && !diagnosticsError && (
              <section aria-labelledby="model-diagnostics" className="rounded-[26px] border border-edge/70 bg-panel/65 p-5 shadow-lg shadow-slate-950/5 backdrop-blur-xl">
                <div className="flex flex-wrap items-baseline justify-between gap-3">
                  <div>
                    <p className="text-[10px] uppercase text-mute">Local inference</p>
                    <h2 id="model-diagnostics" className="mt-1 font-display text-2xl uppercase text-text">Model diagnostics</h2>
                  </div>
                  <span className="rounded-full border border-edge px-3 py-1 text-xs text-mute">
                    {diagnostics.cuda_available
                      ? `CUDA · ${diagnostics.gpu_name ?? "GPU"}`
                      : diagnostics.cuda_available === false ? "CPU inference" : "Runtime unavailable"}
                  </span>
                </div>
                {!diagnostics.runtime_available && diagnostics.runtime_message && (
                  <p className="mt-4 text-sm text-amber-500">{diagnostics.runtime_message}</p>
                )}
                {diagnostics.cuda_available && (
                  <p className="mt-3 text-xs text-mute">
                    GPU memory: {diagnostics.gpu_memory_allocated_gib ?? "—"} GiB allocated · {diagnostics.gpu_memory_reserved_gib ?? "—"} GiB reserved
                  </p>
                )}
                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  <ModelStatus title="Answer model" model={diagnostics.generator} />
                  <ModelStatus title="Safety model" model={diagnostics.guard} />
                </div>
              </section>
            )}
            {error ? <ErrorState message={error} onRetry={load} /> : !metrics || !page ? <LoadingState /> : (
            <>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
                <MetricCard label="Requests checked" value={String(metrics.total_requests)} />
                <MetricCard label="Input blocks" value={String(metrics.input_blocks)} />
                <MetricCard label="Output blocks" value={String(metrics.output_blocks)} />
                <MetricCard label="Redactions" value={String(metrics.redactions)} />
                <MetricCard label="Average latency" value={metrics.average_latency_ms === null ? "—" : `${metrics.average_latency_ms} ms`} />
              </div>

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
        </>
      )}
    </div>
  );
}
