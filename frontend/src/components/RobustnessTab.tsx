import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle, ChevronRight, Play, ShieldAlert, Sparkles } from "lucide-react";
import MetricCard from "./MetricCard";
import { EmptyState, ErrorState, LoadingState } from "./States";
import { api, ApiError } from "../services/api";
import type { MetamorphicPreviewItem, MetamorphicResults } from "../types/api";

function getBarColor(pct: number): string {
  if (pct >= 95) return "bg-emerald-500";
  if (pct >= 85) return "bg-cyan-500";
  if (pct >= 70) return "bg-amber-500";
  return "bg-rose-500";
}

function getDecisionBadge(decision: string) {
  const d = decision.toUpperCase();
  if (d === "BLOCK") {
    return <span className="inline-flex items-center rounded-full bg-rose-500/15 px-2.5 py-0.5 text-[11px] font-medium text-rose-400 border border-rose-500/30">BLOCK</span>;
  }
  if (d === "ALLOW") {
    return <span className="inline-flex items-center rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-[11px] font-medium text-emerald-400 border border-emerald-500/30">ALLOW</span>;
  }
  if (d === "REVIEW") {
    return <span className="inline-flex items-center rounded-full bg-amber-500/15 px-2.5 py-0.5 text-[11px] font-medium text-amber-400 border border-amber-500/30">REVIEW</span>;
  }
  return <span className="inline-flex items-center rounded-full bg-slate-500/15 px-2.5 py-0.5 text-[11px] font-medium text-slate-400 border border-slate-500/30">{d}</span>;
}

export default function RobustnessTab() {
  const [data, setData] = useState<MetamorphicResults | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Optional "Try it" preview interactive state
  const [testPrompt, setTestPrompt] = useState("");
  const [previewItems, setPreviewItems] = useState<MetamorphicPreviewItem[] | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.metamorphicResults();
      setData(res);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load metamorphic results.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handlePreviewSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testPrompt.trim() || testPrompt.length > 500) return;
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const res = await api.metamorphicPreview(testPrompt.trim());
      setPreviewItems(res.items);
    } catch (err) {
      setPreviewError(err instanceof ApiError ? err.message : "Failed to preview metamorphic decisions.");
    } finally {
      setPreviewLoading(false);
    }
  };

  if (loading) return <LoadingState />;
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!data) return <EmptyState title="No robustness data" hint="Run the metamorphic evaluation suite to see results." />;

  // Sort families weakest first (ascending robustness %)
  const families = [...(data.attack?.by_family ?? [])].sort((a, b) => a.robustness_pct - b.robustness_pct);

  // Known gaps: families below 100%
  const knownGaps = families.filter((f) => f.robustness_pct < 100);

  // Check if before/after comparison is present in the data
  const hasBeforeAfter = Boolean(
    (data.before_after && data.before_after.length > 0) ||
    data.attack?.by_family?.some((f) => f.before_robustness_pct !== undefined)
  );

  // Format run date
  const runDateFormatted = data.run_date
    ? data.run_date.replace("T", " ").slice(0, 19) + " UTC"
    : "—";

  return (
    <div className="space-y-8">
      {/* 1. Headline card & key metrics */}
      <section aria-labelledby="headline-overview" className="space-y-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-l-2 border-cyan-500 pl-3">
          <h2 id="headline-overview" className="font-display text-3xl uppercase text-text">Metamorphic Robustness Overview</h2>
          <span className="text-xs text-mute font-mono">
            Seed: {data.seed} · Run: {runDateFormatted}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <MetricCard
            label="Overall Robustness"
            value={`${data.attack.robustness_pct.toFixed(1)}%`}
          />
          <MetricCard
            label="95% Wilson CI"
            value={`[${data.attack.ci_95[0]}%, ${data.attack.ci_95[1]}%]`}
          />
          <MetricCard
            label="Stable Variants"
            value={`${data.attack.stable} / ${data.attack.total}`}
          />
          <MetricCard
            label="Benign Invariance"
            value={data.benign ? `${data.benign.robustness_pct.toFixed(1)}%` : "100.0%"}
          />
        </div>
      </section>

      {/* 2. Known Gaps Callout */}
      {knownGaps.length > 0 && (
        <section aria-labelledby="known-gaps" className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 shadow-sm">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-amber-500" />
            <div className="space-y-2">
              <h3 id="known-gaps" className="text-sm font-semibold text-text">
                Known Gaps in Metamorphic Coverage
              </h3>
              <p className="text-xs text-mute leading-relaxed">
                The following transformation families exhibit bypasses (&lt; 100% stability) under metamorphic variation. Defense rules for these attack patterns are active areas for hardening:
              </p>
              <div className="flex flex-wrap gap-2 pt-1">
                {knownGaps.map((gap) => (
                  <span
                    key={gap.key}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-amber-500/30 bg-panel/70 px-2.5 py-1 text-xs font-mono text-text"
                  >
                    <span className="font-semibold text-amber-400">{gap.key}</span>
                    <span className="text-mute">({gap.robustness_pct}% · {gap.violations} bypasses)</span>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* 3. Per-family horizontal bars (sorted weakest first) */}
      <section aria-labelledby="family-breakdown" className="rounded-[26px] border border-edge/70 bg-panel/65 p-5 shadow-lg shadow-slate-950/5 backdrop-blur-xl space-y-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-l-2 border-cyan-500 pl-3">
          <div>
            <h2 id="family-breakdown" className="font-display text-2xl uppercase text-text">
              Robustness by Transform Family
            </h2>
            <p className="text-xs text-mute">Sorted weakest first · Labeled with stable / total variant counts</p>
          </div>
          <span className="text-xs text-mute">{families.length} transformation families evaluated</span>
        </div>

        <div className="space-y-3.5 pt-2">
          {families.map((fam) => (
            <div key={fam.key} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-text capitalize">{fam.key.replace("_", " ")}</span>
                  <span className="text-mute">({fam.stable} / {fam.total} stable)</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-mute text-[11px]">CI: [{fam.ci_95[0]}%, {fam.ci_95[1]}%]</span>
                  <span className="font-semibold text-text">{fam.robustness_pct.toFixed(1)}%</span>
                </div>
              </div>
              <div className="h-3 w-full overflow-hidden rounded-full border border-edge/60 bg-edge/40">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${getBarColor(fam.robustness_pct)}`}
                  style={{ width: `${Math.max(2, Math.min(100, fam.robustness_pct))}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 4. Before / After Comparison per family (Rendered only if present in data) */}
      {hasBeforeAfter && (
        <section aria-labelledby="before-after" className="rounded-[26px] border border-edge/70 bg-panel/65 p-5 shadow-lg shadow-slate-950/5 backdrop-blur-xl space-y-4">
          <div className="border-l-2 border-cyan-500 pl-3">
            <h2 id="before-after" className="font-display text-2xl uppercase text-text">
              Before / After Family Comparison
            </h2>
            <p className="text-xs text-mute">Impact of rule updates on transformation resilience</p>
          </div>
          <div className="overflow-x-auto rounded-xl border border-edge/65">
            <table className="w-full text-left text-xs">
              <thead className="bg-table-head text-table-head-text">
                <tr>
                  <th className="px-4 py-3 font-semibold">Transform Family</th>
                  <th className="px-4 py-3 font-semibold">Baseline %</th>
                  <th className="px-4 py-3 font-semibold">Post-Hardening %</th>
                  <th className="px-4 py-3 font-semibold">Net Improvement</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge/60">
                {(data.before_after ?? []).map((row) => (
                  <tr key={row.family} className="hover:bg-table-hover">
                    <td className="px-4 py-3 font-mono font-medium text-text">{row.family}</td>
                    <td className="px-4 py-3 font-mono text-mute">{row.before_pct.toFixed(1)}%</td>
                    <td className="px-4 py-3 font-mono text-text">{row.after_pct.toFixed(1)}%</td>
                    <td className="px-4 py-3 font-mono font-semibold text-emerald-400">
                      +{(row.after_pct - row.before_pct).toFixed(1)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* 5. Per-rule table */}
      <section aria-labelledby="rule-table" className="rounded-[26px] border border-edge/70 bg-panel/65 p-5 shadow-lg shadow-slate-950/5 backdrop-blur-xl space-y-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-l-2 border-cyan-500 pl-3">
          <div>
            <h2 id="rule-table" className="font-display text-2xl uppercase text-text">
              Per-Rule Detection Robustness
            </h2>
            <p className="text-xs text-mute">Defense stability under metamorphic variants of each baseline rule</p>
          </div>
          <span className="text-xs text-mute font-mono">
            {data.attack?.by_rule?.length ?? 0} rules checked
          </span>
        </div>

        <div className="overflow-x-auto rounded-xl border border-edge/65">
          <table className="w-full text-left text-xs">
            <thead className="bg-table-head text-table-head-text">
              <tr>
                <th className="px-4 py-3 font-semibold">Detection Rule</th>
                <th className="px-4 py-3 font-semibold">Stable</th>
                <th className="px-4 py-3 font-semibold">Total</th>
                <th className="px-4 py-3 font-semibold">Robustness %</th>
                <th className="px-4 py-3 font-semibold">95% Wilson CI</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-edge/60">
              {(data.attack?.by_rule ?? []).map((r) => (
                <tr key={r.key} className="hover:bg-table-hover">
                  <td className="px-4 py-2.5 font-mono text-text">{r.key}</td>
                  <td className="px-4 py-2.5 font-mono text-text">{r.stable}</td>
                  <td className="px-4 py-2.5 font-mono text-mute">{r.total}</td>
                  <td className="px-4 py-2.5 font-mono font-medium">
                    <span className={r.robustness_pct >= 90 ? "text-emerald-400" : r.robustness_pct >= 75 ? "text-cyan-400" : "text-amber-400"}>
                      {r.robustness_pct.toFixed(1)}%
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-mute text-[11px]">
                    [{r.ci_95[0]}%, {r.ci_95[1]}%]
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* 6. Bypass list: Minimized transform chain and seed ID only (NEVER raw text) */}
      <section aria-labelledby="bypass-list" className="rounded-[26px] border border-edge/70 bg-panel/65 p-5 shadow-lg shadow-slate-950/5 backdrop-blur-xl space-y-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-l-2 border-cyan-500 pl-3">
          <div>
            <h2 id="bypass-list" className="font-display text-2xl uppercase text-text">
              Observed Bypass Chains
            </h2>
            <p className="text-xs text-mute">
              Minimized transformation sequences resulting in policy bypasses. Only seed IDs and chain sequences shown.
            </p>
          </div>
          <span className="text-xs text-mute font-mono">
            {data.bypasses ? `${data.bypasses.length} minimized chains` : `${data.violations?.length ?? 0} violations`}
          </span>
        </div>

        {data.bypasses && data.bypasses.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-edge/65">
            <table className="w-full text-left text-xs">
              <thead className="bg-table-head text-table-head-text">
                <tr>
                  <th className="px-4 py-3 font-semibold">Seed ID</th>
                  <th className="px-4 py-3 font-semibold">Minimized Transform Chain</th>
                  <th className="px-4 py-3 font-semibold">Observed Outcome</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge/60">
                {data.bypasses.slice(0, 30).map((b, idx) => (
                  <tr key={`${b.seed_id}-${idx}`} className="hover:bg-table-hover">
                    <td className="px-4 py-2.5 font-mono font-medium text-text">{b.seed_id}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap items-center gap-1 font-mono text-xs">
                        {b.minimal_chain.map((step, sIdx) => (
                          <span key={sIdx} className="inline-flex items-center gap-1">
                            <span className="rounded bg-panel/80 border border-edge/60 px-2 py-0.5 text-text">
                              {step}
                            </span>
                            {sIdx < b.minimal_chain.length - 1 && (
                              <ChevronRight className="size-3 text-mute" />
                            )}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono">{getDecisionBadge(b.decision)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : data.violations && data.violations.length > 0 ? (
          <div className="overflow-x-auto rounded-xl border border-edge/65">
            <table className="w-full text-left text-xs">
              <thead className="bg-table-head text-table-head-text">
                <tr>
                  <th className="px-4 py-3 font-semibold">Seed ID</th>
                  <th className="px-4 py-3 font-semibold">Attack Category</th>
                  <th className="px-4 py-3 font-semibold">Transform</th>
                  <th className="px-4 py-3 font-semibold">Observed Outcome</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-edge/60">
                {data.violations.slice(0, 30).map((v, idx) => (
                  <tr key={`${v.seed_id}-${idx}`} className="hover:bg-table-hover">
                    <td className="px-4 py-2.5 font-mono font-medium text-text">{v.seed_id}</td>
                    <td className="px-4 py-2.5 font-mono text-mute">{v.category}</td>
                    <td className="px-4 py-2.5 font-mono text-text">{v.transform}</td>
                    <td className="px-4 py-2.5 font-mono">{getDecisionBadge(v.decision)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-400 flex items-center gap-2">
            <CheckCircle className="size-4" />
            <span>No bypass chains observed. Guardrails maintained 100% stability.</span>
          </div>
        )}
      </section>

      {/* 7. Try it: Transform Decision Preview (Admin Only, max 500 chars, no raw variant text returned) */}
      <section aria-labelledby="try-it-preview" className="rounded-[26px] border border-edge/70 bg-panel/65 p-5 shadow-lg shadow-slate-950/5 backdrop-blur-xl space-y-4">
        <div className="border-l-2 border-cyan-500 pl-3">
          <div className="flex items-center gap-2">
            <Sparkles className="size-4 text-cyan-400" />
            <h2 id="try-it-preview" className="font-display text-2xl uppercase text-text">
              Transform Decision Preview
            </h2>
          </div>
          <p className="text-xs text-mute">
            Test prompt resilience across all attack transforms. Returns verdict decisions only (ALLOW/BLOCK/REVIEW) — variant text is never exposed.
          </p>
        </div>

        <form onSubmit={handlePreviewSubmit} className="space-y-3">
          <div className="relative">
            <textarea
              value={testPrompt}
              onChange={(e) => setTestPrompt(e.target.value.slice(0, 500))}
              placeholder="Enter a test prompt to preview how transforms are evaluated (max 500 characters)..."
              rows={3}
              maxLength={500}
              className="w-full resize-none rounded-xl border border-edge/70 bg-panel/60 p-3 text-xs text-text placeholder:text-mute focus:border-cyan-500 focus:outline-none"
            />
            <div className="flex items-center justify-between pt-1 text-[11px] text-mute">
              <span>Rate limited to 10 requests / minute</span>
              <span className={testPrompt.length >= 500 ? "text-rose-400 font-mono" : "font-mono"}>
                {testPrompt.length} / 500
              </span>
            </div>
          </div>

          <button
            type="submit"
            disabled={previewLoading || !testPrompt.trim()}
            className="inline-flex items-center gap-2 rounded-xl bg-brand px-4 py-2.5 text-xs font-medium text-white shadow-sm hover:bg-brand-hover disabled:opacity-50 transition-colors"
          >
            <Play className="size-3.5" />
            {previewLoading ? "Evaluating Transforms..." : "Preview Decisions"}
          </button>
        </form>

        {previewError && (
          <p role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-400">
            {previewError}
          </p>
        )}

        {previewItems && (
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between text-xs text-mute">
              <span>{previewItems.length} transforms evaluated</span>
              <span className="font-mono">
                {previewItems.filter((i) => i.decision === "BLOCK").length} Blocked ·{" "}
                {previewItems.filter((i) => i.decision === "ALLOW").length} Allowed
              </span>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 max-h-[360px] overflow-y-auto pr-1">
              {previewItems.map((item, idx) => (
                <div
                  key={`${item.transform}-${idx}`}
                  className="flex items-center justify-between rounded-xl border border-edge/60 bg-panel/80 p-2.5 text-xs"
                >
                  <div className="min-w-0 pr-2">
                    <p className="font-mono font-medium text-text truncate">{item.transform}</p>
                    <p className="text-[10px] text-mute capitalize">{item.family.replace("_", " ")}</p>
                  </div>
                  <div>{getDecisionBadge(item.decision)}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
