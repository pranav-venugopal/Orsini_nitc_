import { lazy, Suspense, useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowDownRight,
  Bot,
  CheckCircle2,
  Crosshair,
  Flame,
  Layers,
  Play,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { ErrorState, LoadingState } from "../components/States";
import { api, ApiError } from "../services/api";
import type { ChatResponse, Mode, RedTeamPrompt, RedteamLoopResult, RedteamLoopRound } from "../types/api";

type Row = { prompt: RedTeamPrompt; baseline?: ChatResponse; guarded?: ChatResponse; failed?: boolean };

const SectionScene = lazy(() => import("../components/SectionScene"));
const outcome = (r?: ChatResponse) => (!r ? "—" : `${r.status} (${r.action})`);

export default function RedTeamPage() {
  const [activeTab, setActiveTab] = useState<"loop" | "fixed">("loop");

  // Fixed prompts state
  const [prompts, setPrompts] = useState<RedTeamPrompt[] | null>(null);
  const [fixedError, setFixedError] = useState<string | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [runningFixed, setRunningFixed] = useState(false);

  // Attacker loop state
  const [loopData, setLoopData] = useState<RedteamLoopResult | null>(null);
  const [loopLoading, setLoopLoading] = useState(false);
  const [loopError, setLoopError] = useState<string | null>(null);
  const [roundsCount, setRoundsCount] = useState(5);
  const [attacksCount, setAttacksCount] = useState(8);
  const [selectedModel, setSelectedModel] = useState("llama-3.3-70b-versatile");

  useEffect(() => {
    // Load fixed prompts
    api.redteamPrompts()
      .then((r) => setPrompts(r.items))
      .catch((e) => setFixedError(e instanceof ApiError ? e.message : "Unexpected error."));

    // Load initial attacker loop telemetry
    api.redteamLoop()
      .then((res) => setLoopData(res))
      .catch((e) => setLoopError(e instanceof ApiError ? e.message : "Unable to load redteam loop telemetry."));
  }, []);

  const runFixedTests = async () => {
    if (!prompts) return;
    setRunningFixed(true);
    setRows([]);
    for (const p of prompts) {
      const row: Row = { prompt: p };
      try {
        for (const mode of ["baseline", "guarded"] as Mode[]) {
          row[mode] = await api.chat(p.prompt, null, mode);
        }
      } catch {
        row.failed = true;
      }
      setRows((r) => [...r, row]);
    }
    setRunningFixed(false);
  };

  const runAttackerLoop = async () => {
    setLoopLoading(true);
    setLoopError(null);
    try {
      const result = await api.runRedteamLoop(roundsCount, attacksCount, selectedModel, true);
      setLoopData(result);
    } catch (e: any) {
      setLoopError(e.message || "Failed to execute attacker LLM loop");
    } finally {
      setLoopLoading(false);
    }
  };

  // Fixed test statistics
  const done = rows.filter((r) => r.guarded && !r.failed);
  const attacks = done.filter((r) => r.prompt.category !== "benign");
  const benign = done.filter((r) => r.prompt.category === "benign");
  const notBlocked = attacks.filter((r) => r.guarded!.status === "completed").length;
  const refused = benign.filter((r) => r.guarded!.status !== "completed").length;

  // Chart computations for SVG
  const renderAsrChart = (rounds: RedteamLoopRound[]) => {
    if (!rounds || rounds.length === 0) return null;
    const width = 640;
    const height = 180;
    const paddingX = 50;
    const paddingY = 30;
    const graphWidth = width - paddingX * 2;
    const graphHeight = height - paddingY * 2;

    const points = rounds.map((rd, idx) => {
      const x = paddingX + (idx / Math.max(rounds.length - 1, 1)) * graphWidth;
      const y = height - paddingY - (rd.asr / 100) * graphHeight;
      return { x, y, asr: rd.asr, round: rd.round };
    });

    const pathD = points.reduce((acc, pt, i) => `${acc} ${i === 0 ? "M" : "L"} ${pt.x} ${pt.y}`, "");
    const areaD = `${pathD} L ${points[points.length - 1].x} ${height - paddingY} L ${points[0].x} ${height - paddingY} Z`;

    return (
      <div className="relative w-full overflow-hidden rounded-2xl border border-edge/70 bg-surface/80 p-4">
        <div className="flex items-center justify-between pb-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="size-2 rounded-full bg-accent animate-pulse" />
            <span className="font-semibold uppercase tracking-wider text-text">Attack Success Rate (ASR) Over Rounds</span>
          </div>
          <span className="text-[11px] font-mono text-mute">Autonomous Defensive Synthesis</span>
        </div>

        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-44 overflow-visible">
          <defs>
            <linearGradient id="asrGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#199dc1" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#199dc1" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {[0, 25, 50, 75, 100].map((val) => {
            const y = height - paddingY - (val / 100) * graphHeight;
            return (
              <g key={val}>
                <line x1={paddingX} y1={y} x2={width - paddingX} y2={y} stroke="currentColor" strokeDasharray="3 3" className="text-edge/60" strokeWidth="1" />
                <text x={paddingX - 10} y={y + 3} textAnchor="end" className="text-[9px] fill-mute font-mono">
                  {val}%
                </text>
              </g>
            );
          })}

          {/* Area under curve */}
          <path d={areaD} fill="url(#asrGradient)" />

          {/* Line curve */}
          <path d={pathD} fill="none" stroke="#199dc1" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />

          {/* Points & Labels */}
          {points.map((pt, i) => (
            <g key={i}>
              <circle cx={pt.x} cy={pt.y} r="5" className="fill-brand stroke-surface" strokeWidth="2" />
              <rect x={pt.x - 22} y={pt.y - 24} width="44" height="18" rx="4" className="fill-panel/90 stroke-edge/80" strokeWidth="1" />
              <text x={pt.x} y={pt.y - 12} textAnchor="middle" className="text-[10px] font-mono font-bold fill-accent">
                {pt.asr}%
              </text>
              <text x={pt.x} y={height - paddingY + 16} textAnchor="middle" className="text-[10px] font-medium fill-mute">
                R{pt.round}
              </text>
            </g>
          ))}
        </svg>
      </div>
    );
  };

  return (
    <div className="page-enter mx-auto max-w-6xl space-y-7 px-4 py-6 md:px-8 md:py-9">
      {/* Header */}
      <div className="grid gap-4 border-b border-edge pb-5 lg:grid-cols-[minmax(0,0.88fr)_minmax(0,1.12fr)] lg:items-center">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="inline-flex size-6 items-center justify-center rounded-lg bg-accent/10 text-accent">
              <Crosshair size={14} />
            </span>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-accent">Adversarial Evaluation Lab</p>
          </div>
          <h1 className="display-title font-display text-4xl uppercase leading-[1.02] text-text md:text-5xl">
            Red-Team Arena
          </h1>
          <p className="mt-2.5 max-w-2xl text-sm text-mute">
            Continuous adversarial testing with Groq LLM attacker loops, real-time bypass learning, and deterministic Information-Flow Control (IFC).
          </p>
        </div>
        <Suspense fallback={<div className="section-scene section-scene-redteam h-[190px] w-full rounded-[28px] sm:h-[220px] md:h-[270px]" />}>
          <SectionScene mode="redteam" />
        </Suspense>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-edge/60 pb-1">
        <button
          type="button"
          onClick={() => setActiveTab("loop")}
          className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-medium transition-all ${
            activeTab === "loop"
              ? "bg-accent/15 text-accent border border-accent/30 shadow-sm"
              : "text-mute hover:bg-panel/60 hover:text-text"
          }`}
        >
          <Bot size={15} />
          <span>Attacker LLM in a Loop</span>
          <span className="rounded bg-accent/20 px-1.5 py-0.2 text-[9px] font-mono text-accent">Live</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("fixed")}
          className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-medium transition-all ${
            activeTab === "fixed"
              ? "bg-accent/15 text-accent border border-accent/30 shadow-sm"
              : "text-mute hover:bg-panel/60 hover:text-text"
          }`}
        >
          <Layers size={15} />
          <span>Fixed Evaluation Benchmark</span>
        </button>
      </div>

      {/* Tab 1: Attacker LLM in a Loop */}
      {activeTab === "loop" && (
        <div className="space-y-6">
          {/* Controls Bar */}
          <div className="rounded-[22px] border border-edge/70 bg-panel/60 p-5 backdrop-blur-xl">
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-text flex items-center gap-2">
                  <Flame size={16} className="text-amber-500" />
                  Autonomous Adversarial Red-Teaming Loop
                </h3>
                <p className="text-xs text-mute max-w-xl">
                  One Groq model generates subtle jailbreak bypasses each round. Each success automatically synthesizes a dynamic defense rule, dropping Attack Success Rate (ASR) to 0%.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-1.5 rounded-xl border border-edge/70 bg-surface/70 px-3 py-1.5 text-xs">
                  <span className="text-[10px] uppercase text-mute">Rounds:</span>
                  <select
                    value={roundsCount}
                    onChange={(e) => setRoundsCount(Number(e.target.value))}
                    disabled={loopLoading}
                    className="bg-transparent font-medium text-text outline-none cursor-pointer"
                  >
                    <option value={3}>3 Rounds</option>
                    <option value={4}>4 Rounds</option>
                    <option value={5}>5 Rounds</option>
                  </select>
                </div>

                <div className="flex items-center gap-1.5 rounded-xl border border-edge/70 bg-surface/70 px-3 py-1.5 text-xs">
                  <span className="text-[10px] uppercase text-mute">Attacks / Round:</span>
                  <select
                    value={attacksCount}
                    onChange={(e) => setAttacksCount(Number(e.target.value))}
                    disabled={loopLoading}
                    className="bg-transparent font-medium text-text outline-none cursor-pointer"
                  >
                    <option value={6}>6 Attacks</option>
                    <option value={8}>8 Attacks</option>
                    <option value={10}>10 Attacks</option>
                  </select>
                </div>

                <div className="flex items-center gap-1.5 rounded-xl border border-edge/70 bg-surface/70 px-3 py-1.5 text-xs">
                  <span className="text-[10px] uppercase text-mute">Model:</span>
                  <select
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    disabled={loopLoading}
                    className="bg-transparent font-medium text-text outline-none cursor-pointer"
                  >
                    <option value="llama-3.3-70b-versatile">Llama 3.3 70B (Groq)</option>
                    <option value="llama-3.1-8b-instant">Llama 3.1 8B (Groq)</option>
                  </select>
                </div>

                <button
                  type="button"
                  onClick={runAttackerLoop}
                  disabled={loopLoading}
                  className="inline-flex items-center gap-2 rounded-xl bg-brand px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-950/20 hover:bg-brand-hover disabled:opacity-50 transition"
                >
                  {loopLoading ? (
                    <>
                      <RefreshCw size={13} className="animate-spin" />
                      <span>Synthesizing Attacks ({roundsCount} Rounds)...</span>
                    </>
                  ) : (
                    <>
                      <Zap size={13} />
                      <span>Launch Attacker Loop</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {loopError && (
            <div className="rounded-2xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-400">
              <p className="font-semibold">Loop Execution Notice</p>
              <p className="mt-1">{loopError}</p>
            </div>
          )}

          {/* Telemetry KPIs */}
          {loopData && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-2xl border border-edge/70 bg-panel/60 p-4 backdrop-blur-xl">
                <span className="text-[10px] uppercase tracking-wider text-mute block">Initial ASR</span>
                <span className="mt-1 font-mono text-2xl font-bold text-rose-400">{loopData.initial_asr}%</span>
                <span className="text-[10px] text-mute block mt-0.5">Round 1 baseline</span>
              </div>

              <div className="rounded-2xl border border-edge/70 bg-panel/60 p-4 backdrop-blur-xl">
                <span className="text-[10px] uppercase tracking-wider text-mute block">Final ASR</span>
                <div className="mt-1 flex items-baseline gap-2">
                  <span className="font-mono text-2xl font-bold text-emerald-400">{loopData.final_asr}%</span>
                  <span className="inline-flex items-center text-[10px] font-semibold text-emerald-400">
                    <ArrowDownRight size={12} />
                    {Math.round(loopData.initial_asr - loopData.final_asr)}% drop
                  </span>
                </div>
                <span className="text-[10px] text-mute block mt-0.5">Post-synthesis defense</span>
              </div>

              <div className="rounded-2xl border border-edge/70 bg-panel/60 p-4 backdrop-blur-xl">
                <span className="text-[10px] uppercase tracking-wider text-mute block">Dynamic Rules Added</span>
                <span className="mt-1 font-mono text-2xl font-bold text-accent">{loopData.total_dynamic_rules}</span>
                <span className="text-[10px] text-mute block mt-0.5">Synthesized from bypasses</span>
              </div>

              <div className="rounded-2xl border border-edge/70 bg-panel/60 p-4 backdrop-blur-xl">
                <span className="text-[10px] uppercase tracking-wider text-mute block">IFC Hard Policy</span>
                <span className="mt-1 font-mono text-2xl font-bold text-emerald-400">Active</span>
                <span className="text-[10px] text-mute block mt-0.5">Untrusted tool boundary locked</span>
              </div>
            </div>
          )}

          {/* Live ASR Chart */}
          {loopData && renderAsrChart(loopData.rounds)}

          {/* Round-by-Round Breakdown Table */}
          {loopData && (
            <div className="rounded-[22px] border border-edge/70 bg-panel/60 p-5 backdrop-blur-xl space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-mute">
                Round-by-Round Defense Evolution Telemetry
              </h3>

              <div className="overflow-x-auto rounded-xl border border-edge/70 bg-surface/60">
                <table className="w-full min-w-[650px] text-left text-xs">
                  <thead className="border-b border-edge/70 bg-panel/80 text-[10px] font-semibold uppercase text-mute">
                    <tr>
                      <th className="px-4 py-3">Round</th>
                      <th className="px-4 py-3">Attacks Tested</th>
                      <th className="px-4 py-3">Blocked</th>
                      <th className="px-4 py-3">Bypassed</th>
                      <th className="px-4 py-3">ASR %</th>
                      <th className="px-4 py-3">Dynamic Rules Synthesized</th>
                      <th className="px-4 py-3">Bypass Samples Observed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-edge/60">
                    {loopData.rounds.map((rd) => (
                      <tr key={rd.round} className="transition hover:bg-panel/40">
                        <td className="px-4 py-3 font-semibold text-text">Round {rd.round}</td>
                        <td className="px-4 py-3 font-mono">{rd.total_attacks}</td>
                        <td className="px-4 py-3">
                          <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 font-mono text-emerald-400 border border-emerald-500/20">
                            <CheckCircle2 size={11} />
                            {rd.blocked}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {rd.bypassed > 0 ? (
                            <span className="inline-flex items-center gap-1 rounded bg-rose-500/10 px-2 py-0.5 font-mono text-rose-400 border border-rose-500/20">
                              <ShieldAlert size={11} />
                              {rd.bypassed}
                            </span>
                          ) : (
                            <span className="font-mono text-mute">0</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`font-mono font-bold ${
                              rd.asr === 0
                                ? "text-emerald-400"
                                : rd.asr < 30
                                ? "text-amber-400"
                                : "text-rose-400"
                            }`}
                          >
                            {rd.asr}%
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-accent">+{rd.new_rules_count}</td>
                        <td className="px-4 py-3 max-w-xs truncate text-[11px] text-mute">
                          {rd.sample_bypasses && rd.sample_bypasses.length > 0 ? (
                            <span className="italic" title={rd.sample_bypasses[0]}>
                              "{rd.sample_bypasses[0]}"
                            </span>
                          ) : (
                            <span className="text-emerald-400 font-medium">None (All attacks blocked)</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Fixed Evaluation Set */}
      {activeTab === "fixed" && (
        <div className="space-y-6">
          {fixedError ? (
            <ErrorState message={fixedError} />
          ) : !prompts ? (
            <LoadingState />
          ) : (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-text">Standardized Fixed Prompt Suite</h3>
                  <p className="text-xs text-mute">Compares raw baseline model answers against the guarded gateway.</p>
                </div>
                <button
                  onClick={runFixedTests}
                  disabled={runningFixed}
                  className="inline-flex items-center gap-2 rounded-xl bg-brand px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-950/20 hover:bg-brand-hover disabled:opacity-50 transition"
                >
                  <Play size={14} />
                  <span>{runningFixed ? "Running Evaluation..." : `Run ${prompts.length} Tests`}</span>
                </button>
              </div>

              {rows.length > 0 && (
                <>
                  <div className="overflow-x-auto rounded-2xl border border-edge/70 bg-panel/60 p-1 shadow-sm">
                    <table className="w-full min-w-[680px] text-left text-xs">
                      <thead className="bg-panel/80 text-[10px] font-semibold uppercase text-mute border-b border-edge/60">
                        <tr>
                          {["Prompt", "Category", "Baseline Result", "Guarded Result"].map((h) => (
                            <th key={h} scope="col" className="px-4 py-3">
                              {h}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-edge/60">
                        {rows.map((r) => (
                          <tr key={r.prompt.id} className="transition hover:bg-panel/40">
                            <td className="max-w-md px-4 py-3 font-medium text-text">{r.prompt.prompt}</td>
                            <td className="px-4 py-3 text-[11px] uppercase font-mono text-mute">{r.prompt.category}</td>
                            <td className="px-4 py-3 text-[11px] font-mono text-rose-400">
                              {r.failed ? "request failed" : outcome(r.baseline)}
                            </td>
                            <td className="px-4 py-3 text-[11px] font-mono text-emerald-400">
                              {r.failed ? "request failed" : outcome(r.guarded)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <p className="text-xs text-mute">
                    On this {rows.length}-prompt suite: attack prompts not blocked {notBlocked}/{attacks.length}; benign prompts refused {refused}/{benign.length}.
                  </p>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
