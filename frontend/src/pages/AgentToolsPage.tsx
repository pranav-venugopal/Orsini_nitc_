import { useState } from "react";
import { useOutletContext } from "react-router-dom";
import { AlertCircle, CheckCircle2, ChevronRight, Cpu, ExternalLink, Globe, Lock, Mail, Play, ShieldAlert, ShieldCheck, Terminal, Wrench } from "lucide-react";
import { api } from "../services/api";
import type { SessionUser, ToolRequest, ToolResponse } from "../types/api";

type ToolType = "calculator" | "fetch_url" | "send_email";

interface ToolPreset {
  title: string;
  desc: string;
  isAttack?: boolean;
  args: Record<string, any>;
  approve?: boolean;
  adminOnly?: boolean;
}

export default function AgentToolsPage() {
  const outletContext = useOutletContext<{ user?: SessionUser }>();
  const user = outletContext?.user;
  const isAdmin = user?.role === "admin";
  const [selectedTool, setSelectedTool] = useState<ToolType>("calculator");
  const [calcExpr, setCalcExpr] = useState("(250 * 4) + 120");
  const [urlInput, setUrlInput] = useState("https://example.com/api/data");
  const [emailTo, setEmailTo] = useState("ops-team@company.internal");
  const [emailSubject, setEmailSubject] = useState("Security telemetry summary");
  const [emailBody, setEmailBody] = useState("Weekly security event audit completed.");
  const [approveEmail, setApproveEmail] = useState(false);

  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<ToolResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const PRESETS: Record<ToolType, ToolPreset[]> = {
    calculator: [
      {
        title: "Safe Math Evaluation",
        desc: "Legitimate arithmetic expression evaluated via AST",
        args: { expr: "(120 * 4) + 45 / 3" },
      },
      {
        title: "Code Injection Exploit",
        desc: "Attempts Python code execution (__import__)",
        isAttack: true,
        args: { expr: "__import__('os').system('id')" },
      },
      {
        title: "Eval Invocation Attempt",
        desc: "Attempts eval() call inside expression",
        isAttack: true,
        args: { expr: "eval('2+2')" },
      },
    ],
    fetch_url: [
      {
        title: "Allowed Domain Fetch",
        desc: "Fetch canned data from allowed domain (example.com)",
        args: { url: "https://example.com/reports/compliance" },
      },
      {
        title: "Cloud Metadata SSRF",
        desc: "Target AWS metadata endpoint (169.254.169.254)",
        isAttack: true,
        args: { url: "http://169.254.169.254/latest/meta-data/" },
      },
      {
        title: "Loopback Port Probe",
        desc: "Target localhost backend port (127.0.0.1:8000)",
        isAttack: true,
        args: { url: "http://127.0.0.1:8000/internal-secrets" },
      },
    ],
    send_email: [
      {
        title: "Unapproved Email (Member)",
        desc: "Triggers human-in-the-loop review policy",
        args: { to: "analyst@company.com", subject: "Draft note", body: "Pending draft" },
        approve: false,
      },
      {
        title: "Admin Approved Dispatch",
        desc: "Explicit admin authorization (approve=true)",
        args: { to: "secops@company.com", subject: "Critical incident notification", body: "Confirmed alert." },
        approve: true,
        adminOnly: true,
      },
    ],
  };

  const runExecution = async (customReq?: ToolRequest) => {
    setLoading(true);
    setError(null);

    let req: ToolRequest;
    if (customReq) {
      req = customReq;
    } else {
      if (selectedTool === "calculator") {
        req = { name: "calculator", args: { expr: calcExpr } };
      } else if (selectedTool === "fetch_url") {
        req = { name: "fetch_url", args: { url: urlInput } };
      } else {
        req = {
          name: "send_email",
          args: { to: emailTo, subject: emailSubject, body: emailBody },
          approve: approveEmail,
        };
      }
    }

    try {
      const res = await api.executeTool(req);
      setResponse(res);
    } catch (e: any) {
      setError(e.message || "Failed to execute tool request");
      setResponse(null);
    } finally {
      setLoading(false);
    }
  };

  const applyPreset = (preset: ToolPreset) => {
    if (selectedTool === "calculator") {
      setCalcExpr(preset.args.expr);
    } else if (selectedTool === "fetch_url") {
      setUrlInput(preset.args.url);
    } else {
      setEmailTo(preset.args.to);
      setEmailSubject(preset.args.subject);
      setEmailBody(preset.args.body);
      setApproveEmail(Boolean(preset.approve));
    }
    runExecution({
      name: selectedTool,
      args: preset.args,
      approve: preset.approve,
    });
  };

  return (
    <div className="page-enter mx-auto max-w-6xl space-y-6 px-4 py-8 md:px-8">
      {/* Header */}
      <div className="flex flex-col gap-2 border-b border-edge/60 pb-6 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="inline-flex size-7 items-center justify-center rounded-lg bg-accent/10 text-accent">
              <Wrench size={16} />
            </span>
            <p className="text-xs font-semibold uppercase tracking-wider text-accent">Phase 3 Guardrails</p>
          </div>
          <h1 className="mt-1 font-display text-2xl font-medium tracking-tight text-text sm:text-3xl">
            Agent Tool Safety Sandbox
          </h1>
          <p className="mt-1 text-sm text-mute">
            Live evaluation of <span className="font-mono text-xs text-text">ToolCallGuard</span>, AST arithmetic bounds, SSRF allowlists, and human-in-the-loop approvals.
          </p>
        </div>
      </div>

      {/* Tool Selector Tabs */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <button
          type="button"
          onClick={() => { setSelectedTool("calculator"); setResponse(null); }}
          className={`flex items-start gap-3 rounded-2xl border p-4 text-left transition-all ${
            selectedTool === "calculator"
              ? "border-accent bg-accent/[0.08] shadow-[0_4px_20px_rgba(25,157,193,0.12)]"
              : "border-edge/60 bg-panel/50 hover:bg-panel/80 text-mute"
          }`}
        >
          <div className="rounded-xl border border-edge/80 bg-panel p-2.5 text-text">
            <Cpu size={18} />
          </div>
          <div>
            <h3 className="font-medium text-sm text-text">AST Calculator</h3>
            <p className="mt-0.5 text-xs text-mute">Strict operator tree, strictly no eval/exec</p>
          </div>
        </button>

        <button
          type="button"
          onClick={() => { setSelectedTool("fetch_url"); setResponse(null); }}
          className={`flex items-start gap-3 rounded-2xl border p-4 text-left transition-all ${
            selectedTool === "fetch_url"
              ? "border-accent bg-accent/[0.08] shadow-[0_4px_20px_rgba(25,157,193,0.12)]"
              : "border-edge/60 bg-panel/50 hover:bg-panel/80 text-mute"
          }`}
        >
          <div className="rounded-xl border border-edge/80 bg-panel p-2.5 text-text">
            <Globe size={18} />
          </div>
          <div>
            <h3 className="font-medium text-sm text-text">URL Fetcher</h3>
            <p className="mt-0.5 text-xs text-mute">SSRF defense & domain allowlisting</p>
          </div>
        </button>

        <button
          type="button"
          onClick={() => { setSelectedTool("send_email"); setResponse(null); }}
          className={`flex items-start gap-3 rounded-2xl border p-4 text-left transition-all ${
            selectedTool === "send_email"
              ? "border-accent bg-accent/[0.08] shadow-[0_4px_20px_rgba(25,157,193,0.12)]"
              : "border-edge/60 bg-panel/50 hover:bg-panel/80 text-mute"
          }`}
        >
          <div className="rounded-xl border border-edge/80 bg-panel p-2.5 text-text">
            <Mail size={18} />
          </div>
          <div>
            <h3 className="font-medium text-sm text-text">Email Dispatcher</h3>
            <p className="mt-0.5 text-xs text-mute">Human-in-the-loop admin approval</p>
          </div>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Configuration & Attack Presets (7 cols) */}
        <div className="space-y-5 lg:col-span-7">
          {/* Quick Attack Presets */}
          <div className="rounded-[22px] border border-edge/70 bg-panel/60 p-5 backdrop-blur-xl">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-mute mb-3">
              One-Click Test Presets
            </h3>
            <div className="space-y-2">
              {PRESETS[selectedTool].filter((p) => !p.adminOnly || isAdmin).map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => applyPreset(preset)}
                  className="flex w-full items-center justify-between rounded-xl border border-edge/60 bg-surface/70 p-3 text-left transition hover:border-accent hover:bg-surface"
                >
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-text">{preset.title}</span>
                      {preset.isAttack && (
                        <span className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-medium text-rose-400 border border-rose-500/30">
                          <ShieldAlert size={10} /> Exploit
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-mute">{preset.desc}</p>
                  </div>
                  <ChevronRight size={14} className="text-mute shrink-0" />
                </button>
              ))}
            </div>
          </div>

          {/* Custom Argument Editor */}
          <div className="rounded-[22px] border border-edge/70 bg-panel/60 p-5 backdrop-blur-xl space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-mute">
              Tool Arguments & Execution
            </h3>

            {selectedTool === "calculator" && (
              <div>
                <label className="block text-xs font-medium text-text mb-1">
                  Arithmetic Expression:
                </label>
                <input
                  type="text"
                  value={calcExpr}
                  onChange={(e) => setCalcExpr(e.target.value)}
                  placeholder="e.g. (14 * 5) + 2"
                  className="w-full rounded-xl border border-edge/70 bg-surface/90 px-3.5 py-2.5 font-mono text-xs text-text focus:border-accent focus:outline-none"
                />
              </div>
            )}

            {selectedTool === "fetch_url" && (
              <div>
                <label className="block text-xs font-medium text-text mb-1">
                  Target URL (Domain allowlist: example.com, api.example.com):
                </label>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="e.g. https://example.com/api/test"
                  className="w-full rounded-xl border border-edge/70 bg-surface/90 px-3.5 py-2.5 font-mono text-xs text-text focus:border-accent focus:outline-none"
                />
              </div>
            )}

            {selectedTool === "send_email" && (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-text mb-1">Recipient Address:</label>
                  <input
                    type="email"
                    value={emailTo}
                    onChange={(e) => setEmailTo(e.target.value)}
                    className="w-full rounded-xl border border-edge/70 bg-surface/90 px-3.5 py-2 font-mono text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-text mb-1">Subject:</label>
                  <input
                    type="text"
                    value={emailSubject}
                    onChange={(e) => setEmailSubject(e.target.value)}
                    className="w-full rounded-xl border border-edge/70 bg-surface/90 px-3.5 py-2 text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-text mb-1">Body:</label>
                  <textarea
                    rows={2}
                    value={emailBody}
                    onChange={(e) => setEmailBody(e.target.value)}
                    className="w-full rounded-xl border border-edge/70 bg-surface/90 px-3.5 py-2 text-xs text-text focus:border-accent focus:outline-none"
                  />
                </div>
                {isAdmin ? (
                  <div className="flex items-center gap-2 pt-1">
                    <input
                      type="checkbox"
                      id="approve-check"
                      checked={approveEmail}
                      onChange={(e) => setApproveEmail(e.target.checked)}
                      className="rounded border-edge/80 bg-surface text-accent focus:ring-accent"
                    />
                    <label htmlFor="approve-check" className="text-xs text-text select-none cursor-pointer">
                      Explicit Admin Approval Flag (<span className="font-mono text-[11px] text-accent">approve=true</span>)
                    </label>
                  </div>
                ) : (
                  <div className="rounded-xl border border-edge/60 bg-surface/50 p-2.5 text-[11px] text-mute flex items-center gap-2">
                    <Lock size={12} className="text-mute shrink-0" />
                    <span>Member role: Outbound dispatch requires administrator authorization.</span>
                  </div>
                )}
              </div>
            )}

            <button
              type="button"
              onClick={() => runExecution()}
              disabled={loading}
              className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-brand px-4 py-3 text-xs font-medium text-white shadow-lg shadow-cyan-950/20 hover:bg-brand-hover disabled:opacity-50"
            >
              <Play size={14} />
              <span>{loading ? "Evaluating ToolCallGuard..." : "Send Tool Call to Guardrail Engine"}</span>
            </button>
          </div>
        </div>

        {/* Right Column: Guardrail Decision & Execution Result (5 cols) */}
        <div className="space-y-5 lg:col-span-5">
          <div className="rounded-[22px] border border-edge/70 bg-panel/60 p-5 backdrop-blur-xl min-h-[380px] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between border-b border-edge/60 pb-3">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-mute">
                  Interceptor Telemetry
                </h3>
                {response && (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase ${
                      response.status === "executed"
                        ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                        : response.status === "review_required"
                        ? "border border-amber-500/30 bg-amber-500/10 text-amber-400"
                        : "border border-rose-500/30 bg-rose-500/10 text-rose-400"
                    }`}
                  >
                    {response.status === "executed" ? <CheckCircle2 size={12} /> : <ShieldAlert size={12} />}
                    {response.decision}
                  </span>
                )}
              </div>

              {error && (
                <div className="mt-4 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-400">
                  <p className="font-semibold">Execution Error</p>
                  <p className="mt-1">{error}</p>
                </div>
              )}

              {!response && !error && !loading && (
                <div className="flex flex-col items-center justify-center py-16 text-center text-mute">
                  <Terminal size={32} className="opacity-40 mb-3" />
                  <p className="text-xs font-medium text-text">No Tool Call Sent Yet</p>
                  <p className="text-[11px] max-w-xs mt-1">
                    Select a preset or enter parameters on the left to see the ToolCallGuard interceptor in action.
                  </p>
                </div>
              )}

              {loading && (
                <div className="flex flex-col items-center justify-center py-16 text-center text-mute">
                  <div className="size-6 animate-spin rounded-full border-2 border-accent border-t-transparent mb-3" />
                  <p className="text-xs">Evaluating safety guardrails...</p>
                </div>
              )}

              {response && (
                <div className="mt-4 space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="rounded-xl border border-edge/60 bg-surface/60 p-2.5">
                      <span className="text-[10px] text-mute block uppercase">Status</span>
                      <span className="font-semibold text-text">{response.status}</span>
                    </div>
                    <div className="rounded-xl border border-edge/60 bg-surface/60 p-2.5">
                      <span className="text-[10px] text-mute block uppercase">Request ID</span>
                      <span className="font-mono text-[11px] text-text truncate block">{response.request_id}</span>
                    </div>
                  </div>

                  {response.reason && (
                    <div className="rounded-xl border border-edge/60 bg-surface/60 p-2.5 text-xs">
                      <span className="text-[10px] text-mute block uppercase">Policy Reason</span>
                      <span className="font-mono text-amber-400 text-[11px]">{response.reason}</span>
                    </div>
                  )}

                  {response.message && (
                    <div className="rounded-xl border border-edge/60 bg-surface/60 p-2.5 text-xs">
                      <span className="text-[10px] text-mute block uppercase">Interceptor Note</span>
                      <p className="text-text mt-0.5">{response.message}</p>
                    </div>
                  )}

                  {response.categories && response.categories.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {response.categories.map((c, i) => (
                        <span key={i} className="rounded-md border border-edge/70 bg-panel px-2 py-0.5 text-[10px] font-mono text-mute">
                          {c}
                        </span>
                      ))}
                    </div>
                  )}

                  {response.result !== undefined && (
                    <div className="rounded-xl border border-edge/60 bg-surface/70 p-3">
                      <span className="text-[10px] text-mute block uppercase mb-1">Execution Output</span>
                      <pre className="font-mono text-[11px] text-emerald-400 overflow-x-auto whitespace-pre-wrap">
                        {typeof response.result === "object"
                          ? JSON.stringify(response.result, null, 2)
                          : String(response.result)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="mt-6 border-t border-edge/60 pt-3 text-[11px] text-mute flex items-center justify-between">
              <span>Tamper-evident audit logged to DB</span>
              {isAdmin && (
                <a href="/dashboard" className="inline-flex items-center gap-1 text-accent hover:underline">
                  <span>Security monitor</span>
                  <ExternalLink size={10} />
                </a>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
