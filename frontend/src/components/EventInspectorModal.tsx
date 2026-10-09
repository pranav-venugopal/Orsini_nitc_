import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Copy,
  ExternalLink,
  LoaderCircle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  X,
} from "lucide-react";
import { api } from "../services/api";
import type { RequestDetails, SecurityEvent } from "../types/api";

interface EventInspectorModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

export default function EventInspectorModal({ event, onClose }: EventInspectorModalProps) {
  const [details, setDetails] = useState<RequestDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [copiedOutput, setCopiedOutput] = useState(false);
  const [copiedReqId, setCopiedReqId] = useState(false);

  useEffect(() => {
    if (!event) return;
    let active = true;
    setLoading(true);

    api
      .eventDetails(event.request_id)
      .then((res) => {
        if (active) setDetails(res);
      })
      .catch(() => {
        // Fallback to data already on the event object
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [event]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!event) return null;

  // Resolve fields from event or details
  const userPrompt =
    event.user_prompt ||
    details?.user_prompt ||
    details?.messages?.find((m) => m.role === "user")?.content ||
    null;

  const attemptedOutput =
    event.attempted_output ||
    details?.attempted_output ||
    details?.messages?.find((m) => (m.role as string) === "attempted_output")?.content ||
    null;

  const finalOutput =
    event.final_output ||
    details?.final_output ||
    details?.messages?.find((m) => m.role === "assistant")?.content ||
    null;

  const isBypassedInputBlockedOutput =
    event.stage === "output" && (event.action === "blocked_output" || event.label === "unsafe");

  const isInputBlock =
    event.stage === "input" && (event.action === "blocked_input" || event.label === "unsafe");

  const copyToClipboard = async (text: string, type: "prompt" | "output" | "reqId") => {
    try {
      await navigator.clipboard.writeText(text);
      if (type === "prompt") {
        setCopiedPrompt(true);
        setTimeout(() => setCopiedPrompt(false), 2000);
      } else if (type === "output") {
        setCopiedOutput(true);
        setTimeout(() => setCopiedOutput(false), 2000);
      } else {
        setCopiedReqId(true);
        setTimeout(() => setCopiedReqId(false), 2000);
      }
    } catch {
      // Ignore
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 md:p-8"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/70 backdrop-blur-md transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal Card */}
      <div className="relative flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-[26px] border border-edge/80 bg-surface shadow-2xl shadow-cyan-950/20 backdrop-blur-2xl">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-edge/70 bg-panel/70 px-6 py-4.5">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-mute">
                Incident Inspection
              </span>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium uppercase ${
                  isBypassedInputBlockedOutput
                    ? "border border-rose-500/30 bg-rose-500/10 text-rose-400"
                    : isInputBlock
                    ? "border border-amber-500/30 bg-amber-500/10 text-amber-400"
                    : event.action === "passed"
                    ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border border-edge bg-panel text-mute"
                }`}
              >
                {isBypassedInputBlockedOutput ? (
                  <>
                    <ShieldAlert size={12} /> Bypassed Input · Blocked at Output
                  </>
                ) : isInputBlock ? (
                  <>
                    <ShieldX size={12} /> Blocked at Input Layer
                  </>
                ) : (
                  <>
                    <ShieldCheck size={12} /> {event.action}
                  </>
                )}
              </span>
            </div>
            <h2 id="modal-title" className="font-display text-2xl font-bold uppercase tracking-tight text-text">
              Request Details & Threat Forensics
            </h2>
            <div className="flex flex-wrap items-center gap-3 text-xs text-mute">
              <span className="font-mono text-cyan-600 dark:text-cyan-400">{event.request_id}</span>
              <button
                onClick={() => copyToClipboard(event.request_id, "reqId")}
                className="inline-flex items-center gap-1 text-[11px] hover:text-text"
                title="Copy Request ID"
              >
                {copiedReqId ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                {copiedReqId ? "Copied" : "Copy ID"}
              </button>
              <span>·</span>
              <span>{event.timestamp.replace("T", " ").slice(0, 19)} UTC</span>
              <span>·</span>
              <span>Latency: {event.latency_ms} ms</span>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="grid size-9 place-items-center rounded-full border border-edge/80 bg-panel/80 text-mute transition-colors hover:border-cyan-600 hover:text-text"
          >
            <X size={18} />
          </button>
        </div>

        {/* Scrollable Content Body */}
        <div className="space-y-6 overflow-y-auto px-6 py-6 text-sm">
          {/* Multi-layer Pipeline Stepper */}
          <section className="rounded-2xl border border-edge/60 bg-panel/50 p-4">
            <p className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-mute">
              Multi-Layer Defense Pipeline Flow
            </p>
            <div className="grid gap-2 sm:grid-cols-3 sm:items-center sm:gap-4">
              {/* Layer 1: Input Guard */}
              <div
                className={`flex flex-col rounded-xl border p-3 ${
                  isInputBlock
                    ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
                    : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold uppercase">
                  <span>Layer 1: Input Guard</span>
                  {isInputBlock ? <ShieldX size={15} /> : <ShieldCheck size={15} />}
                </div>
                <p className="mt-1 text-xs">
                  {isInputBlock
                    ? "✕ Blocked (Adversarial input detected)"
                    : "✓ Passed / Allowed (Bypassed to AI)"}
                </p>
              </div>

              {/* Layer 2: LLM Generation */}
              <div
                className={`flex flex-col rounded-xl border p-3 ${
                  isInputBlock
                    ? "border-edge/50 bg-panel/30 text-mute opacity-60"
                    : "border-cyan-500/40 bg-cyan-500/10 text-cyan-300"
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold uppercase">
                  <span>Layer 2: AI Model</span>
                  <ExternalLink size={15} />
                </div>
                <p className="mt-1 text-xs">
                  {isInputBlock
                    ? "— Skipped (Model not invoked)"
                    : "✓ Executed & Generated Response"}
                </p>
              </div>

              {/* Layer 3: Output Guard */}
              <div
                className={`flex flex-col rounded-xl border p-3 ${
                  isBypassedInputBlockedOutput
                    ? "border-rose-500/50 bg-rose-500/15 text-rose-300 shadow-sm shadow-rose-950/20"
                    : event.action === "redacted"
                    ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                    : isInputBlock
                    ? "border-edge/50 bg-panel/30 text-mute opacity-60"
                    : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold uppercase">
                  <span>Layer 3: Output Guard</span>
                  {isBypassedInputBlockedOutput ? (
                    <ShieldAlert size={15} />
                  ) : event.action === "redacted" ? (
                    <AlertTriangle size={15} />
                  ) : (
                    <ShieldCheck size={15} />
                  )}
                </div>
                <p className="mt-1 text-xs font-medium">
                  {isBypassedInputBlockedOutput
                    ? "✕ INTERCEPTED & BLOCKED"
                    : event.action === "redacted"
                    ? "⚠️ PII Redacted"
                    : isInputBlock
                    ? "— Skipped"
                    : "✓ Passed Output Check"}
                </p>
              </div>
            </div>
          </section>

          {/* User Prompt Section */}
          <section className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="grid size-6 place-items-center rounded-lg border border-edge bg-panel text-xs text-cyan-600 dark:text-cyan-400">
                  1
                </span>
                <h3 className="font-medium text-text">User Prompt Provided</h3>
              </div>
              {userPrompt && (
                <button
                  onClick={() => copyToClipboard(userPrompt, "prompt")}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-edge/70 bg-panel/70 px-2.5 py-1 text-xs text-mute transition-colors hover:border-cyan-600 hover:text-text"
                >
                  {copiedPrompt ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
                  {copiedPrompt ? "Copied" : "Copy prompt"}
                </button>
              )}
            </div>

            <div className="rounded-2xl border border-edge/70 bg-panel/60 p-4 font-mono text-xs leading-relaxed text-text">
              {loading && !userPrompt ? (
                <div className="flex items-center gap-2 text-mute">
                  <LoaderCircle size={14} className="animate-spin text-cyan-600" />
                  Loading user prompt…
                </div>
              ) : userPrompt ? (
                <p className="whitespace-pre-wrap break-words">{userPrompt}</p>
              ) : (
                <p className="italic text-mute">No prompt recorded for this request ID.</p>
              )}
            </div>
          </section>

          {/* AI Attempted Output Section (Key Feature) */}
          <section className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="grid size-6 place-items-center rounded-lg border border-rose-500/40 bg-rose-500/10 text-xs font-bold text-rose-500">
                  2
                </span>
                <h3 className="font-medium text-text">
                  AI Attempted Output{" "}
                  {isBypassedInputBlockedOutput && (
                    <span className="text-xs font-semibold text-rose-500 dark:text-rose-400">
                      (Intercepted by Output Guard)
                    </span>
                  )}
                </h3>
              </div>
              {attemptedOutput && (
                <button
                  onClick={() => copyToClipboard(attemptedOutput, "output")}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-xs text-rose-400 transition-colors hover:bg-rose-500/20"
                >
                  {copiedOutput ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
                  {copiedOutput ? "Copied" : "Copy attempted output"}
                </button>
              )}
            </div>

            {isBypassedInputBlockedOutput ? (
              <div className="rounded-2xl border border-rose-500/40 bg-rose-950/20 p-4.5 shadow-lg shadow-rose-950/15 backdrop-blur-md">
                <div className="mb-3 flex items-start gap-2.5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
                  <AlertTriangle size={18} className="shrink-0 text-rose-400" />
                  <div>
                    <p className="font-semibold text-rose-300">
                      Output Guardrail Triggered: Intercepted Response
                    </p>
                    <p className="mt-0.5 text-rose-400/90">
                      The user prompt slipped past the initial input guard. The model generated the response below,
                      but the output guardrail detected harmful content (
                      {event.categories.length ? event.categories.join(", ") : "policy violation"}) and suppressed it
                      before it ever reached the user.
                    </p>
                  </div>
                </div>

                <div className="rounded-xl border border-rose-500/20 bg-panel/85 p-3.5 font-mono text-xs leading-relaxed text-rose-100">
                  {attemptedOutput ? (
                    <p className="whitespace-pre-wrap break-words">{attemptedOutput}</p>
                  ) : loading ? (
                    <div className="flex items-center gap-2 text-mute">
                      <LoaderCircle size={14} className="animate-spin text-rose-500" />
                      Retrieving intercepted model output…
                    </div>
                  ) : (
                    <p className="italic text-rose-400/70">
                      The output was blocked by policy. Detailed raw text was not logged for this request.
                    </p>
                  )}
                </div>
              </div>
            ) : isInputBlock ? (
              <div className="rounded-2xl border border-edge/60 bg-panel/40 p-4 text-xs text-mute">
                <div className="flex items-center gap-2 text-text">
                  <Shield size={15} className="text-cyan-600" />
                  <span className="font-medium">Model Generation Aborted</span>
                </div>
                <p className="mt-1">
                  The input guard blocked this prompt immediately at Layer 1. The model was never called, so no
                  attempted output was generated.
                </p>
              </div>
            ) : (
              <div className="rounded-2xl border border-edge/70 bg-panel/60 p-4 font-mono text-xs leading-relaxed text-text">
                {finalOutput ? (
                  <p className="whitespace-pre-wrap break-words">{finalOutput}</p>
                ) : (
                  <p className="italic text-mute">Standard safe model output delivered.</p>
                )}
              </div>
            )}
          </section>

          {/* Section 3: Final Delivered Response */}
          {isBypassedInputBlockedOutput && finalOutput && (
            <section className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="grid size-6 place-items-center rounded-lg border border-edge bg-panel text-xs text-cyan-600 dark:text-cyan-400">
                  3
                </span>
                <h3 className="font-medium text-text">What Was Sent to the User (Safe Refusal)</h3>
              </div>
              <div className="rounded-2xl border border-edge/70 bg-panel/50 p-3.5 text-xs text-mute">
                <p className="italic">"{finalOutput}"</p>
              </div>
            </section>
          )}

          {/* Threat Classification & Diagnostics Meta */}
          <section className="space-y-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-mute">
              Guardrail Finding & Threat Categorization
            </h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-xl border border-edge/60 bg-panel/40 p-3">
                <p className="text-[10px] uppercase text-mute">Stage Evaluated</p>
                <p className="mt-1 font-semibold uppercase text-text">{event.stage}</p>
              </div>
              <div className="rounded-xl border border-edge/60 bg-panel/40 p-3">
                <p className="text-[10px] uppercase text-mute">Classification</p>
                <p
                  className={`mt-1 font-semibold uppercase ${
                    event.label === "unsafe"
                      ? "text-rose-500"
                      : event.label === "safe"
                      ? "text-emerald-500"
                      : "text-amber-500"
                  }`}
                >
                  {event.label}
                </p>
              </div>
              <div className="rounded-xl border border-edge/60 bg-panel/40 p-3">
                <p className="text-[10px] uppercase text-mute">Enforcement Action</p>
                <p className="mt-1 font-semibold text-text">{event.action}</p>
              </div>
              <div className="rounded-xl border border-edge/60 bg-panel/40 p-3">
                <p className="text-[10px] uppercase text-mute">Evaluation Latency</p>
                <p className="mt-1 font-semibold text-text">{event.latency_ms} ms</p>
              </div>
            </div>

            {event.categories.length > 0 && (
              <div className="mt-2 rounded-xl border border-edge/60 bg-panel/40 p-3">
                <p className="text-[10px] uppercase text-mute">Threat Categories Detected</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {event.categories.map((cat) => (
                    <span
                      key={cat}
                      className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-xs font-medium text-rose-400"
                    >
                      {cat}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </section>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-edge/70 bg-panel/70 px-6 py-3.5 text-xs text-mute">
          <span>Security Monitor Forensic View</span>
          <button
            onClick={onClose}
            className="rounded-full bg-brand px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-brand-hover"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
