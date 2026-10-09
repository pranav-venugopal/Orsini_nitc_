import type { ChatResponse } from "../types/api";

type StepState = "pending" | "passed" | "blocked" | "error" | "skipped";

// Every state is derived ONLY from fields the backend returned.
function steps(r: ChatResponse): { name: string; state: StepState }[] {
  const chk = (c: ChatResponse["input_check"]): StepState =>
    c === null ? "skipped" : c.label === "safe" ? "passed" : c.label === "unsafe" ? "blocked" : "error";
  const input = chk(r.input_check);
  const output = chk(r.output_check);
  const generated = input === "blocked" || input === "error" ? "skipped" : r.action === "error" && r.output_check === null ? "error" : "passed";
  return [
    { name: "Input check", state: input },
    { name: "Response generated", state: generated },
    { name: "Output check", state: output },
  ];
}

const TEXT: Record<StepState, string> = { pending: "Running", passed: "Passed", blocked: "Blocked", error: "Failed", skipped: "Not run" };
const ICON: Record<StepState, string> = { pending: "…", passed: "✓", blocked: "✕", error: "!", skipped: "–" };

export function PendingStatus() {
  return (
    <p role="status" className="flex items-center gap-2 text-sm text-mute">
      <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-accent" aria-hidden />
      Checking input, generating a response and checking output…
    </p>
  );
}

export default function SecurityStatus({ r }: { r: ChatResponse }) {
  return (
    <ul aria-label="Security steps" className="flex flex-wrap gap-2 text-xs">
      {steps(r).map((s) => (
        <li key={s.name} className={`rounded-full border px-2.5 py-1 ${s.state === "passed" ? "border-accent/60 text-accent" : s.state === "skipped" ? "border-edge text-mute" : "border-amber-400/60 text-amber-200"}`}>
          <span aria-hidden>{ICON[s.state]} </span>{s.name}: {TEXT[s.state]}
        </li>
      ))}
    </ul>
  );
}
