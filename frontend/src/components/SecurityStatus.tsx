import type { ChatResponse } from "../types/api";
import { CircleAlert, CircleCheck, CircleMinus, LoaderCircle, ShieldX } from "lucide-react";

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
const ICON = { pending: LoaderCircle, passed: CircleCheck, blocked: ShieldX, error: CircleAlert, skipped: CircleMinus };

export function PendingStatus() {
  return (
    <p role="status" className="flex items-center gap-2 text-sm text-mute">
      <LoaderCircle size={15} className="animate-spin text-cyan-700" aria-hidden />
      Checking input, generating a response and checking output…
    </p>
  );
}

export default function SecurityStatus({ r }: { r: ChatResponse }) {
  return (
    <ul aria-label="Security steps" className="flex flex-wrap gap-2 text-xs">
      {steps(r).map((s) => (
        <li key={s.name} className={`flex items-center gap-1.5 border px-2 py-1 ${s.state === "passed" ? "status-pass" : s.state === "skipped" ? "status-skip" : s.state === "error" ? "status-error" : "status-warn"}`}>
          {(() => { const Icon = ICON[s.state]; return <Icon size={13} aria-hidden />; })()}{s.name}: {TEXT[s.state]}
        </li>
      ))}
    </ul>
  );
}
