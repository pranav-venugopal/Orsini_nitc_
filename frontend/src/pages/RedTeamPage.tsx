import { useEffect, useState } from "react";
import { ErrorState, LoadingState } from "../components/States";
import { api, ApiError } from "../services/api";
import type { ChatResponse, Mode, RedTeamPrompt } from "../types/api";

type Row = { prompt: RedTeamPrompt; baseline?: ChatResponse; guarded?: ChatResponse; failed?: boolean };

const outcome = (r?: ChatResponse) => (!r ? "—" : `${r.status} (${r.action})`);

export default function RedTeamPage() {
  const [prompts, setPrompts] = useState<RedTeamPrompt[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    api.redteamPrompts().then((r) => setPrompts(r.items)).catch((e) => setError(e instanceof ApiError ? e.message : "Unexpected error."));
  }, []);

  const run = async () => {
    if (!prompts) return;
    setRunning(true); setRows([]);
    for (const p of prompts) {
      const row: Row = { prompt: p };
      try {
        for (const mode of ["baseline", "guarded"] as Mode[]) row[mode] = await api.chat(p.prompt, null, mode);
      } catch { row.failed = true; }
      setRows((r) => [...r, row]);
    }
    setRunning(false);
  };

  // Rates are computed only from this defined prompt set, using the observed results above.
  const done = rows.filter((r) => r.guarded && !r.failed);
  const attacks = done.filter((r) => r.prompt.category !== "benign");
  const benign = done.filter((r) => r.prompt.category === "benign");
  const notBlocked = attacks.filter((r) => r.guarded!.status === "completed").length;
  const refused = benign.filter((r) => r.guarded!.status !== "completed").length;

  return (
    <div className="mx-auto max-w-5xl space-y-5 p-4 md:p-6">
      <h1 className="text-xl font-semibold">Red-team playground</h1>
      <p className="text-sm text-mute">Runs a fixed set of approved prompts through the baseline and the guarded pipeline, and shows what the backend actually did.</p>
      {error ? <ErrorState message={error} /> : !prompts ? <LoadingState /> : (
        <>
          <button onClick={run} disabled={running} className="rounded-xl bg-accent px-4 py-2 text-sm font-medium text-ink disabled:opacity-40">
            {running ? "Running…" : `Run ${prompts.length} test prompts`}
          </button>
          {rows.length > 0 && (
            <>
              <div className="overflow-x-auto rounded-xl border border-edge">
                <table className="w-full min-w-[680px] text-left text-sm">
                  <thead className="bg-node text-mute"><tr>
                    {["Prompt", "Category", "Baseline result", "Guarded result"].map((h) => <th key={h} scope="col" className="px-3 py-2 font-medium">{h}</th>)}
                  </tr></thead>
                  <tbody>{rows.map((r) => (
                    <tr key={r.prompt.id} className="border-t border-edge align-top">
                      <td className="px-3 py-2">{r.prompt.prompt}</td>
                      <td className="px-3 py-2">{r.prompt.category}</td>
                      <td className="px-3 py-2">{r.failed ? "request failed" : outcome(r.baseline)}</td>
                      <td className="px-3 py-2">{r.failed ? "request failed" : outcome(r.guarded)}</td>
                    </tr>))}
                  </tbody>
                </table>
              </div>
              <p className="text-sm text-mute">
                On this {rows.length}-prompt set (guarded pipeline): attack prompts not blocked {notBlocked}/{attacks.length}; benign prompts refused {refused}/{benign.length}.
                A small demo set, not a benchmark.
              </p>
            </>
          )}
        </>
      )}
    </div>
  );
}
