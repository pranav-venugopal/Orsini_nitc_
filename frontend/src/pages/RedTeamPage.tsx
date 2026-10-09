import { useEffect, useState } from "react";
import { Play } from "lucide-react";
import PageArtwork from "../components/PageArtwork";
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
    <div className="page-enter mx-auto max-w-6xl space-y-7 px-4 py-6 md:px-8 md:py-9">
      <div className="flex flex-wrap items-end justify-between gap-5 border-b border-edge pb-5">
        <div>
          <p className="mb-2 text-[10px] uppercase text-mute">Adversarial test bench</p>
          <h1 className="font-display text-5xl uppercase leading-none text-text md:text-6xl">Red-team lab</h1>
          <p className="mt-3 max-w-2xl text-sm text-mute">Compare observed baseline and guarded outcomes on a fixed prompt set.</p>
        </div>
        <PageArtwork label="Adversarial testing" />
      </div>
      {error ? <ErrorState message={error} /> : !prompts ? <LoadingState /> : (
        <>
          <button onClick={run} disabled={running} className="inline-flex items-center gap-2 bg-brand px-4 py-3 text-sm font-medium text-white hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-50">
            <Play size={15} /> {running ? "Running" : `Run ${prompts.length} tests`}
          </button>
          {rows.length > 0 && (
            <>
              <div className="overflow-x-auto border border-edge bg-panel/75 shadow-[0_8px_24px_rgba(15,65,78,0.045)]">
                <table className="w-full min-w-[680px] text-left text-sm">
                  <thead className="bg-table-head text-table-head-text"><tr>
                    {["Prompt", "Category", "Baseline result", "Guarded result"].map((h) => <th key={h} scope="col" className="px-3 py-3 text-[10px] font-medium uppercase">{h}</th>)}
                  </tr></thead>
                  <tbody>{rows.map((r) => (
                    <tr key={r.prompt.id} className="border-t border-edge/80 align-top transition-colors hover:bg-table-hover">
                      <td className="max-w-md px-3 py-3">{r.prompt.prompt}</td>
                      <td className="px-3 py-3 text-xs uppercase">{r.prompt.category}</td>
                      <td className="px-3 py-3 text-xs">{r.failed ? "request failed" : outcome(r.baseline)}</td>
                      <td className="px-3 py-3 text-xs">{r.failed ? "request failed" : outcome(r.guarded)}</td>
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
