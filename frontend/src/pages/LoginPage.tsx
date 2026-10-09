import { useState, type FormEvent } from "react";
import { ArrowLeft, ArrowRight, LoaderCircle, ShieldCheck } from "lucide-react";
import { motion } from "motion/react";
import { Link } from "react-router-dom";
import ThemeToggle from "../components/ThemeToggle";
import Brand from "../components/Brand";
import SignalArtwork from "../components/SignalArtwork";
import type { SessionUser } from "../types/api";

type Theme = "light" | "dark";

export default function LoginPage({ theme, onToggleTheme, onLogin }: {
  theme: Theme;
  onToggleTheme: () => void;
  onLogin: (username: string, password: string) => Promise<SessionUser>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (pending) return;
    setPending(true);
    setError("");
    try {
      await onLogin(username, password);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Sign in was unsuccessful.");
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="public-home page-enter min-h-screen overflow-hidden px-4 text-text md:px-8">
      <header className="mx-auto flex h-[76px] max-w-7xl items-center justify-between border-b border-edge/45">
        <Brand to="/" />
        <div className="flex items-center gap-3"><Link to="/" className="hidden items-center gap-2 text-xs text-mute transition-colors hover:text-text sm:inline-flex"><ArrowLeft size={14} /> Home</Link><ThemeToggle theme={theme} onToggle={onToggleTheme} /></div>
      </header>

      <main className="mx-auto grid min-h-[calc(100vh-77px)] max-w-7xl items-center gap-8 py-8 lg:grid-cols-[minmax(0,1.05fr)_minmax(350px,0.8fr)] lg:gap-14">
        <motion.div initial={{ opacity: 0, x: -14 }} animate={{ opacity: 1, x: 0 }} transition={{ duration: 0.6 }} className="relative order-2 lg:order-1">
          <p className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-[0.12em] text-accent"><span className="size-1.5 rounded-full bg-accent shadow-[0_0_12px_rgba(0,170,220,0.8)]" /> Private workspace</p>
          <h1 className="display-title font-display text-5xl font-semibold leading-[0.98] text-text sm:text-6xl lg:text-7xl">Access<br /><span className="bg-gradient-to-r from-cyan-600 via-sky-500 to-blue-700 bg-clip-text text-transparent">your space.</span></h1>
          <p className="mt-5 max-w-lg text-sm leading-6 text-mute sm:text-base">Your workspace opens according to your assigned role. Monitoring and red-team controls are restricted to administrators.</p>
          <SignalArtwork className="mt-7 h-[200px] sm:h-[260px]" />
        </motion.div>

        <motion.section initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.65, delay: 0.12 }} className="surface-glass order-1 rounded-[30px] p-6 sm:p-9 lg:order-2">
          <div className="mb-7">
            <p className="text-[10px] uppercase tracking-[0.12em] text-accent">Secure session</p>
            <h2 className="mt-2 font-display text-4xl uppercase text-text sm:text-5xl">Sign in</h2>
            <p className="mt-2 text-sm text-mute">Use the credentials assigned by your gateway administrator.</p>
          </div>
          <form onSubmit={submit} className="space-y-5">
            <div>
              <label htmlFor="username" className="mb-2 block text-xs font-medium text-text">Username</label>
              <input id="username" name="username" autoComplete="username" required maxLength={120} value={username} onChange={(event) => { setUsername(event.target.value); setError(""); }} className="auth-input w-full rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all focus:border-cyan-500 focus:ring-4 focus:ring-cyan-400/15" />
            </div>
            <div>
              <label htmlFor="password" className="mb-2 block text-xs font-medium text-text">Password</label>
              <input id="password" name="password" type="password" autoComplete="current-password" required maxLength={256} value={password} onChange={(event) => { setPassword(event.target.value); setError(""); }} aria-invalid={Boolean(error)} aria-describedby="password-error" className="auth-input w-full rounded-2xl border px-4 py-3.5 text-sm outline-none transition-all focus:border-cyan-500 focus:ring-4 focus:ring-cyan-400/15" />
            </div>
            <p id="password-error" role={error ? "alert" : undefined} className="min-h-4 text-xs text-status-error">{error}</p>
            <button type="submit" disabled={pending || !username || !password} className="group flex h-12 w-full items-center justify-center gap-2 rounded-full bg-brand px-5 text-sm font-semibold text-white shadow-[0_14px_36px_rgba(5,45,68,0.22)] transition-all hover:-translate-y-0.5 hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-50">
              {pending ? <><LoaderCircle size={16} className="animate-spin" /> Verifying</> : <>Enter workspace <ArrowRight size={16} className="transition-transform group-hover:translate-x-1" /></>}
            </button>
          </form>
          <p className="mt-4 border-t border-edge/40 pt-5 text-center text-sm text-mute">New here? <Link to="/signup" className="font-medium text-accent underline-offset-4 hover:underline">Create an account</Link></p>
          <div className="mt-5 flex items-center gap-2 text-[10px] uppercase tracking-[0.08em] text-mute"><ShieldCheck size={13} className="text-accent" /> Signed sessions / role-based access</div>
        </motion.section>
      </main>
    </div>
  );
}
