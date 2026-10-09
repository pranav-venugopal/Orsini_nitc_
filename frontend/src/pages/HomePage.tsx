import { lazy, Suspense } from "react";
import { ArrowDown, ArrowRight, ShieldCheck } from "lucide-react";
import { motion, useReducedMotion } from "motion/react";
import { Link } from "react-router-dom";
import ThemeToggle from "../components/ThemeToggle";

const CyberHeadScene = lazy(() => import("../components/CyberHeadScene"));
type Theme = "light" | "dark";

export default function HomePage({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  const reducedMotion = useReducedMotion() ?? false;
  return (
    <div className="public-home page-enter min-h-screen overflow-hidden px-4 text-text md:px-8">
      <header className="mx-auto flex h-[76px] max-w-7xl items-center justify-between border-b border-edge/45">
        <Link to="/" className="flex items-center gap-2.5" aria-label="Secure AI home">
          <span className="grid size-10 place-items-center rounded-2xl border border-accent/35 bg-accent/10 text-accent shadow-[0_0_24px_rgba(0,174,225,0.18)]"><ShieldCheck size={21} /></span>
          <span><span className="block font-display text-2xl uppercase leading-none">Secure AI</span><span className="mt-1 block text-[9px] uppercase tracking-[0.1em] text-mute">Defense gateway</span></span>
        </Link>
        <nav className="flex items-center gap-2 sm:gap-4" aria-label="Public navigation">
          <a href="#controls" className="hidden rounded-full px-4 py-2 text-xs text-mute transition-colors hover:text-text sm:inline-flex">Platform</a>
          <Link to="/login" className="inline-flex items-center gap-2 rounded-full bg-brand px-4 py-2.5 text-xs font-semibold text-white shadow-lg shadow-cyan-950/15 transition-all hover:-translate-y-0.5 hover:bg-brand-hover sm:px-5">Sign in <ArrowRight size={14} /></Link>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        </nav>
      </header>

      <main className="mx-auto max-w-7xl">
        <section className="grid min-h-[650px] items-center gap-8 py-10 lg:grid-cols-[minmax(360px,0.84fr)_minmax(0,1.16fr)] lg:gap-5 lg:py-12">
          <motion.div
            initial={reducedMotion ? false : { opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: [0.22, 0.68, 0.25, 1] }}
            className="relative z-10"
          >
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-accent/25 bg-panel/50 px-3 py-2 text-[10px] uppercase tracking-[0.08em] text-mute shadow-[0_8px_24px_rgba(8,84,118,0.08)] backdrop-blur-xl">
              <span className="relative flex size-2"><span className="absolute inline-flex size-full animate-ping rounded-full bg-cyan-400 opacity-50" /><span className="relative inline-flex size-2 rounded-full bg-cyan-500" /></span>
              AI security / response gateway
            </div>
            <h1 className="display-title max-w-2xl font-display text-7xl uppercase leading-[0.78] text-text sm:text-8xl lg:text-[108px]">
              Defend<br /><span className="bg-gradient-to-r from-cyan-600 via-sky-500 to-blue-700 bg-clip-text text-transparent">every</span><br />request.
            </h1>
            <p className="mt-7 max-w-lg text-base leading-7 text-mute sm:text-lg">
              A controlled path between people and models. Inspect every prompt, response, and policy decision before it reaches your application.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link to="/login" className="group inline-flex items-center gap-3 rounded-full bg-brand px-6 py-3.5 text-sm font-semibold text-white shadow-[0_14px_36px_rgba(5,45,68,0.24)] transition-all duration-300 hover:-translate-y-1 hover:bg-brand-hover">
                Enter the gateway <ArrowRight size={16} className="transition-transform group-hover:translate-x-1" />
              </Link>
              <a href="#controls" className="inline-flex items-center gap-2 rounded-full border border-edge/70 bg-panel/48 px-5 py-3.5 text-sm text-text/80 backdrop-blur-lg transition-all hover:-translate-y-0.5 hover:border-accent/50">
                Explore controls <ArrowDown size={15} />
              </a>
            </div>
            <div className="mt-10 flex items-center gap-3 text-xs text-mute">
              <span className="grid size-8 place-items-center rounded-full border border-accent/25 bg-panel/45 text-accent"><ShieldCheck size={15} /></span>
              Fail-closed checks <span className="text-accent/55">·</span> Minimal audit data <span className="text-accent/55">·</span> Measured results
            </div>
          </motion.div>

          <motion.div
            initial={reducedMotion ? false : { opacity: 0, scale: 0.96, x: 18 }}
            animate={{ opacity: 1, scale: 1, x: 0 }}
            transition={{ duration: 0.9, delay: 0.12, ease: [0.2, 0.7, 0.2, 1] }}
            className="relative lg:-mr-12"
          >
            <div className="pointer-events-none absolute -inset-x-8 inset-y-8 rounded-[48px] bg-cyan-400/12 blur-3xl" />
            <Suspense fallback={<div className="cyber-scene h-[320px] rounded-[32px] sm:h-[420px] lg:h-[520px]"><img src="/HEAD.jpg" alt="" className="size-full rounded-[32px] object-cover object-[55%_42%]" /></div>}>
              <CyberHeadScene className="h-[320px] rounded-[32px] shadow-[0_40px_100px_rgba(0,55,85,0.22)] sm:h-[420px] lg:h-[520px]" />
            </Suspense>
            <div className="pointer-events-none absolute -bottom-5 left-4 hidden rounded-2xl border border-white/55 bg-panel/62 px-4 py-3 text-xs text-text shadow-[0_20px_60px_rgba(6,54,78,0.14)] backdrop-blur-2xl sm:block lg:left-0">
              <p className="text-[9px] uppercase tracking-[0.1em] text-mute">Gateway status</p>
              <p className="mt-1 flex items-center gap-2 font-medium"><span className="size-1.5 rounded-full bg-emerald-500 shadow-[0_0_9px_rgba(16,185,129,0.8)]" />Policy enforced</p>
            </div>
            <div className="pointer-events-none absolute -right-1 top-8 hidden rounded-2xl border border-white/55 bg-panel/56 px-4 py-3 text-xs text-text shadow-[0_20px_60px_rgba(6,54,78,0.12)] backdrop-blur-2xl sm:block lg:right-1">
              <p className="text-[9px] uppercase tracking-[0.1em] text-mute">Trace</p>
              <p className="mt-1 font-mono text-accent">INPUT / MODEL / OUTPUT</p>
            </div>
          </motion.div>
        </section>

        <section id="controls" className="mb-10 scroll-mt-8 rounded-[30px] border border-white/45 bg-panel/38 px-5 py-7 shadow-[0_24px_70px_rgba(10,69,98,0.08)] backdrop-blur-2xl sm:px-8 lg:px-10">
          <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
            <div><p className="text-[10px] uppercase tracking-[0.12em] text-accent">Inside the gateway</p><h2 className="mt-2 font-display text-4xl uppercase text-text sm:text-5xl">Control at every layer</h2></div>
            <Link to="/login" className="group inline-flex items-center gap-2 pb-1 text-sm text-mute transition-colors hover:text-accent">Open workspace <ArrowRight size={15} className="transition-transform group-hover:translate-x-1" /></Link>
          </div>
          <div className="grid divide-y divide-edge/45 md:grid-cols-3 md:divide-x md:divide-y-0">
            {[
              ["01", "Inspect", "Screen input before it reaches the model."],
              ["02", "Constrain", "Check generated output before returning it."],
              ["03", "Measure", "Compare guarded results with the baseline."],
            ].map(([number, title, text], index) => (
              <motion.div key={number} initial={reducedMotion ? false : { opacity: 0, y: 12 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: index * 0.1, duration: 0.5 }} className="flex gap-4 py-5 md:px-6 md:py-2 first:md:pl-0 last:md:pr-0">
                <span className="font-display text-2xl text-accent/70">{number}</span>
                <div><h3 className="font-display text-2xl uppercase text-text">{title}</h3><p className="mt-1 max-w-xs text-sm text-mute">{text}</p></div>
              </motion.div>
            ))}
          </div>
        </section>
        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-edge/45 py-5 text-[10px] uppercase tracking-[0.08em] text-mute"><span>Secure AI / Defense gateway</span><span>Safe systems are measured, not assumed.</span></footer>
      </main>
    </div>
  );
}
