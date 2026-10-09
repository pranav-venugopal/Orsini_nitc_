import { Link } from "react-router-dom";

export default function Brand({ to = "/chat", compact = false }: { to?: string; compact?: boolean }) {
  return (
    <Link to={to} className="group inline-flex shrink-0 items-center gap-2.5" aria-label="Aegis AI home">
      <span className="brand-mark grid size-10 place-items-center rounded-[15px]">
        <svg aria-hidden="true" viewBox="0 0 32 32" fill="none" className="size-7">
          <circle cx="16" cy="16" r="10.8" stroke="currentColor" strokeWidth="1.7" opacity=".52" />
          <circle cx="16" cy="16" r="6.4" stroke="currentColor" strokeWidth="1.7" />
          <circle cx="16" cy="16" r="2.1" fill="currentColor" />
          <path d="M16 1.8v5.1M30.2 16h-5.1M16 30.2v-5.1M1.8 16h5.1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" opacity=".72" />
        </svg>
      </span>
      <span className="leading-tight">
        <span className={`block font-display font-semibold tracking-[-0.055em] text-text ${compact ? "text-lg" : "text-xl"}`}>Aegis<span className="text-accent"> AI</span></span>
        {!compact && <span className="mt-0.5 block text-[9px] font-medium uppercase tracking-[0.18em] text-mute">Private workspace</span>}
      </span>
    </Link>
  );
}
