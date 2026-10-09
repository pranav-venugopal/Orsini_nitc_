import { motion, useReducedMotion } from "motion/react";

export default function SignalArtwork({ className = "" }: { className?: string }) {
  const reducedMotion = useReducedMotion() ?? false;

  return (
    <div role="img" aria-label="Abstract light sculpture representing a protected AI signal" className={`signal-art relative isolate overflow-hidden rounded-[32px] ${className}`}>
      <div className="signal-art__grain absolute inset-0" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_48%,rgba(157,247,255,0.15),transparent_44%),linear-gradient(145deg,rgba(4,27,48,0.2),rgba(5,15,36,0.74))]" />
      <motion.div
        className="signal-art__orb absolute left-1/2 top-1/2 aspect-square w-[53%] -translate-x-1/2 -translate-y-1/2 rounded-full"
        animate={reducedMotion ? undefined : { rotate: 360 }}
        transition={{ duration: 36, repeat: Infinity, ease: "linear" }}
      >
        <svg aria-hidden="true" viewBox="0 0 320 320" className="size-full overflow-visible">
          <defs>
            <linearGradient id="signal-stroke" x1="34" y1="36" x2="286" y2="284" gradientUnits="userSpaceOnUse">
              <stop stopColor="#E7FEFF" stopOpacity=".9" />
              <stop offset=".48" stopColor="#67E8F9" stopOpacity=".45" />
              <stop offset="1" stopColor="#818CF8" stopOpacity=".8" />
            </linearGradient>
          </defs>
          <circle cx="160" cy="160" r="118" fill="#55DDF4" fillOpacity=".035" />
          <circle cx="160" cy="160" r="110" fill="none" stroke="url(#signal-stroke)" strokeWidth="1.2" strokeDasharray="2 8" />
          <circle cx="160" cy="160" r="82" fill="none" stroke="url(#signal-stroke)" strokeOpacity=".7" strokeWidth="1" />
          <circle cx="160" cy="160" r="55" fill="none" stroke="url(#signal-stroke)" strokeWidth="1.4" />
          <path d="M160 69v182M69 160h182M96 96l128 128M224 96 96 224" stroke="url(#signal-stroke)" strokeOpacity=".35" strokeWidth="1" />
          <path d="M160 125l28 16v32l-28 16-28-16v-32l28-16Z" fill="#B7F8FF" fillOpacity=".13" stroke="#C8FAFF" strokeOpacity=".8" strokeWidth="1.5" />
          <circle cx="160" cy="157" r="6" fill="#E5FCFF" />
          <circle cx="160" cy="157" r="19" fill="none" stroke="#B6F5FF" strokeOpacity=".72" />
        </svg>
      </motion.div>
      <motion.span
        aria-hidden="true"
        className="absolute left-[19%] top-[27%] size-2 rounded-full bg-cyan-100 shadow-[0_0_22px_5px_rgba(103,232,249,0.8)]"
        animate={reducedMotion ? undefined : { x: [0, 18, 0], y: [0, -12, 0], opacity: [0.55, 1, 0.55] }}
        transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.span
        aria-hidden="true"
        className="absolute bottom-[24%] right-[21%] size-1.5 rounded-full bg-indigo-200 shadow-[0_0_18px_4px_rgba(129,140,248,0.78)]"
        animate={reducedMotion ? undefined : { x: [0, -12, 0], y: [0, 10, 0], opacity: [0.5, 1, 0.5] }}
        transition={{ duration: 7, repeat: Infinity, ease: "easeInOut" }}
      />
      <div className="absolute inset-x-5 bottom-5 flex items-center justify-between gap-3 sm:inset-x-7 sm:bottom-7">
        <div>
          <p className="text-[9px] font-medium uppercase tracking-[0.2em] text-cyan-50/55">Private by design</p>
          <p className="mt-1 text-sm font-medium tracking-tight text-white/90 sm:text-base">Every signal, thoughtfully guarded.</p>
        </div>
        <span className="hidden rounded-full border border-white/15 bg-white/[0.07] px-3 py-1.5 text-[9px] uppercase tracking-[0.12em] text-cyan-50/70 backdrop-blur sm:block">Input · Model · Output</span>
      </div>
    </div>
  );
}
