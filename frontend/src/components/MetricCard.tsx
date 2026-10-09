import { motion, useReducedMotion } from "motion/react";

export default function MetricCard({ label, value }: { label: string; value: string }) {
  const reducedMotion = useReducedMotion() ?? false;
  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 18, scale: 0.98 }}
      whileInView={{ opacity: 1, y: 0, scale: 1 }}
      viewport={{ once: true, amount: 0.35 }}
      whileHover={reducedMotion ? undefined : { y: -4, transition: { duration: 0.24 } }}
      transition={{ duration: 0.58, ease: [0.22, 0.68, 0.25, 1] }}
      className="metric-surface relative min-w-0 overflow-hidden rounded-[20px] border p-4 sm:p-5"
    >
      <div className="metric-glint absolute left-5 top-0 h-[2px] w-14 bg-cyan-500" />
      <p className="text-[10px] uppercase text-mute">{label}</p>
      <p className="mt-2 truncate font-display text-4xl leading-none text-text sm:text-5xl">{value}</p>
    </motion.div>
  );
}
