export default function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="relative min-w-0 overflow-hidden border border-edge bg-panel/75 p-4 shadow-[0_8px_24px_rgba(15,65,78,0.045)] backdrop-blur-sm">
      <div className="absolute left-0 top-0 h-[2px] w-12 bg-cyan-500" />
      <p className="text-[10px] uppercase text-mute">{label}</p>
      <p className="mt-2 truncate font-display text-4xl leading-none text-text">{value}</p>
    </div>
  );
}
