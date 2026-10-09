export default function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-edge bg-panel p-4">
      <p className="text-sm text-mute">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
    </div>
  );
}
