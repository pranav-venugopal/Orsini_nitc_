export function LoadingState({ label = "Loading…" }: { label?: string }) {
  return <p role="status" className="py-10 text-center text-mute">{label}</p>;
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="alert-panel border bg-panel p-5 text-center text-text shadow-sm">
      <p className="font-medium">Couldn't load this data</p>
      <p className="mt-1 text-sm text-mute">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-3 border border-edge bg-panel px-3 py-2 text-sm hover:border-cyan-600">
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="border border-dashed border-edge bg-panel/40 p-8 text-center">
      <p className="font-medium">{title}</p>
      <p className="mt-1 text-sm text-mute">{hint}</p>
    </div>
  );
}
