import { useState } from "react";

export default function ChatComposer({ onSend, disabled }: { onSend: (t: string) => void; disabled: boolean }) {
  const [text, setText] = useState("");
  const submit = () => {
    if (!text.trim() || disabled) return;
    onSend(text);
    setText("");
  };
  return (
    <div className="flex items-end gap-2 border-t border-edge bg-panel p-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]">
      <label htmlFor="msg" className="sr-only">Message</label>
      <textarea id="msg" rows={1} value={text} maxLength={4000} disabled={disabled}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); } }}
        placeholder="Ask something…  (Enter to send, Shift+Enter for a new line)"
        className="max-h-40 min-h-[44px] flex-1 resize-none rounded-xl border border-edge bg-ink px-3 py-2.5 text-sm placeholder:text-mute disabled:opacity-60" />
      <button onClick={submit} disabled={disabled || !text.trim()}
        className="h-[44px] rounded-xl bg-accent px-4 text-sm font-medium text-ink disabled:cursor-not-allowed disabled:opacity-40">
        {disabled ? "Working…" : "Send"}
      </button>
    </div>
  );
}
