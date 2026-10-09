import { useState } from "react";
import { ArrowUp, ShieldCheck } from "lucide-react";

export default function ChatComposer({ onSend, disabled }: { onSend: (t: string) => void; disabled: boolean }) {
  const [text, setText] = useState("");
  const submit = () => {
    if (!text.trim() || disabled) return;
    onSend(text);
    setText("");
  };
  return (
    <div className="sticky bottom-0 border-t border-edge/45 bg-panel/45 px-0 py-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] backdrop-blur-2xl">
      <div className="flex items-end gap-3 rounded-[22px] border border-edge/65 bg-panel/72 p-2 shadow-[0_16px_48px_rgba(18,79,96,0.16),inset_0_1px_0_rgba(255,255,255,0.65)] backdrop-blur-2xl focus-within:border-cyan-500/80">
        <label htmlFor="msg" className="sr-only">Message</label>
        <textarea id="msg" rows={1} value={text} maxLength={4000} disabled={disabled}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(); } }}
        placeholder="Message the secure gateway"
        className="max-h-40 min-h-[44px] flex-1 resize-none bg-transparent px-3 py-2.5 text-sm text-text placeholder:text-mute disabled:opacity-60" />
        <div className="hidden items-center gap-1.5 px-2 pb-3 text-[10px] uppercase text-mute sm:flex"><ShieldCheck size={13} /> Protected</div>
        <button onClick={submit} disabled={disabled || !text.trim()} aria-label={disabled ? "Sending message" : "Send message"}
          className="flex h-11 items-center gap-2 bg-brand px-4 text-sm font-medium text-white hover:bg-brand-hover disabled:cursor-not-allowed disabled:opacity-40">
          {disabled ? "Working" : "Send"}<ArrowUp size={16} />
        </button>
      </div>
    </div>
  );
}
