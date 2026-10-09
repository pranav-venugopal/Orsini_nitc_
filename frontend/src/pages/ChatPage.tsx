import { useEffect, useRef, useState } from "react";
import ChatComposer from "../components/ChatComposer";
import ChatMessage from "../components/ChatMessage";
import { PendingStatus } from "../components/SecurityStatus";
import { useChat } from "../hooks/useChat";

export default function ChatPage() {
  const { messages, loading, send } = useChat();
  const [modelId, setModelId] = useState("openai/gpt-oss-20b");
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => {
    end.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const handleSend = (text: string) => {
    send(text, modelId);
  };

  return (
    <div className="page-enter mx-auto flex h-full min-h-0 w-full max-w-4xl flex-col px-4 md:px-8">
      <div className="flex shrink-0 items-center justify-between gap-3 py-5">
        <div>
          <p className="mb-1 text-[10px] font-medium uppercase tracking-[0.16em] text-accent">Private workspace</p>
          <div className="flex items-center gap-3">
            <h1 className="font-display text-xl font-medium tracking-tight text-text sm:text-2xl">Aegis assistant</h1>
            <select
              value={modelId}
              onChange={(e) => setModelId(e.target.value)}
              className="ml-2 rounded-md border border-edge/60 bg-panel/55 px-2 py-1 text-xs text-mute outline-none focus:border-cyan-500"
              aria-label="Select Model"
            >
              <option value="openai/gpt-oss-20b">GPT OSS 20B (OpenAI)</option>
              <option value="openai/gpt-oss-120b">GPT OSS 120B (OpenAI)</option>
              <option value="qwen/qwen3.8-27b">Qwen 3.8 27B</option>
            </select>
          </div>
        </div>
        <span className="rounded-full border border-edge/60 bg-panel/55 px-3 py-1.5 text-[10px] text-mute backdrop-blur">Guarded mode</span>
      </div>
      <div className="chat-transcript flex-1 space-y-5 overflow-y-auto py-5 md:py-7" aria-live="polite">
        {messages.length === 0 && (
          <div className="mx-auto flex min-h-full max-w-2xl flex-col justify-center pb-12">
            <div className="mb-5 grid size-12 place-items-center rounded-[18px] border border-accent/20 bg-accent/[0.08] text-accent shadow-[0_8px_30px_rgba(25,157,193,0.12)]"><span className="brand-mark grid size-full place-items-center rounded-[18px]"><svg aria-hidden="true" viewBox="0 0 32 32" fill="none" className="size-7"><circle cx="16" cy="16" r="10.8" stroke="currentColor" strokeWidth="1.7" opacity=".52" /><circle cx="16" cy="16" r="6.4" stroke="currentColor" strokeWidth="1.7" /><circle cx="16" cy="16" r="2.1" fill="currentColor" /></svg></span></div>
            <h2 className="font-display text-3xl font-medium tracking-[-0.045em] text-text sm:text-4xl">What can I help you explore?</h2>
            <p className="mt-3 max-w-lg text-sm leading-6 text-mute">Your messages are screened before they reach the model, and responses are checked before they return.</p>
          </div>
        )}
        {messages.map((m) => <ChatMessage key={m.id} m={m} />)}
        {loading && <div className="border border-edge bg-panel/80 px-4 py-3 shadow-sm"><PendingStatus /></div>}
        <div ref={end} />
      </div>
      <div className="shrink-0 pb-3">
        <ChatComposer onSend={handleSend} disabled={loading} />
        <p className="mt-2 text-center text-[10px] text-mute/80">AI can make mistakes. Review important information before relying on it.</p>
      </div>
    </div>
  );
}
