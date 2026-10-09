import { lazy, Suspense, useEffect, useRef } from "react";
import { ArrowDownLeft, ShieldCheck } from "lucide-react";
import ChatComposer from "../components/ChatComposer";
import ChatMessage from "../components/ChatMessage";
import { PendingStatus } from "../components/SecurityStatus";
import { useChat } from "../hooks/useChat";

const CyberHeadScene = lazy(() => import("../components/CyberHeadScene"));

export default function ChatPage() {
  const { messages, loading, send } = useChat();
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => {
    end.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  return (
    <div className="page-enter mx-auto flex h-full min-h-0 w-full max-w-6xl flex-col px-4 md:px-8">
      <header className="flex items-end justify-between gap-4 border-b border-edge py-6 md:py-8">
        <div>
          <p className="mb-2 flex items-center gap-2 text-[10px] uppercase text-mute"><span className="size-1.5 bg-cyan-500" /> Protected session</p>
          <h1 className="font-display text-5xl uppercase leading-[0.88] text-text md:text-7xl">Secure AI <span className="text-accent">Assistant</span></h1>
        </div>
        <div className="hidden items-center gap-3 md:flex">
          <div className="flex items-center gap-2 border border-edge bg-panel/70 px-3 py-2 text-xs text-text">
            <ShieldCheck size={15} className="text-accent" /> Guarded mode
          </div>
        </div>
      </header>
      <div className="flex-1 space-y-5 overflow-y-auto py-5 md:py-7" aria-live="polite">
        {messages.length === 0 && (
          <div className="mx-auto my-5 grid max-w-5xl items-center gap-5 md:my-8 md:grid-cols-[minmax(0,0.9fr)_minmax(20rem,1.1fr)] md:gap-8">
            <div className="flex items-center gap-4 border-l-2 border-cyan-500 px-4 py-2 md:gap-6 md:px-6">
              <div className="hidden size-16 shrink-0 place-items-center border border-accent/30 bg-accent/10 text-accent md:grid">
              <ArrowDownLeft size={29} strokeWidth={1.5} />
            </div>
            <div>
              <h2 className="font-display text-3xl uppercase text-text md:text-4xl">Start a conversation</h2>
              <p className="mt-1 max-w-xl text-sm text-mute">Messages are screened before a response is returned.</p>
            </div>
            </div>
            <Suspense fallback={<div className="cyber-scene relative h-[190px] w-full overflow-hidden sm:h-[220px] md:h-[258px]"><img src="/HEAD.jpg" alt="" className="absolute inset-0 size-full object-cover object-[55%_42%]" /></div>}>
              <CyberHeadScene />
            </Suspense>
          </div>
        )}
        {messages.map((m) => <ChatMessage key={m.id} m={m} />)}
        {loading && <div className="border border-edge bg-panel/80 px-4 py-3 shadow-sm"><PendingStatus /></div>}
        <div ref={end} />
      </div>
      <ChatComposer onSend={send} disabled={loading} />
    </div>
  );
}
