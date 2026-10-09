import { useEffect, useRef } from "react";
import ChatComposer from "../components/ChatComposer";
import ChatMessage from "../components/ChatMessage";
import { PendingStatus } from "../components/SecurityStatus";
import { useChat } from "../hooks/useChat";

export default function ChatPage() {
  const { messages, loading, send } = useChat();
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => {
    end.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 space-y-4 overflow-y-auto p-4 md:p-6" aria-live="polite">
        {messages.length === 0 && (
          <div className="mx-auto mt-16 max-w-md text-center">
            <h1 className="text-xl font-semibold">Ask anything</h1>
            <p className="mt-2 text-sm text-mute">Every prompt and answer goes through the backend's safety checks. You'll see what each check returned under the reply.</p>
          </div>
        )}
        {messages.map((m) => <ChatMessage key={m.id} m={m} />)}
        {loading && <div className="rounded-2xl bg-panel px-4 py-3 ring-1 ring-edge"><PendingStatus /></div>}
        <div ref={end} />
      </div>
      <ChatComposer onSend={send} disabled={loading} />
    </div>
  );
}
