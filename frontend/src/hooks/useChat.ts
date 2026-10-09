import { useCallback, useRef, useState } from "react";
import { api, ApiError } from "../services/api";
import type { ChatResponse } from "../types/api";

export interface Msg {
  id: string;
  role: "user" | "assistant";
  text: string;
  response?: ChatResponse;   // present on assistant messages from the backend
  clientError?: boolean;     // network/parse failure (no backend decision)
}

export function useChat() {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [loading, setLoading] = useState(false);
  const conv = useRef<string | null>(null);

  const send = useCallback(async (text: string, modelId?: string) => {
    const trimmed = text.trim();
    if (!trimmed || loading) return;
    setMessages((m) => [...m, { id: crypto.randomUUID(), role: "user", text: trimmed }]);
    setLoading(true);
    try {
      const r = await api.chat(trimmed, conv.current, "guarded", modelId);
      conv.current = r.conversation_id ?? conv.current;
      setMessages((m) => [...m, { id: r.request_id, role: "assistant", text: r.answer, response: r }]);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Something went wrong.";
      setMessages((m) => [...m, { id: crypto.randomUUID(), role: "assistant", text: msg, clientError: true }]);
    } finally {
      setLoading(false);
    }
  }, [loading]);

  return { messages, loading, send };
}
