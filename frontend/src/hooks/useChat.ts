import { useCallback, useEffect, useState } from "react";
import { api, ApiError, CHAT_STORAGE_KEY, CONV_STORAGE_KEY } from "../services/api";
import type { ChatResponse } from "../types/api";

export interface Msg {
  id: string;
  role: "user" | "assistant";
  text: string;
  response?: ChatResponse;   // present on assistant messages from the backend
  clientError?: boolean;     // network/parse failure (no backend decision)
}

function loadInitialMessages(): Msg[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.sessionStorage.getItem(CHAT_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function loadInitialConvId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage.getItem(CONV_STORAGE_KEY) || null;
  } catch {
    return null;
  }
}

// Module-level persistent state across route unmounts
let cachedMessages: Msg[] = loadInitialMessages();
let cachedConvId: string | null = loadInitialConvId();
let cachedLoading = false;
const listeners = new Set<(state: { messages: Msg[]; loading: boolean; convId: string | null }) => void>();

function notify() {
  const state = { messages: cachedMessages, loading: cachedLoading, convId: cachedConvId };
  listeners.forEach((listener) => listener(state));
  if (typeof window !== "undefined") {
    try {
      window.sessionStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(cachedMessages));
      if (cachedConvId) {
        window.sessionStorage.setItem(CONV_STORAGE_KEY, cachedConvId);
      } else {
        window.sessionStorage.removeItem(CONV_STORAGE_KEY);
      }
    } catch {
      // ignore storage quota issues
    }
  }
}

export function resetChatCache() {
  cachedMessages = [];
  cachedConvId = null;
  cachedLoading = false;
  notify();
}

export function useChat() {
  const [messages, setMessages] = useState<Msg[]>(cachedMessages);
  const [loading, setLoading] = useState(cachedLoading);

  useEffect(() => {
    const listener = (state: { messages: Msg[]; loading: boolean; convId: string | null }) => {
      setMessages(state.messages);
      setLoading(state.loading);
    };
    listeners.add(listener);

    // Synchronize current cache immediately on mount
    setMessages(cachedMessages);
    setLoading(cachedLoading);

    // If cache is empty in this session but we have a stored conversation id, attempt DB history restore
    if (cachedMessages.length === 0 && cachedConvId) {
      api.history(cachedConvId)
        .then((res) => {
          if (res.items && res.items.length > 0 && cachedMessages.length === 0) {
            cachedMessages = res.items.map((item) => ({
              id: item.message_id || item.request_id || crypto.randomUUID(),
              role: item.role,
              text: item.content,
            }));
            notify();
          }
        })
        .catch(() => {
          // Ignore history fetch errors silently
        });
    }

    return () => {
      listeners.delete(listener);
    };
  }, []);

  const send = useCallback(async (text: string, modelId?: string) => {
    const trimmed = text.trim();
    if (!trimmed || cachedLoading) return;

    const userMsg: Msg = { id: crypto.randomUUID(), role: "user", text: trimmed };
    cachedMessages = [...cachedMessages, userMsg];
    cachedLoading = true;
    notify();

    try {
      const r = await api.chat(trimmed, cachedConvId, "guarded", modelId);
      if (r.conversation_id) {
        cachedConvId = r.conversation_id;
      }
      cachedMessages = [
        ...cachedMessages,
        { id: r.request_id || crypto.randomUUID(), role: "assistant", text: r.answer, response: r },
      ];
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Something went wrong.";
      cachedMessages = [
        ...cachedMessages,
        { id: crypto.randomUUID(), role: "assistant", text: msg, clientError: true },
      ];
    } finally {
      cachedLoading = false;
      notify();
    }
  }, []);

  const clear = useCallback(() => {
    resetChatCache();
  }, []);

  return { messages, loading, send, clear };
}
