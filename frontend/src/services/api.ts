import type { ChatResponse, EventsPage, Health, Metrics, Mode, RedTeamPrompt } from "../types/api";

const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";

export class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit, timeoutMs = 60000): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${BASE}${path}`, { ...init, signal: ctrl.signal });
    if (!res.ok) throw new ApiError(`The server returned an error (${res.status}).`);
    return (await res.json()) as T;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    if (e instanceof DOMException && e.name === "AbortError") throw new ApiError("The request timed out. Try again.");
    throw new ApiError("Can't reach the backend. Check that it's running and VITE_API_BASE_URL is correct.");
  } finally {
    clearTimeout(timer);
  }
}

const VALID_STATUS = ["completed", "blocked", "review_required", "error"];

export const api = {
  health: () => request<Health>("/health", undefined, 8000),
  async chat(message: string, conversationId: string | null, mode: Mode = "guarded"): Promise<ChatResponse> {
    const r = await request<ChatResponse>("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, conversation_id: conversationId, mode }),
    });
    if (!r || typeof r.answer !== "string" || !VALID_STATUS.includes(r.status))
      throw new ApiError("The server sent a response the app doesn't understand.");
    return r;
  },
  metrics: () => request<Metrics>("/security/metrics", undefined, 10000),
  events: (p: { limit: number; offset: number; stage?: string; action?: string }) => {
    const q = new URLSearchParams({ limit: String(p.limit), offset: String(p.offset) });
    if (p.stage) q.set("stage", p.stage);
    if (p.action) q.set("action", p.action);
    return request<EventsPage>(`/security/events?${q}`, undefined, 10000);
  },
  redteamPrompts: () => request<{ items: RedTeamPrompt[] }>("/redteam/prompts", undefined, 10000),
};
