import type { ChatResponse, EventsPage, Health, LoginResponse, Metrics, Mode, ModelDiagnostics, RedTeamPrompt, RequestDetails, SessionUser, ToolRequest, ToolResponse } from "../types/api";

const BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000";
const SESSION_KEY = "secure-ai-access-token";
export const CHAT_STORAGE_KEY = "aegis-chat-messages";
export const CONV_STORAGE_KEY = "aegis-chat-conversation-id";

export class ApiError extends Error {
  constructor(message: string, readonly field?: string) {
    super(message);
  }
}

function storedToken() {
  return typeof window === "undefined" ? null : window.sessionStorage.getItem(SESSION_KEY);
}

export function clearSession() {
  if (typeof window !== "undefined") {
    window.sessionStorage.removeItem(SESSION_KEY);
    window.sessionStorage.removeItem(CHAT_STORAGE_KEY);
    window.sessionStorage.removeItem(CONV_STORAGE_KEY);
  }
}

export function hasSession() {
  return Boolean(storedToken());
}

async function request<T>(path: string, init?: RequestInit, timeoutMs = 60000): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const headers = new Headers(init?.headers);
    const token = storedToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    const res = await fetch(`${BASE}${path}`, { ...init, headers, signal: ctrl.signal });
    if (!res.ok) {
      const payload = await res.json().catch(() => null) as { detail?: unknown; field?: string } | null;
      const details = Array.isArray(payload?.detail) ? payload.detail : null;
      const firstDetail = details?.[0] as { loc?: unknown[]; msg?: string } | undefined;
      const message = typeof payload?.detail === "string"
        ? payload.detail
        : firstDetail?.msg ?? `The server returned an error (${res.status}).`;
      const location = firstDetail?.loc;
      const locationField = location?.[location.length - 1];
      const field = payload?.field ?? (typeof locationField === "string" ? locationField : undefined);
      throw new ApiError(message, field);
    }
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
  async login(username: string, password: string): Promise<SessionUser> {
    const result = await request<LoginResponse>("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }, 10000);
    window.sessionStorage.setItem(SESSION_KEY, result.access_token);
    return result.user;
  },
  async register(username: string, password: string): Promise<SessionUser> {
    const result = await request<LoginResponse>("/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }, 10000);
    window.sessionStorage.setItem(SESSION_KEY, result.access_token);
    return result.user;
  },
  me: () => request<SessionUser>("/auth/me", undefined, 8000),
  async chat(message: string, conversationId: string | null, mode: Mode = "guarded", modelId?: string, context?: string[]): Promise<ChatResponse> {
    const r = await request<ChatResponse>("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({ message, conversation_id: conversationId, mode, model_id: modelId, context: context && context.length ? context : undefined }),
    }, 600000);
    if (!r || typeof r.answer !== "string" || !VALID_STATUS.includes(r.status))
      throw new ApiError("The server sent a response the app doesn't understand.");
    return r;
  },
  executeTool: (req: ToolRequest) =>
    request<ToolResponse>("/agent/tool", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    }, 15000),
  history: (conversationId?: string | null) => {
    const q = conversationId ? `?conversation_id=${encodeURIComponent(conversationId)}` : "";
    return request<{ items: Array<{ message_id: string; request_id: string; conversation_id: string; role: "user" | "assistant"; content: string; created_at: string }> }>(`/chat/history${q}`, undefined, 10000);
  },
  metrics: () => request<Metrics>("/security/metrics", undefined, 10000),
  modelDiagnostics: () => request<ModelDiagnostics>("/security/diagnostics", undefined, 10000),
  events: (p: { limit: number; offset: number; stage?: string; action?: string }) => {
    const q = new URLSearchParams({ limit: String(p.limit), offset: String(p.offset) });
    if (p.stage) q.set("stage", p.stage);
    if (p.action) q.set("action", p.action);
    return request<EventsPage>(`/security/events?${q}`, undefined, 10000);
  },
  eventDetails: (requestId: string) => request<RequestDetails>(`/security/events/${encodeURIComponent(requestId)}`, undefined, 10000),
  redteamPrompts: () => request<{ items: RedTeamPrompt[] }>("/redteam/prompts", undefined, 10000),
};
