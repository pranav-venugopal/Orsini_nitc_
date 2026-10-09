// Mirrors backend/app/schemas.py. Keep in sync with the backend owner.
export type Label = "safe" | "unsafe" | "error";
export type Status = "completed" | "blocked" | "review_required" | "error";
export type Mode = "guarded" | "baseline";
export type UserRole = "admin" | "member";

export interface SessionUser { username: string; role: UserRole }

export interface Check { label: Label; categories: string[] }

export interface ChatResponse {
  request_id: string;
  conversation_id: string | null;
  status: Status;
  answer: string;
  input_check: Check | null;   // null = check not run
  output_check: Check | null;  // null = check not run
  action: string;
  latency_ms: number;
  mode: Mode;
  mock_models: boolean;
}

export interface SecurityEvent {
  event_id: string; timestamp: string; request_id: string;
  stage: "input" | "output"; label: Label; categories: string[];
  action: string; latency_ms: number;
}
export interface EventsPage { items: SecurityEvent[]; total: number; limit: number; offset: number }

export interface Metrics {
  total_requests: number; input_blocks: number; output_blocks: number; redactions: number;
  average_latency_ms: number | null; evaluation_summary: EvaluationSummary | null;
}
export interface EvaluationRates {
  attacks: number; attack_successes: number; attack_success_rate: number | null;
  benign_cases: number; false_refusals: number; false_refusal_rate: number | null;
}
export interface EvaluationSummary {
  generated_at: string; dataset_cases: number;
  baseline: EvaluationRates; guarded: EvaluationRates;
}
export interface Health { status: string; model_mode: string; mock_models: boolean }
export interface LoginResponse { access_token: string; token_type: "bearer"; user: SessionUser }
export interface RedTeamPrompt { id: string; category: "benign" | "prompt_injection" | "should_refuse"; prompt: string }
