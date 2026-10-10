// Mirrors backend/app/schemas.py. Keep in sync with the backend owner.
export type Label = "safe" | "unsafe" | "error" | "review";
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
  dropped_context?: string[];
  low_confidence?: boolean;
  unsupported_claims?: string[];
  check_skipped?: boolean;
}

export interface ToolRequest {
  name: string;
  args?: Record<string, any>;
  conversation_id?: string | null;
  approve?: boolean;
}

export interface ToolResponse {
  request_id: string;
  name: string;
  status: "executed" | "blocked" | "review_required" | "error";
  decision: string;
  result?: any;
  reason?: string | null;
  message?: string | null;
  categories: string[];
}

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  request_id: string;
  stage: "input" | "output" | "tool" | "context";
  label: Label;
  categories: string[];
  action: string;
  latency_ms: number;
  user_prompt?: string | null;
  attempted_output?: string | null;
  final_output?: string | null;
  prev_hash?: string | null;
  hash?: string | null;
}
export interface EventsPage { items: SecurityEvent[]; total: number; limit: number; offset: number }

export interface Metrics {
  total_requests: number; input_blocks: number; output_blocks: number; redactions: number;
  average_latency_ms: number | null; evaluation_summary: EvaluationSummary | null;
}
export interface RuntimeDiagnostics {
  model_id: string;
  loaded: boolean;
  device_map: Record<string, string> | null;
  dtype: string | null;
  runtime_available: boolean;
  runtime_message: string | null;
  cuda_available: boolean | null;
  gpu_name: string | null;
  gpu_memory_allocated_gib: number | null;
  gpu_memory_reserved_gib: number | null;
  last_error: string | null;
}
export interface ModelDiagnostics {
  model_mode: string;
  mock_models: boolean;
  runtime_available: boolean;
  runtime_message: string | null;
  cuda_available: boolean | null;
  gpu_name: string | null;
  gpu_memory_allocated_gib: number | null;
  gpu_memory_reserved_gib: number | null;
  generator: RuntimeDiagnostics;
  guard: RuntimeDiagnostics;
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

export interface ChatMessageRecord {
  message_id: string;
  request_id: string;
  conversation_id: string;
  username: string;
  role: "user" | "assistant";
  content: string;
  created_at: string;
}

export interface RequestRecord {
  request_id: string;
  timestamp: string;
  status: Status;
  mode: Mode;
  latency_ms: number;
}

export interface RequestDetails {
  request: RequestRecord | null;
  events: SecurityEvent[];
  messages: ChatMessageRecord[];
  user_prompt?: string | null;
  attempted_output?: string | null;
  final_output?: string | null;
}

export interface RedteamLoopRound {
  round: number;
  total_attacks: number;
  bypassed: number;
  blocked: number;
  asr: number;
  new_rules_count: number;
  sample_bypasses: string[];
}

export interface RedteamLoopResult {
  timestamp: number;
  model: string;
  rounds: RedteamLoopRound[];
  initial_asr: number;
  final_asr: number;
  total_dynamic_rules: number;
}

