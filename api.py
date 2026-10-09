
import logging
import os
import sys
import time
import uuid
from typing import Any

# Ensure current directory is in Python path for uvicorn reloader subprocesses
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from guardrails_engine import GuardrailsEngine, LlamaGuardClassifier


# ── Inference backend selection ──────────────────────────────
# Set INFERENCE_MODE=local  for on-device Transformers (Qwen on GPU).
# Set INFERENCE_MODE=groq   for Groq cloud API (requires GROQ_API_KEY).
INFERENCE_MODE = os.getenv("INFERENCE_MODE", "groq").lower()

if INFERENCE_MODE == "local":
    from main import MainLLM, MODEL_ID
    llm = MainLLM()
elif INFERENCE_MODE == "groq":
    from groq_llm import GroqLLM, GROQ_MODEL_ID as MODEL_ID
    llm = GroqLLM()
else:
    raise ValueError(
        f"Unknown INFERENCE_MODE='{INFERENCE_MODE}'. Use 'local' or 'groq'."
    )


# Log detailed errors to the local terminal, not to API clients.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardrail_gateway")


app = FastAPI(
    title="LLM Guardrail Gateway",
    description=(
        "An API gateway that validates prompts and LLM responses "
        "before returning them to clients."
    ),
    version="0.2.0",
)


# Llama Guard is a native engine guard, not a generation backend.  It is lazy
# loaded by its first input/output check and reused for the lifetime of the app.
engine = GuardrailsEngine(
    GuardrailsEngine.default_guards(
        use_llama_guard=True,
        llama_guard_model_id=os.getenv("LLAMA_GUARD_MODEL_ID", "meta-llama/Llama-Guard-3-1B"),
    )
)

REFUSAL = "Sorry, I can't help with that request."


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=10_000)
    conversation_id: str | None = None
    mode: str = "guarded"

class ChatResponse(BaseModel):
    request_id: str
    conversation_id: str | None = None
    status: str
    answer: str
    input_check: dict | None = None
    output_check: dict | None = None
    action: str
    latency_ms: int
    mode: str
    mock_models: bool
    # Legacy gateway fields are retained for API consumers that predate the UI.
    response: str
    input_decision: str
    output_decision: str | None = None
    model: str
    inference: str


def _safety_classifier() -> LlamaGuardClassifier:
    for guard in engine.guards:
        if isinstance(guard, LlamaGuardClassifier):
            return guard
    raise RuntimeError("Llama Guard is not configured")


def _check_payload(result):
    if result is None:
        return None
    if result.decision in {"ALLOW", "REDACT"}:
        label = "safe"
    elif "system" in result.categories:
        label = "error"
    else:
        label = "unsafe"
    return {"label": label, "categories": result.categories}


def _result_status(input_result, output_result) -> tuple[str, str]:
    blocked = input_result if not input_result.allowed else output_result
    if blocked is None or blocked.allowed:
        return "completed", "redacted" if blocked and blocked.decision == "REDACT" else "returned"
    if blocked.decision == "REVIEW":
        return "review_required", "review"
    if "system" in blocked.categories:
        return "error", "error"
    return "blocked", "blocked_input" if blocked.stage == "input" else "blocked_output"


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "LLM Guardrail Gateway",
        "status": "running",
        "inference": INFERENCE_MODE,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    """Report generation and mandatory safety readiness without exposing errors."""
    safety = _safety_classifier().readiness()
    generation_loaded = INFERENCE_MODE == "groq" or llm.model is not None
    return {
        "status": "ok" if safety["ready"] else "degraded",
        "model_mode": INFERENCE_MODE,
        "mock_models": False,
        "model": MODEL_ID,
        "inference": INFERENCE_MODE,
        "model_loaded": generation_loaded,
        "generation": {"backend": INFERENCE_MODE, "model": getattr(llm, "model_id", MODEL_ID), "ready": generation_loaded},
        "safety_classifier": safety,
        "ready": bool(generation_loaded and safety["ready"]),
    }

@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest) -> ChatResponse:
    t0 = time.perf_counter()
    try:
        response, input_result, output_result = engine.protect(
            user_text=req.message,
            llm=llm.generate,
            refusal=REFUSAL,
        )
        latency = int((time.perf_counter() - t0) * 1000)
        status, action = _result_status(input_result, output_result)
        return ChatResponse(
            request_id=f"req_{uuid.uuid4().hex[:10]}",
            conversation_id=req.conversation_id,
            status=status,
            answer=response,
            input_check=_check_payload(input_result),
            output_check=_check_payload(output_result),
            action=action,
            latency_ms=latency,
            mode=req.mode,
            mock_models=False,
            response=response,
            input_decision=input_result.decision,
            output_decision=output_result.decision if output_result is not None else None,
            model=getattr(llm, "model_id", MODEL_ID),
            inference=INFERENCE_MODE,
        )

    except Exception:
        logger.exception("Chat request failed")
        raise HTTPException(status_code=500, detail="The gateway could not process this request.") from None

# Stubs for frontend compatibility
@app.post("/auth/login")
def login(): return {"access_token": "demo", "token_type": "bearer", "user": {"username": "admin", "role": "admin"}}
@app.post("/auth/register")
def register(): return {"access_token": "demo", "token_type": "bearer", "user": {"username": "admin", "role": "admin"}}
@app.get("/auth/me")
def me(): return {"username": "admin", "role": "admin"}
@app.get("/security/metrics")
def metrics(): return {"total_requests": 0, "input_blocks": 0, "output_blocks": 0, "redactions": 0, "average_latency_ms": 0}
@app.get("/security/diagnostics")
def diagnostics(): return {"model_mode": INFERENCE_MODE, "mock_models": False, "runtime_available": True}
@app.get("/security/events")
def events(): return {"items": [], "total": 0, "limit": 25, "offset": 0}
@app.get("/redteam/prompts")
def redteam(): return {"items": []}
