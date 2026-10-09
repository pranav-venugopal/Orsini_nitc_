
import logging
import os
import sys
from typing import Any

# Ensure current directory is in Python path for uvicorn reloader subprocesses
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from guardrails_engine import GuardrailsEngine


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


from guardrails_engine import GuardrailsEngine, GuardrailsAIGuard, Stage
from guardrails import Guard
from llama_guard_validator import LlamaGuardSafety
from guardrails.hub import ToxicLanguage, DetectPII

# Build the engine and attach Guardrails AI
engine = GuardrailsEngine()

# Removed DetectPII and ToxicLanguage because they make remote requests
# to hub.api.guardrailsai.com which is currently failing (DNS errors).
guard_ai = (
    Guard()
    .use(LlamaGuardSafety(on_fail="exception"))
)

engine.add(GuardrailsAIGuard(guard_ai, stages=[Stage.INPUT, Stage.OUTPUT]))

REFUSAL = "Sorry, I can't help with that request."


class ChatRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="The user prompt to process.",
    )


class ChatResponse(BaseModel):
    response: str
    input_decision: str
    output_decision: str | None
    model: str
    inference: str


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
    """Check API health without forcing model loading."""
    loaded = True if INFERENCE_MODE == "groq" else llm.model is not None
    return {
        "status": "ok",
        "model": MODEL_ID if INFERENCE_MODE == "groq" else MODEL_ID,
        "inference": INFERENCE_MODE,
        "model_loaded": loaded,
    }


@app.post("/chat", response_model=ChatResponse)
def chat(request: ChatRequest) -> ChatResponse:
    """Validate the input, generate a response, and validate output."""
    try:
        response, input_result, output_result = engine.protect(
            user_text=request.prompt,
            llm=llm.generate,
            refusal=REFUSAL,
        )

        return ChatResponse(
            response=response,
            input_decision=input_result.decision,
            output_decision=(
                output_result.decision
                if output_result is not None
                else None
            ),
            model=MODEL_ID,
            inference=INFERENCE_MODE,
        )

    except Exception:
        # Full traceback is visible only in the local server terminal.
        logger.exception("Chat request failed")

        # Never expose stack traces or internal details to API clients.
        raise HTTPException(
            status_code=500,
            detail="The gateway could not process this request.",
        ) from None

