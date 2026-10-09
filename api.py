
import logging
import os
import sys
from typing import Any

# Ensure current directory is in Python path for uvicorn reloader subprocesses
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from guardrails_engine import GuardrailsEngine
from hf_llm import MainLLM, MODEL_ID


# Log detailed errors to the local terminal, not to API clients.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardrail_gateway")


app = FastAPI(
    title="LLM Guardrail Gateway",
    description=(
        "An API gateway that validates prompts and LLM responses "
        "before returning them to clients."
    ),
    version="0.1.0",
)


# Initialize shared instances. Qwen loads lazily on the first
# request that passes the input guardrails.
engine = GuardrailsEngine()
llm = MainLLM()

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


@app.get("/")
def root() -> dict[str, str]:
    return {
        "name": "LLM Guardrail Gateway",
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    """Check gateway health without making an inference request."""
    return {
        "status": "ok",
        "model": MODEL_ID,
        "inference": "huggingface_hosted",
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
        )

    except Exception:
        # Full traceback is visible only in the local server terminal.
        logger.exception("Chat request failed")

        # Never expose stack traces or internal details to API clients.
        raise HTTPException(
            status_code=500,
            detail="The gateway could not process this request.",
        ) from None
