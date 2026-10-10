"""Security pipeline: input check -> generate -> output check. The backend decides; the UI only displays."""
import logging
import time
import uuid
from typing import Any

from guardrails_engine import GuardrailsEngine, ToolCallGuard
from prompts import CANARY, SYSTEM_PROMPT
from . import events
from .config import settings
from .redaction import redact_sensitive
from .schemas import Check, ChatRequest, ChatResponse
from .session_store import session_store

REFUSAL = "I can't help with that request."
BLOCKED_OUTPUT = "The generated answer was withheld by the safety check."
ERROR_MSG = "A safety check could not be completed, so the request was stopped. Please try again."
logger = logging.getLogger(__name__)


def _build():
    if settings.model_mode == "local":
        from .generator import QwenGenerator
        from .guard import LlamaGuard
        return LlamaGuard(settings.guard_model_id), QwenGenerator(settings.qwen_model_id), False
    elif settings.model_mode == "groq":
        from .generator import GroqGenerator
        from .guard import GroqGuard
        return GroqGuard("meta-llama/llama-prompt-guard-2-86m"), GroqGenerator(), False
    from .generator import MockGenerator
    from .guard import MockGuard
    return MockGuard(), MockGenerator(), True


guard, generator, MOCK = _build()

# Unified GuardrailsEngine instance
engine = GuardrailsEngine(
    GuardrailsEngine.default_guards(
        use_llama_guard=False,  # Offline/mock default; guard.classify provides the model-based check
        canaries=[CANARY],
        system_prompt=SYSTEM_PROMPT,
    )
)
engine.add(
    ToolCallGuard(
        allowed_tools={"calculator", "fetch_url", "send_email"},
        allowed_domains={"example.com", "api.example.com"},
        max_calls_per_session=10,
    )
)


def model_diagnostics() -> dict[str, Any]:
    if MOCK:
        return {
            "model_mode": settings.model_mode,
            "mock_models": True,
            "runtime_available": False,
            "runtime_message": "The app is using stand-in models.",
            "cuda_available": None,
            "gpu_name": None,
            "gpu_memory_allocated_gib": None,
            "gpu_memory_reserved_gib": None,
            "generator": {"model_id": "mock", "loaded": False, "device_map": None, "dtype": None},
            "guard": {"model_id": "mock", "loaded": False, "device_map": None, "dtype": None},
        }

    generator_info = generator.diagnostics()
    guard_info = guard.diagnostics()
    return {
        "model_mode": settings.model_mode,
        "mock_models": False,
        "runtime_available": (
            generator_info["runtime_available"] and guard_info["runtime_available"]
        ),
        "runtime_message": (
            generator_info["runtime_message"] or guard_info["runtime_message"]
        ),
        "cuda_available": generator_info["cuda_available"],
        "gpu_name": generator_info["gpu_name"],
        "gpu_memory_allocated_gib": generator_info["gpu_memory_allocated_gib"],
        "gpu_memory_reserved_gib": generator_info["gpu_memory_reserved_gib"],
        "generator": generator_info,
        "guard": guard_info,
    }


def _check(text: str, role: str, context: str | None = None) -> Check:
    try:
        c = guard.classify(text, role, context)
        return c if c.label in ("safe", "unsafe") else Check(label="error")
    except Exception:
        logger.exception("Safety classifier failed for role %s", role)
        return Check(label="error")  # never silently safe


def _generate(message: str, model_id: str | None) -> str:
    if model_id is None:
        return generator.generate(message)
    return generator.generate(message, model_id=model_id)


def run_chat(req: ChatRequest, username: str) -> ChatResponse:
    rid = f"req_{uuid.uuid4().hex[:10]}"
    conversation_id = req.conversation_id or f"conv_{uuid.uuid4().hex[:12]}"
    t0 = time.perf_counter()

    # Load recent conversation history and session
    history = events.get_conversation_history(conversation_id, limit=20)
    session = session_store.get(conversation_id)

    persisted_message, _ = redact_sensitive(req.message)
    events.log_chat_message(rid, conversation_id, username, "user", persisted_message)

    valid_context: list[str] = []
    dropped_context: list[str] = []

    def ms(since: float) -> int:
        return int((time.perf_counter() - since) * 1000)

    def done(status, answer, action, ic=None, oc=None, dropped=None):
        resp = ChatResponse(request_id=rid, conversation_id=conversation_id, status=status, answer=answer,
                             input_check=ic, output_check=oc, action=action, latency_ms=ms(t0),
                             mode=req.mode, mock_models=MOCK,
                             dropped_context=dropped if dropped is not None else dropped_context)
        events.log_request(rid, status, req.mode, resp.latency_ms)
        persisted_answer, _ = redact_sensitive(answer)
        events.log_chat_message(rid, conversation_id, username, "assistant", persisted_answer)
        return resp

    if req.mode == "baseline":
        try:
            return done("completed", _generate(req.message, req.model_id), "returned_unchecked")
        except Exception:
            logger.exception("Baseline model generation failed")
            return done("error", ERROR_MSG, "error")

    t = time.perf_counter()

    # Validate context documents before they enter the prompt
    if req.context:
        for doc in req.context:
            c_res = engine.validate_context(doc, history=history, session=session)
            if not c_res.allowed:
                dropped_context.append(doc)
                events.log_event(rid, "context", "unsafe", c_res.categories, "blocked_context", ms(t))
                events.log_request(rid, "blocked", req.mode, ms(t0))
                session_store.save(conversation_id, session)
                return done("blocked", REFUSAL, "blocked_context", ic=Check(label="unsafe", categories=c_res.categories), dropped=dropped_context)
            else:
                valid_context.append(doc)

    # 1. Input stage: Run GuardrailsEngine input validation (de-obfuscation, injection, PII, etc.)
    r_in = engine.validate_input(req.message, history=history, session=session)
    if not r_in.allowed:
        session_store.save(conversation_id, session)
        is_error = "system" in r_in.categories
        ic_label = "error" if is_error else "unsafe"
        action = "error" if is_error else "blocked_input"
        status_val = "error" if is_error else "blocked"
        events.log_event(rid, "input", ic_label, r_in.categories, action, ms(t))
        return done(status_val,
                    ERROR_MSG if is_error else (r_in.message or REFUSAL), action,
                    ic=Check(label=ic_label, categories=r_in.categories))

    # Pattern / PII sanitization and model guard check
    effective_message = req.message
    if valid_context:
        effective_message = "Context:\n" + "\n---\n".join(valid_context) + f"\n\nQuestion: {req.message}"

    sanitized_message, input_sensitive_categories = redact_sensitive(effective_message)
    ic = _check(sanitized_message, "user")
    if ic.label != "safe":
        session_store.save(conversation_id, session)
        action = "error" if ic.label == "error" else "blocked_input"
        events.log_event(rid, "input", ic.label, ic.categories, action, ms(t))
        return done("error" if ic.label == "error" else "blocked",
                    ERROR_MSG if ic.label == "error" else REFUSAL, action, ic=ic)

    if input_sensitive_categories:
        input_sensitive_categories = sorted(input_sensitive_categories)
        ic = Check(label="safe", categories=input_sensitive_categories)
        events.log_event(rid, "input", "safe", input_sensitive_categories, "redacted", ms(t))
    else:
        ic = Check(label="safe", categories=[])
        events.log_event(rid, "input", "safe", [], "passed", ms(t))

    try:
        answer = _generate(sanitized_message, req.model_id)
    except Exception:
        logger.exception("Guarded model generation failed")
        session_store.save(conversation_id, session)
        return done("error", ERROR_MSG, "error", ic=ic)

    t = time.perf_counter()

    # 2. Output stage: Run GuardrailsEngine output validation (LeakGuard, PIIGuard, etc.)
    r_out = engine.validate_output(answer, history=(history or []) + [{"role": "user", "content": sanitized_message}], session=session)

    sanitized_answer, sensitive_categories = redact_sensitive(answer)
    oc = _check(sanitized_answer, "assistant", context=sanitized_message)

    session_store.save(conversation_id, session)

    if (not r_out.allowed) or (oc.label != "safe"):
        is_error = (oc.label == "error") or ("system" in r_out.categories)
        oc_label = "error" if is_error else "unsafe"
        action = "error" if is_error else "blocked_output"
        status_val = "error" if is_error else "blocked"
        categories = sorted(set(oc.categories + (r_out.categories if r_out else []) + sensitive_categories))
        events.log_event(rid, "output", oc_label, categories, action, ms(t))
        events.log_chat_message(rid, conversation_id, username, "attempted_output", sanitized_answer)
        return done(status_val,
                    ERROR_MSG if is_error else BLOCKED_OUTPUT, action, ic=ic,
                    oc=Check(label=oc_label, categories=categories))

    if sensitive_categories:
        oc = Check(label="unsafe", categories=sorted(sensitive_categories))
        events.log_event(rid, "output", "unsafe", sorted(sensitive_categories), "redacted", ms(t))
        return done("completed", sanitized_answer, "redacted", ic=ic, oc=oc)

    events.log_event(rid, "output", "safe", [], "passed", ms(t))
    return done("completed", sanitized_answer, "returned", ic=ic, oc=oc)
