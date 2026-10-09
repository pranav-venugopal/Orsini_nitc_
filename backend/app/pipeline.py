"""Security pipeline: input check -> generate -> output check. The backend decides; the UI only displays."""
import time
import uuid

from . import events
from .config import settings
from .redaction import redact_sensitive
from .schemas import Check, ChatRequest, ChatResponse

REFUSAL = "I can't help with that request."
BLOCKED_OUTPUT = "The generated answer was withheld by the safety check."
ERROR_MSG = "A safety check could not be completed, so the request was stopped. Please try again."


def _build():
    if settings.model_mode == "real":
        from .generator import QwenGenerator
        from .guard import LlamaGuard
        return LlamaGuard(settings.guard_model_id, settings.hf_token), QwenGenerator(settings.qwen_model_id, settings.hf_token), False
    from .generator import MockGenerator
    from .guard import MockGuard
    return MockGuard(), MockGenerator(), True


guard, generator, MOCK = _build()


def _check(text: str, role: str) -> Check:
    try:
        c = guard.classify(text, role)
        return c if c.label in ("safe", "unsafe") else Check(label="error")
    except Exception:
        return Check(label="error")  # never silently safe


def run_chat(req: ChatRequest) -> ChatResponse:
    rid = f"req_{uuid.uuid4().hex[:10]}"
    t0 = time.perf_counter()

    def ms(since: float) -> int:
        return int((time.perf_counter() - since) * 1000)

    def done(status, answer, action, ic=None, oc=None):
        resp = ChatResponse(request_id=rid, conversation_id=req.conversation_id, status=status, answer=answer,
                            input_check=ic, output_check=oc, action=action, latency_ms=ms(t0),
                            mode=req.mode, mock_models=MOCK)
        events.log_request(rid, status, req.mode, resp.latency_ms)
        return resp

    if req.mode == "baseline":
        try:
            return done("completed", generator.generate(req.message), "returned_unchecked")
        except Exception:
            return done("error", ERROR_MSG, "error")

    t = time.perf_counter()
    ic = _check(req.message, "user")
    if ic.label != "safe":
        action = "error" if ic.label == "error" else "blocked_input"
        events.log_event(rid, "input", ic.label, ic.categories, action, ms(t))
        return done("error" if ic.label == "error" else "blocked",
                    ERROR_MSG if ic.label == "error" else REFUSAL, action, ic=ic)
    events.log_event(rid, "input", "safe", [], "passed", ms(t))

    try:
        answer = generator.generate(req.message)
    except Exception:
        return done("error", ERROR_MSG, "error", ic=ic)

    t = time.perf_counter()
    sanitized_answer, sensitive_categories = redact_sensitive(answer)
    oc = _check(sanitized_answer, "assistant")
    if oc.label != "safe":
        action = "error" if oc.label == "error" else "blocked_output"
        categories = sorted(set(oc.categories + sensitive_categories))
        events.log_event(rid, "output", oc.label, categories, action, ms(t))
        # TODO(model owner): optional "safe retry" (regenerate with a stricter prompt) before blocking.
        return done("error" if oc.label == "error" else "blocked",
                    ERROR_MSG if oc.label == "error" else BLOCKED_OUTPUT, action, ic=ic,
                    oc=Check(label=oc.label, categories=categories))
    if sensitive_categories:
        oc = Check(label="unsafe", categories=sensitive_categories)
        events.log_event(rid, "output", "unsafe", sensitive_categories, "redacted", ms(t))
        return done("completed", sanitized_answer, "redacted", ic=ic, oc=oc)
    events.log_event(rid, "output", "safe", [], "passed", ms(t))
    return done("completed", sanitized_answer, "returned", ic=ic, oc=oc)
