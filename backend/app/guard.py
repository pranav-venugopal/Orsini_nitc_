"""Safety classifier. Interface = classify(text, role) -> Check.

OWNER: model/security person. Replace LlamaGuard.classify with real inference.
Rule: on any failure return Check(label="error") - never silently "safe".
"""
from .schemas import Check

# Mock rules: obviously a stand-in. Not used in real mode.
_MOCK_RULES = {
    "prompt_injection": ["ignore previous instructions", "ignore all previous", "reveal your system prompt"],
    "violent_or_weapons": ["build a bomb", "make a bomb", "make a weapon"],
    "cybercrime": ["write ransomware", "write malware", "steal passwords"],
    "demo_unsafe_output": ["unsafe_demo_output"],
}


class MockGuard:
    def classify(self, text: str, role: str) -> Check:
        low = text.lower()
        if "[demo-guard-error]" in low:
            raise RuntimeError("demo classifier failure")
        hits = [c for c, kws in _MOCK_RULES.items() if any(k in low for k in kws)]
        return Check(label="unsafe" if hits else "safe", categories=hits)


class LlamaGuard:
    def __init__(self, model_id: str, hf_token: str | None):
        # TODO(model owner): load meta-llama/Llama-Guard-3-1B with transformers, once at startup.
        raise NotImplementedError("Wire Llama Guard 3-1B here")

    def classify(self, text: str, role: str) -> Check:
        # TODO(model owner): role is "user" (input check) or "assistant" (output check).
        # Build the Llama Guard chat template, run generate, parse "safe" / "unsafe\nS1,S2".
        # Return Check(label="error") if the output cannot be parsed.
        raise NotImplementedError
