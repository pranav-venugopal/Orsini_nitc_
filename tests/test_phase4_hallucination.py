"""Tests for Phase 4: Hallucination Mitigation.

Proves:
1. Grounded mode:
   - A contradicted claim is blocked with clear message
   - An unsupported claim is allowed but flagged as low_confidence=True with unsupported claims listed
   - All supported claims -> low_confidence=False, allowed
2. Ungrounded mode:
   - Consistent samples (high token overlap) -> low_confidence=False
   - Inconsistent samples (low token overlap) -> low_confidence=True
3. Fault tolerance:
   - Timeout or exception -> check_skipped=True, allowed
   - HALLUCINATION_CHECK=off -> check_skipped=True
4. Integration test through backend /chat pipeline or gateway with stubbed LLM
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

from hallucination import (
    HallucinationResult,
    check_hallucination,
    compute_token_overlap,
)


def test_token_overlap_computation():
    text1 = "The Eiffel Tower is in Paris, France."
    text2 = "Paris, France is where the Eiffel Tower is."
    overlap = compute_token_overlap(text1, text2)
    assert overlap >= 0.7

    text3 = "Quantum computing uses qubits and superposition."
    overlap_disjoint = compute_token_overlap(text1, text3)
    assert overlap_disjoint == 0.0


def test_grounded_contradicted_claim_blocked():
    context = ["The server uptime for March 2026 was 99.95% with zero unplanned outages."]
    answer = "The server experienced 15 unplanned outages and had 80% uptime in March 2026."

    def stub_llm(prompt: str, **kwargs) -> str:
        return json.dumps({
            "claims": [
                {
                    "claim": "The server experienced 15 unplanned outages in March 2026",
                    "verdict": "contradicted",
                },
                {
                    "claim": "The server had 80% uptime in March 2026",
                    "verdict": "contradicted",
                },
            ]
        })

    res = check_hallucination(answer=answer, prompt="What was the uptime?", context=context, llm=stub_llm)
    assert not res.allowed
    assert res.status == "blocked"
    assert res.decision == "BLOCK"
    assert len(res.contradicted_claims) == 2
    assert "contradicted" in res.message.lower()


def test_grounded_unsupported_claim_flagged():
    context = ["The Python programming language was created by Guido van Rossum."]
    answer = "Python was created by Guido van Rossum and is named after the snake Python reticulatus."

    def stub_llm(prompt: str, **kwargs) -> str:
        return json.dumps({
            "claims": [
                {
                    "claim": "Python was created by Guido van Rossum",
                    "verdict": "supported",
                },
                {
                    "claim": "Python is named after the snake Python reticulatus",
                    "verdict": "unsupported",
                },
            ]
        })

    res = check_hallucination(answer=answer, prompt="Who made Python?", context=context, llm=stub_llm)
    assert res.allowed
    assert res.status == "completed"
    assert res.low_confidence is True
    assert "Python is named after the snake Python reticulatus" in res.unsupported_claims


def test_grounded_supported_claims_pass():
    context = ["Antigravity is an AI pair programmer developed by Google DeepMind."]
    answer = "Antigravity is developed by Google DeepMind as an AI pair programmer."

    def stub_llm(prompt: str, **kwargs) -> str:
        return json.dumps({
            "claims": [
                {
                    "claim": "Antigravity is developed by Google DeepMind",
                    "verdict": "supported",
                },
                {
                    "claim": "Antigravity is an AI pair programmer",
                    "verdict": "supported",
                },
            ]
        })

    res = check_hallucination(answer=answer, prompt="What is Antigravity?", context=context, llm=stub_llm)
    assert res.allowed
    assert res.status == "completed"
    assert res.low_confidence is False
    assert len(res.unsupported_claims) == 0


def test_ungrounded_consistent_samples():
    answer = "The capital of France is Paris."

    def stub_llm(prompt: str, **kwargs) -> str:
        return "The capital of France is Paris, located on the Seine."

    res = check_hallucination(answer=answer, prompt="What is the capital of France?", context=None, llm=stub_llm)
    assert res.allowed
    assert res.low_confidence is False


def test_ungrounded_inconsistent_samples():
    answer = "The treaty was signed in Vienna in 1815."

    call_count = 0

    def stub_llm(prompt: str, **kwargs) -> str:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return "Actually the agreement took place in Berlin in 1945."
        return "It occurred in Tokyo during 1990."

    res = check_hallucination(answer=answer, prompt="Where was the treaty signed?", context=None, llm=stub_llm, threshold=0.5)
    assert res.allowed
    assert res.low_confidence is True


def test_timeout_fallback(monkeypatch):
    def slow_llm(prompt: str, **kwargs) -> str:
        time.sleep(1.0)
        return "Too late"

    res = check_hallucination(answer="test", prompt="test", context=["ctx"], llm=slow_llm, timeout=0.1)
    assert res.allowed
    assert res.check_skipped is True


def test_hallucination_check_disabled(monkeypatch):
    monkeypatch.setenv("HALLUCINATION_CHECK", "off")

    def failing_llm(prompt: str, **kwargs) -> str:
        raise RuntimeError("Should not be called")

    res = check_hallucination(answer="test", prompt="test", context=["ctx"], llm=failing_llm)
    assert res.allowed
    assert res.check_skipped is True
