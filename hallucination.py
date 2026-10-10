"""Hallucination mitigation module.

Supports:
1. Grounded mode (context documents provided):
   Asks the LLM to extract factual claims and categorize them as
   supported | unsupported | contradicted.
   - Any contradicted claim -> block response with clear message.
   - Any unsupported claim -> allow response, set low_confidence=True, list unsupported claims.
2. Ungrounded mode (no context):
   Self-consistency sampling (2 extra samples at temperature 0.7).
   Compares normalized token overlap; if average agreement < threshold, sets low_confidence=True.
3. Timeout and error resilient:
   Configurable via HALLUCINATION_CHECK=on|off (default on) and timeout.
   On timeout or error, sets check_skipped=True rather than failing the request.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("hallucination")

DEFAULT_THRESHOLD = 0.5
DEFAULT_TIMEOUT = 5.0

GROUNDED_EVAL_PROMPT = """You are a strict factual consistency judge.
Given the reference documents and an answer, extract every distinct factual claim made in the answer.
For each claim, decide whether it is:
- "supported": explicitly substantiated by the reference documents.
- "unsupported": not mentioned or cannot be verified from the reference documents.
- "contradicted": directly conflicts with or is refuted by the reference documents.

Return ONLY a valid JSON object matching this schema:
{{
  "claims": [
    {{
      "claim": "claim text",
      "verdict": "supported"
    }}
  ]
}}

Reference Documents:
{documents}

Answer to evaluate:
{answer}
"""


@dataclass
class HallucinationResult:
    allowed: bool = True
    status: str = "completed"  # "completed" | "blocked"
    decision: str = "ALLOW"    # "ALLOW" | "BLOCK"
    low_confidence: bool = False
    unsupported_claims: list[str] = field(default_factory=list)
    contradicted_claims: list[str] = field(default_factory=list)
    check_skipped: bool = False
    message: str | None = None
    reason: str | None = None


def is_hallucination_check_enabled() -> bool:
    val = os.getenv("HALLUCINATION_CHECK", "on").strip().lower()
    return val in ("on", "1", "true", "yes")


def get_timeout() -> float:
    try:
        return float(os.getenv("HALLUCINATION_TIMEOUT", str(DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def get_threshold() -> float:
    try:
        return float(os.getenv("SELF_CONSISTENCY_THRESHOLD", str(DEFAULT_THRESHOLD)))
    except ValueError:
        return DEFAULT_THRESHOLD


def compute_token_overlap(text_a: str, text_b: str) -> float:
    tokens_a = set(re.findall(r"\w+", text_a.lower()))
    tokens_b = set(re.findall(r"\w+", text_b.lower()))
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a.intersection(tokens_b)
    union = tokens_a.union(tokens_b)
    return len(intersection) / len(union)


def _extract_json(raw: str) -> dict[str, Any]:
    raw = raw.strip()
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if match:
        raw = match.group(1)
    else:
        brace_start = raw.find("{")
        brace_end = raw.rfind("}")
        if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
            raw = raw[brace_start : brace_end + 1]
    return json.loads(raw)


def _sample_llm(llm: Callable[..., str], prompt: str, temperature: float = 0.7) -> str:
    try:
        return llm(prompt, temperature=temperature)
    except TypeError:
        return llm(prompt)


def _check_grounded(
    answer: str,
    context: list[str],
    llm: Callable[..., str],
) -> HallucinationResult:
    docs_formatted = "\n---\n".join(f"[{i+1}] {doc}" for i, doc in enumerate(context))
    eval_prompt = GROUNDED_EVAL_PROMPT.format(documents=docs_formatted, answer=answer)
    eval_response = _sample_llm(llm, eval_prompt, temperature=0.0)

    try:
        data = _extract_json(eval_response)
        claims = data.get("claims", [])
    except Exception as e:
        logger.warning("Failed to parse JSON claims from LLM evaluation: %s", e)
        return HallucinationResult(allowed=True, check_skipped=True)

    contradicted: list[str] = []
    unsupported: list[str] = []

    for c in claims:
        verdict = str(c.get("verdict", "")).strip().lower()
        claim_text = str(c.get("claim", "")).strip()
        if verdict == "contradicted":
            contradicted.append(claim_text)
        elif verdict == "unsupported":
            unsupported.append(claim_text)

    if contradicted:
        reasons_summary = "; ".join(contradicted)
        return HallucinationResult(
            allowed=False,
            status="blocked",
            decision="BLOCK",
            low_confidence=True,
            contradicted_claims=contradicted,
            unsupported_claims=unsupported,
            reason="claim_contradicted",
            message=f"Answer withheld: contains factual claims contradicted by reference documents ({reasons_summary}).",
        )

    if unsupported:
        return HallucinationResult(
            allowed=True,
            status="completed",
            decision="ALLOW",
            low_confidence=True,
            unsupported_claims=unsupported,
            reason="claim_unsupported",
        )

    return HallucinationResult(
        allowed=True,
        status="completed",
        decision="ALLOW",
        low_confidence=False,
        unsupported_claims=[],
    )


def _check_ungrounded(
    answer: str,
    prompt: str,
    llm: Callable[..., str],
    threshold: float,
) -> HallucinationResult:
    sample1 = _sample_llm(llm, prompt, temperature=0.7)
    sample2 = _sample_llm(llm, prompt, temperature=0.7)

    overlap1 = compute_token_overlap(answer, sample1)
    overlap2 = compute_token_overlap(answer, sample2)
    avg_overlap = (overlap1 + overlap2) / 2.0

    low_conf = avg_overlap < threshold
    return HallucinationResult(
        allowed=True,
        status="completed",
        decision="ALLOW",
        low_confidence=low_conf,
        unsupported_claims=[],
        reason="low_token_agreement" if low_conf else None,
    )


def check_hallucination(
    answer: str,
    prompt: str,
    context: list[str] | None = None,
    llm: Callable[..., str] | None = None,
    threshold: float | None = None,
    timeout: float | None = None,
) -> HallucinationResult:
    if not is_hallucination_check_enabled():
        return HallucinationResult(allowed=True, check_skipped=True)

    if llm is None:
        return HallucinationResult(allowed=True, check_skipped=True)

    t_limit = timeout if timeout is not None else get_timeout()
    t_thresh = threshold if threshold is not None else get_threshold()

    def _execute() -> HallucinationResult:
        if context and len(context) > 0:
            return _check_grounded(answer=answer, context=context, llm=llm)
        return _check_ungrounded(answer=answer, prompt=prompt, llm=llm, threshold=t_thresh)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_execute)
            return future.result(timeout=t_limit)
    except concurrent.futures.TimeoutError:
        logger.warning("Hallucination check timed out after %.2f seconds", t_limit)
        return HallucinationResult(allowed=True, check_skipped=True, reason="timeout")
    except Exception as e:
        logger.exception("Hallucination check failed with error: %s", e)
        return HallucinationResult(allowed=True, check_skipped=True, reason="error")
