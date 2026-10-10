"""Test reproducibility and minimization of metamorphic mutation fuzzer."""
from __future__ import annotations

import json
from pathlib import Path
import pytest
import guardrails_engine as ge
from eval.metamorphic.run import run_base_suite, run_mutation_fuzzer
from prompts import CANARY, SYSTEM_PROMPT


def test_fuzzer_reproducibility(tmp_path: Path):
    """Proves that the fuzzer is deterministic: the same seed gives an identical violation list."""
    payloads_path = Path("tests/red_team/payloads.json")
    with open(payloads_path, "r", encoding="utf-8") as f:
        payloads = json.load(f)

    engine = ge.GuardrailsEngine(
        ge.GuardrailsEngine.default_guards(
            use_llama_guard=False,
            canaries=[CANARY],
            system_prompt=SYSTEM_PROMPT,
        )
    )

    _, _, baseline_caught, _ = run_base_suite(engine, payloads)
    assert len(baseline_caught) > 0

    out1 = tmp_path / "bypasses_run1.json"
    out2 = tmp_path / "bypasses_run2.json"

    violations1, top1 = run_mutation_fuzzer(
        engine=engine,
        baseline_caught=baseline_caught,
        n_fuzz=40,
        max_chain=3,
        seed_val=42,
        bypasses_out=out1,
    )

    violations2, top2 = run_mutation_fuzzer(
        engine=engine,
        baseline_caught=baseline_caught,
        n_fuzz=40,
        max_chain=3,
        seed_val=42,
        bypasses_out=out2,
    )

    assert violations1 == violations2, "Fuzzer with identical seed produced divergent violations"
    assert top1 == top2, "Fuzzer with identical seed produced divergent top chains"
    assert out1.read_text(encoding="utf-8") == out2.read_text(encoding="utf-8")
