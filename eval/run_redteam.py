"""Red-team evaluation runner.

Loads tests/red_team/payloads.json and runs every payload through GuardrailsEngine.
Measures Attack Success Rate (ASR) on malicious categories and False Refusal Rate (FRR)
on benign categories. Outputs markdown summary and writes docs/RESULTS.md.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

# Ensure repo root and backend are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from guardrails_engine import GuardrailsEngine
from prompts import CANARY, SYSTEM_PROMPT


def run_evaluation(payloads_path: Path | None = None) -> tuple[dict, str]:
    if payloads_path is None:
        payloads_path = REPO_ROOT / "tests" / "red_team" / "payloads.json"

    if not payloads_path.exists():
        raise FileNotFoundError(f"Payloads file not found at {payloads_path}")

    with open(payloads_path, "r", encoding="utf-8") as f:
        payloads = json.load(f)

    # Note on Llama Guard
    print("[INFO] Llama Guard model weights skipped for fast deterministic rule-guard evaluation.")
    engine = GuardrailsEngine(
        GuardrailsEngine.default_guards(
            use_llama_guard=False,
            canaries=[CANARY],
            system_prompt=SYSTEM_PROMPT,
        )
    )

    category_stats = defaultdict(lambda: {"total": 0, "allowed": 0, "blocked": 0, "cases": []})

    for p in payloads:
        pid = p.get("id", "unknown")
        cat = p.get("category", "unknown")
        prompt = p.get("prompt", "")

        res = engine.validate_input(prompt)

        # In GuardrailsEngine:
        # res.allowed == True means request passed through (allowed)
        # res.allowed == False means request was stopped (blocked or review)
        category_stats[cat]["total"] += 1
        if res.allowed:
            category_stats[cat]["allowed"] += 1
        else:
            category_stats[cat]["blocked"] += 1

        category_stats[cat]["cases"].append({
            "id": pid,
            "prompt": prompt,
            "allowed": res.allowed,
            "decision": res.decision,
            "categories": res.categories,
            "reason": res.reason,
        })

    # Build Markdown report
    lines = [
        "# Red-Team Benchmark & Auditing Results",
        "",
        "> **Note:** Measured against real deterministic `GuardrailsEngine` rule guards.",
        "> Model-based Llama Guard was omitted for fast, offline, reproducible benchmarking.",
        "",
        "## Summary by Category",
        "",
        "| Category | Total Cases | Allowed | Blocked / Defended | Attack Success Rate (ASR) | False Refusal Rate (FRR) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]

    total_attacks = 0
    total_attack_allowed = 0
    total_benign = 0
    total_benign_blocked = 0

    for cat, stats in sorted(category_stats.items()):
        total = stats["total"]
        allowed = stats["allowed"]
        blocked = stats["blocked"]

        if cat == "benign":
            total_benign += total
            total_benign_blocked += blocked
            frr_str = f"{(blocked / total * 100):.1f}%" if total else "N/A"
            asr_str = "N/A (Benign)"
        else:
            total_attacks += total
            total_attack_allowed += allowed
            asr_str = f"{(allowed / total * 100):.1f}%" if total else "N/A"
            frr_str = "N/A (Attack)"

        lines.append(f"| `{cat}` | {total} | {allowed} | {blocked} | {asr_str} | {frr_str} |")

    overall_asr = (total_attack_allowed / total_attacks * 100) if total_attacks else 0.0
    overall_frr = (total_benign_blocked / total_benign * 100) if total_benign else 0.0

    lines.extend([
        "",
        "### Aggregate Metrics",
        "",
        f"- **Total Attack Payloads Tested:** {total_attacks}",
        f"- **Attacks Defended (Blocked):** {total_attacks - total_attack_allowed} / {total_attacks}",
        f"- **Overall Attack Success Rate (ASR):** {overall_asr:.1f}%",
        f"- **Total Benign Prompts Tested:** {total_benign}",
        f"- **Benign Prompts Allowed:** {total_benign - total_benign_blocked} / {total_benign}",
        f"- **Overall False Refusal Rate (FRR):** {overall_frr:.1f}%",
        "",
        "## Detailed Case Breakdown",
        "",
    ])

    for cat, stats in sorted(category_stats.items()):
        lines.append(f"### Category: `{cat}`")
        lines.append("")
        for case in stats["cases"]:
            status_icon = "PASS" if ((cat == "benign" and case["allowed"]) or (cat != "benign" and not case["allowed"])) else "FAIL"
            outcome = "Allowed" if case["allowed"] else f"Blocked ({case['decision']}: {', '.join(case['categories']) or case['reason'] or 'rule'})"
            lines.append(f"- `[{status_icon}]` **{case['id']}**: *\"{case['prompt'][:70]}...\"* -> {outcome}")
        lines.append("")

    markdown_report = "\n".join(lines) + "\n"

    # Save to docs/RESULTS.md
    docs_dir = REPO_ROOT / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    results_path = docs_dir / "RESULTS.md"
    with open(results_path, "w", encoding="utf-8") as f:
        f.write(markdown_report)

    print(f"[SUCCESS] Results written to {results_path}")
    return category_stats, markdown_report


def main() -> None:
    category_stats, report = run_evaluation()
    print("\n" + report)


if __name__ == "__main__":
    main()
