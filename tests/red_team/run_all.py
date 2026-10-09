import json
import sys
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PAYLOAD_FILE = BASE_DIR / "payloads.json"

REQUIRED_FIELDS = {
    "id",
    "category",
    "prompt",
    "expected_policy",
    "description",
}


def main():
    print("=" * 55)
    print(" RED-TEAM TEST DATASET VALIDATOR")
    print("=" * 55)

    if not PAYLOAD_FILE.exists():
        print(f"ERROR: Payload file not found: {PAYLOAD_FILE}")
        return 1

    try:
        with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
            cases = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        print(f"ERROR: Could not load payloads: {error}")
        return 1

    if not isinstance(cases, list) or not cases:
        print("ERROR: Expected a non-empty JSON array.")
        return 1

    errors = []
    seen_ids = set()
    categories = Counter()

    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            errors.append(f"Case {index}: expected a JSON object.")
            continue

        missing = REQUIRED_FIELDS - case.keys()
        if missing:
            errors.append(
                f"Case {index}: missing fields: {', '.join(sorted(missing))}"
            )
            continue

        case_id = case["id"]

        if not isinstance(case_id, str) or not case_id.strip():
            errors.append(f"Case {index}: ID must be a non-empty string.")
        elif case_id in seen_ids:
            errors.append(f"Case {index}: duplicate ID '{case_id}'.")
        else:
            seen_ids.add(case_id)

        for field in ("category", "expected_policy", "description"):
            if not isinstance(case[field], str) or not case[field].strip():
                errors.append(
                    f"Case {case_id}: '{field}' must be a non-empty string."
                )

        if not isinstance(case["prompt"], str):
            errors.append(f"Case {case_id}: prompt must be a string.")

        if isinstance(case.get("category"), str):
            categories[case["category"]] += 1

    print(f"Payload file: {PAYLOAD_FILE.name}")
    print(f"Cases loaded: {len(cases)}")
    print()

    print("Cases by category:")
    for category, count in sorted(categories.items()):
        print(f"  {category:<25} {count}")

    print()

    if errors:
        print(f"VALIDATION FAILED: {len(errors)} issue(s)")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("VALIDATION PASSED")
    print("All cases have the required fields and unique IDs.")
    print()
    print("NOTE: This validates test data only.")
    print("It does not execute attacks or verify model guardrails.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
