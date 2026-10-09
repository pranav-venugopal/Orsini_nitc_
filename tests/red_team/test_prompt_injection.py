import json
import unittest
from pathlib import Path

PAYLOAD_FILE = Path(__file__).resolve().parent / "payloads.json"


def load_payloads():
    with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


class PromptInjectionPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = load_payloads()

    def test_direct_injection_case_exists(self):
        cases = [
            case for case in self.payloads
            if case["id"] == "INJECT-001"
        ]
        self.assertEqual(len(cases), 1)
        self.assertEqual(
            cases[0]["expected_policy"],
            "resist_injection",
        )

    def test_jailbreak_case_exists(self):
        cases = [
            case for case in self.payloads
            if case["id"] == "JAILBREAK-001"
        ]
        self.assertEqual(len(cases), 1)
        self.assertEqual(
            cases[0]["expected_policy"],
            "resist_jailbreak",
        )

    def test_attack_prompts_are_non_empty(self):
        attack_categories = {"prompt_injection", "jailbreak"}
        cases = [
            case for case in self.payloads
            if case["category"] in attack_categories
        ]

        self.assertGreaterEqual(len(cases), 2)

        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertTrue(case["prompt"].strip())

    def test_attack_case_ids_are_unique(self):
        cases = [
            case for case in self.payloads
            if case["category"] in {"prompt_injection", "jailbreak"}
        ]
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
