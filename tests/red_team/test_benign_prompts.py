import json
import unittest
from pathlib import Path

PAYLOAD_FILE = Path(__file__).resolve().parent / "payloads.json"


def load_payloads():
    with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


class BenignPromptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = load_payloads()

    def test_benign_cases_exist(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "benign"
        ]
        self.assertGreaterEqual(len(cases), 3)

    def test_benign_cases_expect_allow(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "benign"
        ]
        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertEqual(case["expected_policy"], "allow")

    def test_benign_prompts_are_non_empty(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "benign"
        ]
        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertTrue(case["prompt"].strip())

    def test_benign_case_ids_are_unique(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "benign"
        ]
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
