import json
import unittest
from pathlib import Path

PAYLOAD_FILE = Path(__file__).resolve().parent / "payloads.json"


def load_payloads():
    with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


class JailbreakPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = load_payloads()

    def test_jailbreak_payload_exists(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "jailbreak"
        ]
        self.assertGreaterEqual(len(cases), 1)

    def test_jailbreak_policy_is_defined(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "jailbreak"
        ]
        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertEqual(
                    case["expected_policy"],
                    "resist_jailbreak",
                )

    def test_jailbreak_prompts_are_non_empty(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "jailbreak"
        ]
        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertTrue(case["prompt"].strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
