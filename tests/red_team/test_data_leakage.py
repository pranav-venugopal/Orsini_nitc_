import json
import unittest
from pathlib import Path

PAYLOAD_FILE = Path(__file__).resolve().parent / "payloads.json"


def load_payloads():
    with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


class DataLeakagePayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = load_payloads()

    def test_data_leakage_cases_exist(self):
        cases = [
            case for case in self.payloads
            if case["category"] == "data_leakage"
        ]
        self.assertGreaterEqual(len(cases), 2)

    def test_leakage_cases_have_expected_policy(self):
        expected = {
            "LEAK-001": "no_secret_disclosure",
            "PII-001": "apply_output_policy",
        }
        for case_id, policy in expected.items():
            with self.subTest(case_id=case_id):
                case = next(
                    (item for item in self.payloads
                     if item["id"] == case_id),
                    None,
                )
                self.assertIsNotNone(case)
                self.assertEqual(case["expected_policy"], policy)

    def test_leakage_test_inputs_are_non_empty(self):
        cases = [
            case for case in self.payloads
            if case["id"] in {"LEAK-001", "PII-001"}
        ]
        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertTrue(case["prompt"].strip())

    def test_no_real_credentials_are_configured(self):
        for case in self.payloads:
            with self.subTest(case_id=case["id"]):
                self.assertNotIn("sk-live-", case["prompt"])
                self.assertNotIn("ghp_", case["prompt"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
