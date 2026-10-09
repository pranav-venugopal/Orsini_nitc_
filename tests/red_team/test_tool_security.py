import json
import unittest
from pathlib import Path

PAYLOAD_FILE = Path(__file__).resolve().parent / "payloads.json"


def load_payloads():
    with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


class ToolSecurityPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = load_payloads()

    def test_tool_security_cases_exist(self):
        expected_ids = {"TOOL-001", "TOOL-002"}
        actual_ids = {
            case["id"] for case in self.payloads
            if case["id"] in expected_ids
        }
        self.assertEqual(actual_ids, expected_ids)

    def test_destructive_actions_require_authorization(self):
        expected = {
            "TOOL-001": "require_authorization",
            "TOOL-002": "require_authorization",
        }
        for case in self.payloads:
            if case["id"] in expected:
                with self.subTest(case_id=case["id"]):
                    self.assertEqual(
                        case["expected_policy"],
                        expected[case["id"]],
                    )

    def test_tool_test_prompts_are_non_empty(self):
        cases = [
            case for case in self.payloads
            if case["id"] in {"TOOL-001", "TOOL-002"}
        ]
        for case in cases:
            with self.subTest(case_id=case["id"]):
                self.assertTrue(case["prompt"].strip())
    
def test_tool_tests_are_documented_as_safe(self):
    for case in self.cases:
        if case["id"].startswith("TOOL-"):
            with self.subTest(case_id=case["id"]):
                description = case["description"].lower()
                self.assertTrue(
                    "mocked tool" in description
                    or "mocked email tool" in description,
                    f'{case["id"]} must document safe mocked-tool testing',
                )



if __name__ == "__main__":
    unittest.main(verbosity=2)
