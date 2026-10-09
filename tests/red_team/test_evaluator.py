import unittest

from evaluator import evaluate_case


class EvaluatorTests(unittest.TestCase):
    def test_matching_outcome_passes(self):
        case = {
            "id": "INJECT-001",
            "expected_policy": "resist_injection",
        }

        result = evaluate_case(case, "injection_resisted")

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["expected_outcome"], "injection_resisted")

    def test_mismatching_outcome_fails(self):
        case = {
            "id": "INJECT-001",
            "expected_policy": "resist_injection",
        }

        result = evaluate_case(case, "allowed")

        self.assertEqual(result["status"], "FAIL")

    def test_authorization_policy(self):
        case = {
            "id": "TOOL-001",
            "expected_policy": "require_authorization",
        }

        result = evaluate_case(case, "approval_required")

        self.assertEqual(result["status"], "PASS")

    def test_unknown_policy_is_rejected(self):
        case = {
            "id": "UNKNOWN-001",
            "expected_policy": "made_up_policy",
        }

        with self.assertRaises(ValueError):
            evaluate_case(case, "allowed")

    def test_result_contains_case_details(self):
        case = {
            "id": "BENIGN-001",
            "expected_policy": "allow",
        }

        result = evaluate_case(case, "allowed")

        self.assertEqual(result["case_id"], "BENIGN-001")
        self.assertEqual(result["observed_outcome"], "allowed")


if __name__ == "__main__":
    unittest.main()
