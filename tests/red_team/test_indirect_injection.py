import json
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
PAYLOAD_FILE = TEST_DIR / "payloads.json"
FIXTURE_FILE = TEST_DIR / "fixtures" / "hostile_document.txt"


class IndirectInjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with PAYLOAD_FILE.open("r", encoding="utf-8-sig") as file:
            cls.cases = json.load(file)
        cls.case_by_id = {case["id"]: case for case in cls.cases}

    def test_indirect_injection_case_exists(self):
        self.assertIn("INDIRECT-001", self.case_by_id)

    def test_fixture_exists_and_is_non_empty(self):
        self.assertTrue(FIXTURE_FILE.is_file())
        self.assertTrue(FIXTURE_FILE.read_text(encoding="utf-8-sig").strip())

    def test_fixture_is_labelled_untrusted(self):
        content = FIXTURE_FILE.read_text(encoding="utf-8-sig").lower()
        self.assertIn("untrusted", content)
        self.assertIn("test fixture", content)

    def test_fixture_contains_synthetic_marker(self):
        content = FIXTURE_FILE.read_text(encoding="utf-8-sig")
        self.assertIn("DEMO_SECRET_12345", content)
        self.assertIn("not a real credential", content)

    def test_indirect_injection_has_expected_policy(self):
        case = self.case_by_id["INDIRECT-001"]
        self.assertEqual(
            case["expected_policy"],
            "treat_document_as_untrusted",
        )


if __name__ == "__main__":
    unittest.main()
