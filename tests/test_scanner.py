import tempfile
import unittest
from pathlib import Path

from sdlc_guardrail.scanner import scan


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_detects_container_dependency_and_iac_risks(self) -> None:
        (self.root / "Dockerfile").write_text("FROM python:latest\nCMD python app.py\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("requests\n", encoding="utf-8")
        (self.root / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n', encoding="utf-8")
        rule_ids = {item.rule_id for item in scan(self.root)}
        self.assertTrue({"CTR001", "CTR002", "DEP001", "IAC001"}.issubset(rule_ids))

    def test_detects_synthetic_secret_and_supports_suppression(self) -> None:
        (self.root / "bad.txt").write_text("token=AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
        (self.root / "accepted.txt").write_text("# guardrail: ignore SEC003 reason=synthetic test value\ntoken=AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
        findings = scan(self.root)
        self.assertEqual([(item.rule_id, item.path) for item in findings], [("SEC003", "bad.txt")])

    def test_workflow_rules(self) -> None:
        workflow = self.root / ".github" / "workflows" / "build.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("on: pull_request_target\npermissions: write-all\nsteps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
        rule_ids = {item.rule_id for item in scan(self.root)}
        self.assertEqual(rule_ids, {"CICD001", "CICD002", "CICD003"})


if __name__ == "__main__":
    unittest.main()
