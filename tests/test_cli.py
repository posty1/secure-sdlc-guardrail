import tempfile
import unittest
from pathlib import Path

from sdlc_guardrail.cli import run


class CliTests(unittest.TestCase):
    def test_failure_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "Dockerfile").write_text("FROM python:latest\n", encoding="utf-8")
            self.assertEqual(run(["scan", directory, "--fail-on", "high", "--output", str(Path(directory, "report.txt"))]), 1)
            self.assertEqual(run(["scan", directory, "--fail-on", "critical", "--output", str(Path(directory, "report2.txt"))]), 0)

    def test_invalid_target(self) -> None:
        self.assertEqual(run(["scan", "/path/that/does/not/exist"]), 2)


if __name__ == "__main__":
    unittest.main()
