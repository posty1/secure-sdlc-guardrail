from pathlib import Path

from .models import Finding, SEVERITY_RANK
from .rules import (
    dockerfile_findings,
    requirement_findings,
    secret_findings,
    terraform_findings,
    workflow_findings,
)


SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
MAX_FILE_BYTES = 1_000_000


def _text(path: Path) -> str | None:
    if path.stat().st_size > MAX_FILE_BYTES:
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def scan(root: str | Path) -> list[Finding]:
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError(f"Scan target is not a directory: {base}")
    findings: list[Finding] = []
    for path in sorted(base.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(base).parts):
            continue
        text = _text(path)
        if text is None:
            continue
        relative = path.relative_to(base).as_posix()
        findings.extend(secret_findings(path, relative, text))
        if relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            findings.extend(workflow_findings(relative, text))
        if path.name.startswith("requirements") and path.suffix == ".txt":
            findings.extend(requirement_findings(relative, text))
        if path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile."):
            findings.extend(dockerfile_findings(relative, text))
        if path.suffix == ".tf":
            findings.extend(terraform_findings(relative, text))
    return sorted(findings, key=lambda item: (-SEVERITY_RANK[item.severity], item.path, item.line, item.rule_id))
