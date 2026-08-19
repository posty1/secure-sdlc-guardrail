import json
from collections import Counter
from pathlib import Path

from .models import Finding


def text_report(findings: list[Finding]) -> str:
    if not findings:
        return "Secure SDLC guardrail: no findings."
    lines = [f"{item.severity.upper():8} {item.rule_id} {item.path}:{item.line} {item.message}" for item in findings]
    counts = Counter(item.severity for item in findings)
    summary = ", ".join(f"{level}={counts[level]}" for level in ("critical", "high", "medium", "low") if counts[level])
    return "\n".join(lines + [f"Summary: {summary}"])


def json_report(findings: list[Finding]) -> str:
    return json.dumps({"version": "0.1.0", "findings": [item.to_dict() for item in findings]}, indent=2) + "\n"


def sarif_report(findings: list[Finding]) -> str:
    rules: dict[str, Finding] = {item.rule_id: item for item in findings}
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Python Secure SDLC Guardrail",
                "version": "0.1.0",
                "rules": [{"id": key, "shortDescription": {"text": value.message}, "help": {"text": value.remediation}} for key, value in sorted(rules.items())],
            }},
            "results": [{
                "ruleId": item.rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(item.severity, "note"),
                "message": {"text": item.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.path}, "region": {"startLine": item.line}}}],
            } for item in findings],
        }],
    }
    return json.dumps(payload, indent=2) + "\n"


def write_report(content: str, output: str | None) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        print(content, end="" if content.endswith("\n") else "\n")
