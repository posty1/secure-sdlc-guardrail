import re
from dataclasses import dataclass
from pathlib import Path

from .models import Finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    message: str
    remediation: str


SECRET_RULES = (
    (Rule("SEC001", "critical", "Possible private key committed to source.", "Remove the key, rotate it, and use a managed secret store."), re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")),
    (Rule("SEC002", "critical", "Possible GitHub token committed to source.", "Revoke the token and retrieve it from a CI/CD secret store."), re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    (Rule("SEC003", "high", "Possible AWS access key committed to source.", "Deactivate the key and use workload identity or a managed secret store."), re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)

SUPPRESSION = re.compile(r"guardrail:\s*ignore\s+([A-Z0-9]+)\s+reason=(.+)", re.IGNORECASE)


def is_suppressed(lines: list[str], index: int, rule_id: str) -> bool:
    candidates = lines[max(0, index - 1) : index + 1]
    return any((match := SUPPRESSION.search(line)) and match.group(1).upper() == rule_id for line in candidates)


def secret_findings(path: Path, relative: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    for index, line in enumerate(lines):
        for rule, pattern in SECRET_RULES:
            if pattern.search(line) and not is_suppressed(lines, index, rule.rule_id):
                findings.append(Finding(rule.rule_id, rule.severity, relative, index + 1, rule.message, rule.remediation))
    return findings


def workflow_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        clean = line.strip()
        if clean == "permissions: write-all":
            findings.append(Finding("CICD001", "high", relative, index + 1, "Workflow grants write access to all token scopes.", "Grant only the minimum named permissions required by the job."))
        if re.search(r"(?:^|[\s:\[,])pull_request_target(?:[\s:\],]|$)", clean):
            findings.append(Finding("CICD002", "high", relative, index + 1, "Workflow uses the privileged pull_request_target trigger.", "Use pull_request, or ensure untrusted pull-request code is never checked out or executed."))
        match = re.search(r"uses:\s*([^\s]+)@([^\s#]+)", clean)
        if match and not match.group(1).startswith("./") and not re.fullmatch(r"[0-9a-fA-F]{40}", match.group(2)):
            findings.append(Finding("CICD003", "medium", relative, index + 1, f"Third-party action is not pinned to a full commit SHA: {match.group(0)}", "Pin the action to a reviewed 40-character commit SHA and document the release version."))
    return findings


def requirement_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, line in enumerate(text.splitlines()):
        clean = line.strip()
        if not clean or clean.startswith(("#", "-r", "--")):
            continue
        if "==" not in clean or clean.endswith("==*"):
            findings.append(Finding("DEP001", "medium", relative, index + 1, f"Python dependency is not pinned exactly: {clean}", "Pin a reviewed version and update it through an automated dependency process."))
    return findings


def dockerfile_findings(relative: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    for index, line in enumerate(lines):
        clean = line.strip()
        if clean.upper().startswith("FROM ") and (":latest" in clean.lower() or ":" not in clean.split()[1]):
            findings.append(Finding("CTR001", "medium", relative, index + 1, "Container base image is unpinned or uses latest.", "Pin an approved immutable digest or reviewed version."))
    users = [line.split(maxsplit=1)[1].strip().lower() for line in lines if line.strip().upper().startswith("USER ") and len(line.split(maxsplit=1)) == 2]
    if not users or users[-1] in {"root", "0"}:
        findings.append(Finding("CTR002", "high", relative, max(1, len(lines)), "Container does not end with a non-root USER.", "Create a dedicated user and switch to it before the final command."))
    return findings


def terraform_findings(relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "0.0.0.0/0" in line or "::/0" in line:
            findings.append(Finding("IAC001", "high", relative, index + 1, "Infrastructure rule permits traffic from the public internet.", "Restrict the CIDR range or document an approved public-service exception."))
        if re.search(r"from_port\s*=\s*0", line):
            window = "\n".join(lines[index : index + 5])
            if re.search(r"to_port\s*=\s*(?:0|65535)", window):
                findings.append(Finding("IAC002", "high", relative, index + 1, "Security rule appears to allow an unrestricted port range.", "Allow only the protocols and ports required by the service."))
    return findings
