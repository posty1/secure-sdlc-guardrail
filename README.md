# Python Secure SDLC Guardrail

A dependency-free Python CLI that applies practical security policy checks to source repositories and CI/CD pipelines. It is designed as a reusable pull-request guardrail: findings are explainable, reports are machine-readable, and the command exits non-zero when risk exceeds a configurable threshold.

## Why this project

Security guidance is most useful when engineers receive it during development. This project demonstrates how an application-security team can convert secure-design expectations into automated, version-controlled checks without hiding the decision logic.

## Quick start

```bash
python -m sdlc_guardrail.cli scan examples/insecure_service \
  --format json --output guardrail-report.json --fail-on high
```

Human-readable output is the default:

```bash
python -m sdlc_guardrail.cli scan . --fail-on high
```

Python 3.11+ is recommended. No third-party runtime packages are required.

## Guardrails included

- Secret-pattern detection for private keys, GitHub tokens, and AWS access keys
- GitHub Actions checks for `write-all`, dangerous `pull_request_target` use, and unpinned third-party actions
- Python dependency checks for unpinned or wildcard requirements
- Dockerfile checks for `latest` base images and missing non-root `USER`
- Terraform checks for public ingress (`0.0.0.0/0`) and unrestricted port ranges
- SARIF 2.1.0 output for code-scanning integrations
- Inline suppression with an accountable reason: `guardrail: ignore RULE-ID reason=...`
- Configurable severity threshold suitable for CI/CD enforcement

## Output formats

```bash
python -m sdlc_guardrail.cli scan . --format text
python -m sdlc_guardrail.cli scan . --format json --output report.json
python -m sdlc_guardrail.cli scan . --format sarif --output results.sarif
```

Exit codes:

- `0`: no finding meets the failure threshold
- `1`: one or more findings meet the threshold
- `2`: invalid arguments or configuration

## GitHub Actions example

```yaml
- name: Run secure SDLC guardrails
  run: python -m sdlc_guardrail.cli scan . --format sarif --output results.sarif --fail-on high
```

The included workflow runs the guardrail and unit tests on pushes and pull requests.

## Test

```bash
python -m unittest discover -s tests -v
```

## Design principles

- Read-only scanning: the tool never changes the target repository
- Transparent rules with remediation guidance
- Deterministic output for CI/CD use
- Explicit suppressions rather than silent exceptions
- Synthetic examples only; no real credentials or proprietary code

## Scope

This is a portfolio-quality internal-tool prototype. It complements—not replaces—SAST, SCA, secret-scanning, threat modeling, and expert secure-design review.

## License

MIT
