import argparse

from .models import SEVERITY_RANK
from .reporters import json_report, sarif_report, text_report, write_report
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply explainable secure-SDLC guardrails to a repository")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("scan", help="scan a repository")
    command.add_argument("target", nargs="?", default=".")
    command.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    command.add_argument("--output")
    command.add_argument("--fail-on", choices=("critical", "high", "medium", "low", "never"), default="high")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings = scan(args.target)
    except ValueError as error:
        print(f"error: {error}")
        return 2
    report = {"text": text_report, "json": json_report, "sarif": sarif_report}[args.format](findings)
    write_report(report, args.output)
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    return int(any(SEVERITY_RANK[item.severity] >= threshold for item in findings))


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
