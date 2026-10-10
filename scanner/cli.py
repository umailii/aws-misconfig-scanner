"""Command line entry point."""

import argparse
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.checks.iam import check_iam_mfa
from scanner.checks.s3 import check_s3_buckets
from scanner.checks.security_groups import check_security_groups
from scanner.models import Finding, Severity
from scanner.report import RENDERERS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-misconfig-scanner",
        description="Scan an AWS account for common security misconfigurations (read-only).",
    )
    parser.add_argument("--profile", help="AWS profile name to use")
    parser.add_argument(
        "--region",
        action="append",
        help="Region to scan for regional checks (repeatable). Defaults to the profile region.",
    )
    parser.add_argument(
        "--format",
        choices=sorted(RENDERERS),
        default="console",
        help="Report format (default: console)",
    )
    parser.add_argument("--output", help="Write the report to this file instead of stdout")
    parser.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        help="Exit with code 1 if any finding is at or above this severity "
        "(low, medium, high, critical). Useful in CI.",
    )
    return parser


def run_scan(session, regions: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_s3_buckets(session))
    findings.extend(check_iam_mfa(session))
    for region in regions:
        findings.extend(check_security_groups(session, region))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    threshold = None
    if args.fail_on:
        try:
            threshold = Severity.parse(args.fail_on)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    try:
        session = boto3.Session(profile_name=args.profile)
        regions = args.region or [session.region_name or "us-east-1"]
        findings = run_scan(session, regions)
    except (BotoCoreError, ClientError) as exc:
        print(f"error: could not complete scan: {exc}", file=sys.stderr)
        return 2

    report = RENDERERS[args.format](findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    if threshold is not None and any(f.severity >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
