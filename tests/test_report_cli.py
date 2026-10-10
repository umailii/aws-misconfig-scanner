import json

from scanner.cli import main
from scanner.models import Finding, Severity
from scanner.report import sort_findings, summarize, to_html, to_json


def _finding(severity, resource="r", title="t"):
    return Finding("X-001", severity, resource, "us-east-1", title, "fix it")


def test_findings_sorted_most_severe_first():
    ordered = sort_findings([_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.HIGH)])
    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]


def test_summary_counts_every_severity():
    summary = summarize([_finding(Severity.HIGH), _finding(Severity.HIGH)])
    assert summary == {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0}


def test_json_report_is_valid():
    data = json.loads(to_json([_finding(Severity.MEDIUM)]))
    assert data["summary"]["MEDIUM"] == 1
    assert data["findings"][0]["severity"] == "MEDIUM"


def test_html_report_escapes_content():
    html = to_html([_finding(Severity.LOW, title="<script>alert(1)</script>")])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_cli_fail_on_returns_nonzero(session, capsys):
    session.client("s3").create_bucket(Bucket="cli-bucket")  # MEDIUM finding
    assert main(["--fail-on", "medium"]) == 1
    assert main(["--fail-on", "high"]) == 0


def test_cli_rejects_bad_severity(capsys):
    assert main(["--fail-on", "urgent"]) == 2
