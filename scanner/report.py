"""Report rendering: console text, JSON, and a standalone HTML page."""

import json
from collections import Counter
from datetime import datetime, timezone
from html import escape

from scanner.models import Finding, Severity


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by resource for stable output."""
    return sorted(findings, key=lambda f: (-int(f.severity), f.check_id, f.resource))


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.name for f in findings)
    return {s.name: counts.get(s.name, 0) for s in sorted(Severity, reverse=True)}


def to_console(findings: list[Finding]) -> str:
    ordered = sort_findings(findings)
    summary = summarize(findings)
    lines = ["AWS Misconfiguration Scan", "=" * 25]
    lines.append("  ".join(f"{name}: {count}" for name, count in summary.items()))
    lines.append("")
    if not ordered:
        lines.append("No findings. Nothing to fix.")
        return "\n".join(lines)

    for f in ordered:
        lines.append(f"[{f.severity.name}] {f.check_id}  {f.title}")
        lines.append(f"    Resource:    {f.resource}")
        lines.append(f"    Region:      {f.region}")
        lines.append(f"    Remediation: {f.remediation}")
        lines.append("")
    return "\n".join(lines).rstrip()


def to_json(findings: list[Finding]) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    return json.dumps(payload, indent=2)


_SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
}


def to_html(findings: list[Finding]) -> str:
    ordered = sort_findings(findings)
    summary = summarize(findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    cards = "".join(
        f'<div class="card" style="border-top:4px solid {_SEVERITY_COLORS[name]}">'
        f'<div class="count">{count}</div><div class="label">{name.title()}</div></div>'
        for name, count in summary.items()
    )

    if ordered:
        rows = "".join(
            "<tr>"
            f'<td><span class="badge" style="background:{_SEVERITY_COLORS[f.severity.name]}">'
            f"{f.severity.name}</span></td>"
            f"<td>{escape(f.check_id)}</td>"
            f"<td>{escape(f.title)}</td>"
            f"<td><code>{escape(f.resource)}</code></td>"
            f"<td>{escape(f.region)}</td>"
            f"<td>{escape(f.remediation)}</td>"
            "</tr>"
            for f in ordered
        )
        table = (
            "<table><thead><tr><th>Severity</th><th>Check</th><th>Finding</th>"
            "<th>Resource</th><th>Region</th><th>Remediation</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
        )
    else:
        table = "<p>No findings. Nothing to fix.</p>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS Misconfiguration Scan</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #111827; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .meta {{ color: #6b7280; margin-bottom: 1.5rem; }}
  .cards {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{ background: #f9fafb; padding: 1rem 1.5rem; border-radius: 6px; min-width: 110px; }}
  .count {{ font-size: 2rem; font-weight: 700; }}
  .label {{ color: #4b5563; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
  th {{ background: #f3f4f6; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }}
  code {{ font-size: 0.85rem; word-break: break-all; }}
</style>
</head>
<body>
<h1>AWS Misconfiguration Scan</h1>
<div class="meta">Generated {generated}</div>
<div class="cards">{cards}</div>
{table}
</body>
</html>
"""


RENDERERS = {"console": to_console, "json": to_json, "html": to_html}
