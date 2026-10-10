"""Security group checks: rules that allow traffic from anywhere on the internet."""

from scanner.models import Finding, Severity

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}

# Ports that should almost never be reachable from the whole internet.
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Ports that are commonly and legitimately public.
WEB_PORTS = {80, 443}

REMEDIATION = (
    "Restrict the rule's source to known IP ranges or a security group, "
    "or remove it. Use a bastion host or SSM Session Manager for admin access."
)


def _open_to_world(permission: dict) -> bool:
    v4 = any(r.get("CidrIp") in WORLD_CIDRS for r in permission.get("IpRanges", []))
    v6 = any(r.get("CidrIpv6") in WORLD_CIDRS for r in permission.get("Ipv6Ranges", []))
    return v4 or v6


def _classify(permission: dict) -> tuple[Severity, str] | None:
    """Return (severity, description) for a world-open rule, or None if not risky."""
    if not _open_to_world(permission):
        return None

    protocol = permission.get("IpProtocol")
    if protocol == "-1":
        return Severity.CRITICAL, "all traffic open to the internet"

    low = permission.get("FromPort")
    high = permission.get("ToPort")
    if low is None or high is None:
        return Severity.HIGH, f"protocol {protocol} open to the internet"

    exposed = [name for port, name in SENSITIVE_PORTS.items() if low <= port <= high]
    if exposed:
        return Severity.CRITICAL, f"{', '.join(exposed)} (ports {low}-{high}) open to the internet"

    if low == high and low in WEB_PORTS:
        return Severity.LOW, f"web port {low} open to the internet"

    return Severity.HIGH, f"ports {low}-{high} open to the internet"


def check_security_groups(session, region: str) -> list[Finding]:
    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []

    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page["SecurityGroups"]:
            for permission in group.get("IpPermissions", []):
                result = _classify(permission)
                if result is None:
                    continue
                severity, description = result
                findings.append(
                    Finding(
                        check_id="EC2-001",
                        severity=severity,
                        resource=f"{group['GroupId']} ({group.get('GroupName', 'unnamed')})",
                        region=region,
                        title=f"Inbound rule allows {description}",
                        remediation=REMEDIATION,
                    )
                )

    return findings
