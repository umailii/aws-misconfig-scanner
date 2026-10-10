from scanner.checks.security_groups import check_security_groups
from scanner.models import Severity


def _make_group(session, name, permissions):
    ec2 = session.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group_id = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc_id)["GroupId"]
    # New groups have no inbound rules, so only the rules added here are evaluated.
    ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def _rule(port_from, port_to, cidr="0.0.0.0/0", protocol="tcp"):
    return {
        "IpProtocol": protocol,
        "FromPort": port_from,
        "ToPort": port_to,
        "IpRanges": [{"CidrIp": cidr}],
    }


def _default_group_findings(findings, group_ids):
    return [f for f in findings if any(gid in f.resource for gid in group_ids)]


def test_ssh_open_to_world_is_critical(session):
    gid = _make_group(session, "ssh-open", [_rule(22, 22)])
    findings = _default_group_findings(check_security_groups(session, "us-east-1"), [gid])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "SSH" in findings[0].title


def test_web_port_open_to_world_is_low(session):
    gid = _make_group(session, "https-open", [_rule(443, 443)])
    findings = _default_group_findings(check_security_groups(session, "us-east-1"), [gid])
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_restricted_cidr_is_not_flagged(session):
    gid = _make_group(session, "ssh-office", [_rule(22, 22, cidr="203.0.113.0/24")])
    findings = _default_group_findings(check_security_groups(session, "us-east-1"), [gid])
    assert findings == []


def test_all_traffic_open_is_critical(session):
    gid = _make_group(
        session,
        "all-open",
        [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    findings = _default_group_findings(check_security_groups(session, "us-east-1"), [gid])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_custom_high_port_range_is_high(session):
    gid = _make_group(session, "app-ports", [_rule(8000, 8100)])
    findings = _default_group_findings(check_security_groups(session, "us-east-1"), [gid])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
