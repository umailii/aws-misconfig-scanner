"""IAM checks: console users that are not protected by multi-factor authentication."""

from botocore.exceptions import ClientError

from scanner.models import Finding, Severity

REMEDIATION = (
    "Enable an MFA device for the user, or remove console access "
    "if the user only needs programmatic access."
)


def _has_console_access(iam, user_name: str) -> bool:
    try:
        iam.get_login_profile(UserName=user_name)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchEntity":
            return False
        raise


def _has_mfa(iam, user_name: str) -> bool:
    return bool(iam.list_mfa_devices(UserName=user_name).get("MFADevices"))


def check_iam_mfa(session) -> list[Finding]:
    """Flag IAM users who can sign in to the console but have no MFA device."""
    iam = session.client("iam")
    findings: list[Finding] = []

    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not _has_console_access(iam, name):
                continue
            if _has_mfa(iam, name):
                continue
            findings.append(
                Finding(
                    check_id="IAM-001",
                    severity=Severity.HIGH,
                    resource=user["Arn"],
                    region="global",
                    title="IAM user has console access but no MFA device",
                    remediation=REMEDIATION,
                )
            )

    return findings
