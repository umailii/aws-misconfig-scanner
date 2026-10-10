from scanner.checks.iam import check_iam_mfa
from scanner.models import Severity


def test_console_user_without_mfa_is_high(session):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3r-Secret-Pass!")

    findings = check_iam_mfa(session)
    assert len(findings) == 1
    assert findings[0].check_id == "IAM-001"
    assert findings[0].severity == Severity.HIGH
    assert "alice" in findings[0].resource


def test_programmatic_only_user_is_ignored(session):
    session.client("iam").create_user(UserName="ci-bot")
    assert check_iam_mfa(session) == []


def test_console_user_with_mfa_is_clean(session):
    iam = session.client("iam")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Sup3r-Secret-Pass!")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-device")["VirtualMFADevice"]
    iam.enable_mfa_device(
        UserName="bob",
        SerialNumber=device["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    assert check_iam_mfa(session) == []
