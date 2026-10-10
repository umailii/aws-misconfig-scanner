"""Reproducible before/after demonstration against a MOCKED AWS account.

Everything here runs inside moto. No real AWS account is contacted and no
credentials are needed. Account IDs and resource IDs are redacted in the output.

    pip install -r requirements-dev.txt
    python demo/run_demo.py
"""

import json
import os
import re
import sys

os.environ.update(
    AWS_ACCESS_KEY_ID="testing",
    AWS_SECRET_ACCESS_KEY="testing",
    AWS_SESSION_TOKEN="testing",
    AWS_DEFAULT_REGION="us-east-1",
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from scanner.cli import run_scan  # noqa: E402
from scanner.report import sort_findings, summarize  # noqa: E402

REGION = "us-east-1"
ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def redact(text: str) -> str:
    text = re.sub(r"\b\d{12}\b", "<ACCOUNT_ID>", text)
    return re.sub(r"sg-[0-9a-f]+", "sg-<REDACTED>", text)


def show(label: str, findings) -> None:
    print(f"--- {label} ---")
    summary = summarize(findings)
    print("  ".join(f"{name}: {count}" for name, count in summary.items()))
    for f in sort_findings(findings):
        print(redact(f"  [{f.severity.name}] {f.check_id}  {f.title}"))
        print(redact(f"      {f.resource}"))
    print()


def build_vulnerable_account(session) -> str:
    """Create a deliberately misconfigured mock account. Returns the SSH group id."""
    s3 = session.client("s3")
    s3.create_bucket(Bucket="demo-public-assets")
    s3.put_bucket_acl(Bucket="demo-public-assets", ACL="public-read")
    s3.create_bucket(Bucket="demo-app-logs")  # no Block Public Access anywhere

    ec2 = session.client("ec2")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group_id = ec2.create_security_group(GroupName="demo-ssh", Description="demo", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )

    iam = session.client("iam")
    iam.create_user(UserName="demo-admin")
    iam.create_login_profile(UserName="demo-admin", Password="Demo-Only-Password-1!")
    return group_id


def remediate(session, group_id: str) -> None:
    s3 = session.client("s3")
    print("Configuration changes applied:")

    s3.put_bucket_acl(Bucket="demo-public-assets", ACL="private")
    print("  1. demo-public-assets: ACL changed from public-read to private")

    account_id = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(
        AccountId=account_id, PublicAccessBlockConfiguration=ALL_ON
    )
    print("  2. Account-level Block Public Access: all four settings enabled")

    session.client("ec2").revoke_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )
    print("  3. demo-ssh: inbound SSH from 0.0.0.0/0 removed")

    iam = session.client("iam")
    device = iam.create_virtual_mfa_device(VirtualMFADeviceName="demo-admin-mfa")["VirtualMFADevice"]
    iam.enable_mfa_device(
        UserName="demo-admin",
        SerialNumber=device["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    print("  4. demo-admin: MFA device enabled")
    print()


def main() -> None:
    print("MOCKED RESULTS: generated with moto, not a real AWS account.\n")
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        group_id = build_vulnerable_account(session)

        show("BEFORE: scan of the deliberately misconfigured account", run_scan(session, [REGION]))
        remediate(session, group_id)
        show("AFTER: scan once the changes above are applied", run_scan(session, [REGION]))


if __name__ == "__main__":
    main()
