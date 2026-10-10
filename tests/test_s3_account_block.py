"""Regression tests for how account-level and bucket-level Block Public Access interact."""

import json

import pytest

from scanner.checks import s3 as s3_module
from scanner.checks.s3 import check_s3_buckets, effective_block
from scanner.models import Severity

ALL_ON = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _set_account_block(session, **overrides):
    config = {key: False for key in ALL_ON}
    config.update(overrides)
    account_id = session.client("sts").get_caller_identity()["Account"]
    session.client("s3control").put_public_access_block(
        AccountId=account_id, PublicAccessBlockConfiguration=config
    )


def _public_policy(bucket):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }
    )


def _ids(findings):
    return sorted(f.check_id for f in findings)


def test_effective_block_is_union_of_levels():
    account = {k: False for k in ALL_ON} | {"BlockPublicAcls": True}
    bucket = {k: False for k in ALL_ON} | {"IgnorePublicAcls": True}
    result = effective_block(account, bucket)
    assert result["BlockPublicAcls"] and result["IgnorePublicAcls"]
    assert not result["BlockPublicPolicy"] and not result["RestrictPublicBuckets"]


def test_regression_account_level_block_clears_false_positive(session):
    """Before the fix, a bucket with no bucket-level config was flagged even when
    the account enforced all four settings."""
    session.client("s3").create_bucket(Bucket="covered-by-account")
    _set_account_block(session, **ALL_ON)
    assert check_s3_buckets(session) == []


def test_settings_split_across_levels_count_as_complete(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="split-bucket")
    s3.put_public_access_block(
        Bucket="split-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    _set_account_block(session, BlockPublicAcls=True, IgnorePublicAcls=True)
    assert check_s3_buckets(session) == []


def test_missing_settings_are_named_in_the_finding(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="partial-bucket")
    s3.put_public_access_block(
        Bucket="partial-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    findings = check_s3_buckets(session)
    assert _ids(findings) == ["S3-002"]
    assert "BlockPublicPolicy" in findings[0].title
    assert "RestrictPublicBuckets" in findings[0].title
    assert "BlockPublicAcls" not in findings[0].title


def test_public_acl_blocked_by_account_ignore_setting_is_latent_not_critical(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="latent-acl")
    s3.put_bucket_acl(Bucket="latent-acl", ACL="public-read")
    _set_account_block(session, IgnorePublicAcls=True)
    findings = check_s3_buckets(session)
    assert _ids(findings) == ["S3-003"]
    assert findings[0].severity == Severity.MEDIUM


def test_public_acl_without_ignore_setting_stays_critical(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="exposed-acl")
    s3.put_bucket_acl(Bucket="exposed-acl", ACL="public-read")
    # Blocking new public policies does not neutralize an existing public ACL.
    _set_account_block(session, BlockPublicPolicy=True, RestrictPublicBuckets=True)
    findings = check_s3_buckets(session)
    assert _ids(findings) == ["S3-001"]
    assert findings[0].severity == Severity.CRITICAL


def test_public_policy_is_critical_until_restrict_public_buckets_is_on(session, monkeypatch):
    # moto returns an empty PolicyStatus (it does not evaluate IsPublic), so the
    # AWS-side verdict is stubbed here. What is under test is how the scanner
    # combines that verdict with the effective Block Public Access settings.
    monkeypatch.setattr(s3_module, "_policy_is_public", lambda _s3, _bucket: True)
    s3 = session.client("s3")
    s3.create_bucket(Bucket="policy-bucket")
    s3.put_bucket_policy(Bucket="policy-bucket", Policy=_public_policy("policy-bucket"))

    assert _ids(check_s3_buckets(session)) == ["S3-001"]

    _set_account_block(session, RestrictPublicBuckets=True)
    assert _ids(check_s3_buckets(session)) == ["S3-003"]


def test_unreadable_account_settings_are_reported_not_assumed_safe(session, monkeypatch):
    session.client("s3").create_bucket(Bucket="unknown-account-state")
    monkeypatch.setattr(
        s3_module,
        "get_account_public_access_block",
        lambda _session: (
            {key: False for key in ALL_ON},
            "account-level Block Public Access unreadable (AccessDenied)",
        ),
    )
    findings = check_s3_buckets(session)
    assert _ids(findings) == ["S3-002", "S3-004"]
    incomplete = next(f for f in findings if f.check_id == "S3-004")
    assert incomplete.severity == Severity.LOW
    assert "AccessDenied" in incomplete.title


@pytest.mark.parametrize("bucket", ["a-bucket", "another-bucket"])
def test_no_account_config_behaves_like_bucket_only_scan(session, bucket):
    session.client("s3").create_bucket(Bucket=bucket)
    assert _ids(check_s3_buckets(session)) == ["S3-002"]
