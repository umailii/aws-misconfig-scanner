from scanner.checks.s3 import check_s3_buckets
from scanner.models import Severity


def test_bucket_without_block_public_access_is_medium(session):
    session.client("s3").create_bucket(Bucket="no-pab-bucket")
    findings = check_s3_buckets(session)
    assert len(findings) == 1
    assert findings[0].check_id == "S3-002"
    assert findings[0].severity == Severity.MEDIUM


def test_bucket_with_full_block_public_access_is_clean(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="locked-bucket")
    s3.put_public_access_block(
        Bucket="locked-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert check_s3_buckets(session) == []


def test_public_acl_is_critical(session):
    s3 = session.client("s3")
    s3.create_bucket(Bucket="public-acl-bucket")
    s3.put_bucket_acl(Bucket="public-acl-bucket", ACL="public-read")
    findings = check_s3_buckets(session)
    assert len(findings) == 1
    assert findings[0].check_id == "S3-001"
    assert findings[0].severity == Severity.CRITICAL
