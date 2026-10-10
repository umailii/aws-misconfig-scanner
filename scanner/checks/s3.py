"""S3 checks: buckets that are, or could become, publicly accessible."""

from botocore.exceptions import ClientError

from scanner.models import Finding, Severity

PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

PAB_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

REMEDIATION_PUBLIC = (
    "Remove public ACL grants and bucket policy statements that allow "
    "Principal '*', then enable S3 Block Public Access on the bucket."
)
REMEDIATION_PAB = (
    "Enable all four S3 Block Public Access settings on the bucket "
    "(or at the account level)."
)


def _public_access_block_complete(s3, bucket: str) -> bool:
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    return all(config.get(key, False) for key in PAB_KEYS)


def _policy_is_public(s3, bucket: str) -> bool:
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return False
        raise
    return bool(status.get("IsPublic"))


def _acl_is_public(s3, bucket: str) -> bool:
    grants = s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
    return any(g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEE_URIS for g in grants)


def check_s3_buckets(session) -> list[Finding]:
    """Flag publicly exposed buckets and buckets without full Block Public Access."""
    s3 = session.client("s3")
    findings: list[Finding] = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"
        try:
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            policy_public = _policy_is_public(s3, name)
            acl_public = _acl_is_public(s3, name)
            pab_complete = _public_access_block_complete(s3, name)
        except ClientError as exc:
            findings.append(
                Finding(
                    check_id="S3-000",
                    severity=Severity.LOW,
                    resource=arn,
                    region="unknown",
                    title=f"Could not inspect bucket ({exc.response['Error']['Code']})",
                    remediation="Grant the scanner s3:GetBucket* permissions and re-run.",
                )
            )
            continue

        if policy_public or acl_public:
            reasons = []
            if policy_public:
                reasons.append("bucket policy")
            if acl_public:
                reasons.append("ACL")
            findings.append(
                Finding(
                    check_id="S3-001",
                    severity=Severity.CRITICAL,
                    resource=arn,
                    region=region,
                    title=f"Bucket is publicly accessible via {' and '.join(reasons)}",
                    remediation=REMEDIATION_PUBLIC,
                )
            )
        elif not pab_complete:
            findings.append(
                Finding(
                    check_id="S3-002",
                    severity=Severity.MEDIUM,
                    resource=arn,
                    region=region,
                    title="Block Public Access is not fully enabled",
                    remediation=REMEDIATION_PAB,
                )
            )

    return findings
