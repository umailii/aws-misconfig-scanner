"""S3 checks: buckets that are, or could become, publicly accessible.

Block Public Access (BPA) can be set on a bucket and on the whole account.
AWS applies the stricter of the two for each of the four settings, so this
module computes the *effective* setting (bucket OR account) before judging a
bucket. Reading only the bucket-level configuration gives wrong answers in
both directions; see docs/investigations/account-level-block-public-access.md.
"""

from botocore.exceptions import BotoCoreError, ClientError

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
    "Principal '*', then enable S3 Block Public Access on the bucket "
    "and, ideally, for the whole account."
)
REMEDIATION_LATENT = (
    "Remove the public ACL grant or bucket policy statement. Block Public "
    "Access is hiding it today, but turning that protection off would expose the bucket."
)
REMEDIATION_PAB = (
    "Enable all four S3 Block Public Access settings, preferably at the "
    "account level so new buckets are covered too."
)
REMEDIATION_ACCOUNT_UNREADABLE = (
    "Grant the scanner s3:GetAccountPublicAccessBlock and re-run so "
    "account-level protection can be taken into account."
)


def _none_set() -> dict[str, bool]:
    return {key: False for key in PAB_KEYS}


def _normalize(config: dict) -> dict[str, bool]:
    return {key: bool(config.get(key, False)) for key in PAB_KEYS}


def get_account_public_access_block(session) -> tuple[dict[str, bool], str | None]:
    """Return (account-level settings, note).

    The note is None when the settings were read successfully (including the
    case where no account-level configuration exists). It is a message when
    the settings could not be read; callers then must not assume protection.
    """
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        config = session.client("s3control").get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
        return _normalize(config), None
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            return _none_set(), None
        return _none_set(), f"account-level Block Public Access unreadable ({code})"
    except BotoCoreError as exc:
        return _none_set(), f"account-level Block Public Access unreadable ({type(exc).__name__})"


def _bucket_public_access_block(s3, bucket: str) -> dict[str, bool]:
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return _none_set()
        raise
    return _normalize(config)


def effective_block(account: dict[str, bool], bucket: dict[str, bool]) -> dict[str, bool]:
    """A setting is in force if it is enabled at either level."""
    return {key: account[key] or bucket[key] for key in PAB_KEYS}


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
    """Judge each bucket using its effective Block Public Access settings."""
    s3 = session.client("s3")
    findings: list[Finding] = []

    account_block, account_note = get_account_public_access_block(session)
    if account_note:
        findings.append(
            Finding(
                check_id="S3-004",
                severity=Severity.LOW,
                resource="account",
                region="global",
                title=f"Scan is incomplete: {account_note}; bucket results use bucket-level settings only",
                remediation=REMEDIATION_ACCOUNT_UNREADABLE,
            )
        )

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"
        try:
            region = s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            policy_public = _policy_is_public(s3, name)
            acl_public = _acl_is_public(s3, name)
            bucket_block = _bucket_public_access_block(s3, name)
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

        effective = effective_block(account_block, bucket_block)

        # A public ACL is neutralized by IgnorePublicAcls; a public policy by RestrictPublicBuckets.
        acl_exposed = acl_public and not effective["IgnorePublicAcls"]
        policy_exposed = policy_public and not effective["RestrictPublicBuckets"]

        if acl_exposed or policy_exposed:
            reasons = []
            if policy_exposed:
                reasons.append("bucket policy")
            if acl_exposed:
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
        elif acl_public or policy_public:
            findings.append(
                Finding(
                    check_id="S3-003",
                    severity=Severity.MEDIUM,
                    resource=arn,
                    region=region,
                    title="Public grant exists but is currently blocked by Block Public Access",
                    remediation=REMEDIATION_LATENT,
                )
            )
        elif not all(effective.values()):
            missing = ", ".join(key for key in PAB_KEYS if not effective[key])
            findings.append(
                Finding(
                    check_id="S3-002",
                    severity=Severity.MEDIUM,
                    resource=arn,
                    region=region,
                    title=f"Block Public Access is not fully enabled (missing: {missing})",
                    remediation=REMEDIATION_PAB,
                )
            )

    return findings
