# Demonstration: before and after (mocked)

**These results are mocked.** They were generated with [moto](https://github.com/getmoto/moto), which simulates AWS locally. No real AWS account was scanned, and no credentials were used. The 12-digit account ID and security group IDs are redacted by the script.

## Reproduce it

```bash
pip install -r requirements-dev.txt
python demo/run_demo.py
```

## Setup (a deliberately misconfigured account)

| Resource | Misconfiguration |
|----------|------------------|
| `demo-public-assets` (S3) | Bucket ACL grants public read |
| `demo-app-logs` (S3) | No Block Public Access at bucket or account level |
| `demo-ssh` (security group) | Inbound SSH open to `0.0.0.0/0` |
| `demo-admin` (IAM user) | Console access, no MFA device |

## Output

```
MOCKED RESULTS: generated with moto, not a real AWS account.

--- BEFORE: scan of the deliberately misconfigured account ---
CRITICAL: 2  HIGH: 1  MEDIUM: 1  LOW: 0
  [CRITICAL] EC2-001  Inbound rule allows SSH (port 22) open to the internet
      sg-<REDACTED> (demo-ssh)
  [CRITICAL] S3-001  Bucket is publicly accessible via ACL
      arn:aws:s3:::demo-public-assets
  [HIGH] IAM-001  IAM user has console access but no MFA device
      arn:aws:iam::<ACCOUNT_ID>:user/demo-admin
  [MEDIUM] S3-002  Block Public Access is not fully enabled (missing: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)
      arn:aws:s3:::demo-app-logs

Configuration changes applied:
  1. demo-public-assets: ACL changed from public-read to private
  2. Account-level Block Public Access: all four settings enabled
  3. demo-ssh: inbound SSH from 0.0.0.0/0 removed
  4. demo-admin: MFA device enabled

--- AFTER: scan once the changes above are applied ---
CRITICAL: 0  HIGH: 0  MEDIUM: 0  LOW: 0

```

## What to notice

- The `demo-app-logs` bucket never receives bucket-level settings. It passes the second scan only because enabling Block Public Access at the **account** level counts toward every bucket's effective settings. Reading only bucket-level configuration would still flag it; see [the investigation](investigations/account-level-block-public-access.md).
- The public ACL was removed and Block Public Access was enabled. Had the ACL been left in place, the second scan would report `S3-003` (a public grant that is currently blocked) instead of a clean result, because the exposure would return if the block were ever turned off.
- A clean scan means none of the implemented checks fired. It does not mean the account is secure. See the README's "Known limitations".
