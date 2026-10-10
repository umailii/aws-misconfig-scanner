# AWS Misconfiguration Scanner

[![CI](https://github.com/umailii/aws-misconfig-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/umailii/aws-misconfig-scanner/actions/workflows/ci.yml)

A small, read-only Python tool that scans an AWS account for common security misconfigurations and produces a severity-ranked report. It is built with boto3 and is meant to be easy to read, extend, and run in CI. Requires Python 3.10 or newer.

## Why this exists

I built this project to learn AWS and get hands-on experience with it, focusing on the security side of S3, networking, and IAM. It turns well-documented misconfigurations into automated, testable checks using the AWS SDK. The three areas covered (S3 public exposure, world-open security groups, console users without MFA) each map to controls in the CIS AWS Foundations Benchmark and can be detected with read-only API calls. The reasoning behind the main choices is in [docs/DESIGN.md](docs/DESIGN.md).

## Project history

The initial version was developed locally starting in July 2026 and completed on September 4, 2026. It was first committed and published to GitHub on October 10, 2026.

On October 10, 2026, the project received the account-level S3 Block Public Access fix and regression tests, a mocked demonstration, design and investigation documentation, and GitHub Actions CI configuration. September 4 refers to completion of the initial version, not these later additions.

## What it checks

| ID | Check | Severity |
|----|-------|----------|
| S3-001 | Bucket is public through its policy or ACL | Critical |
| S3-002 | Effective S3 Block Public Access is not fully enabled (names the missing settings) | Medium |
| S3-003 | Public ACL or policy exists but is currently blocked by Block Public Access | Medium |
| S3-004 | Account-level Block Public Access could not be read, so the S3 results are incomplete | Low |
| EC2-001 | Security group allows traffic from `0.0.0.0/0` or `::/0` | Critical for all traffic or sensitive ports (SSH, RDP, databases), High for other ports, Low for 80 and 443 |
| IAM-001 | IAM user has console access but no MFA device | High |

The scanner only makes read calls. It never changes anything in your account.

S3 results use the **effective** Block Public Access settings: a setting counts as enabled if it is on at the bucket level or the account level, because S3 applies whichever is stricter.

## Install

```bash
git clone https://github.com/umailii/aws-misconfig-scanner.git
cd aws-misconfig-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Scan with your default AWS credentials, print to the terminal
python -m scanner

# Use a named profile and scan two regions
python -m scanner --profile my-profile --region us-east-1 --region us-west-2

# Write an HTML or JSON report
python -m scanner --format html --output report.html
python -m scanner --format json --output report.json

# Fail a CI job if anything High or above is found
python -m scanner --fail-on high
```

Exit codes: `0` clean (or below the `--fail-on` threshold), `1` findings at or above the threshold, `2` the scan could not run.

## Permissions

Attach the policy in [`iam-policy.json`](iam-policy.json) to the user or role that runs the scanner. It grants read-only access to exactly what the checks need.

## Sample output

From a mocked test account:

```
AWS Misconfiguration Scan
=========================
CRITICAL: 2  HIGH: 1  MEDIUM: 1  LOW: 0

[CRITICAL] EC2-001  Inbound rule allows SSH (port 22) open to the internet
    Resource:    sg-9bf1a95eeeea7c3a5 (web-ssh)
    Region:      us-east-1
    Remediation: Restrict the rule's source to known IP ranges or a security group, or remove it. Use a bastion host or SSM Session Manager for admin access.

[CRITICAL] S3-001  Bucket is publicly accessible via ACL
    Resource:    arn:aws:s3:::demo-public-assets
    Region:      us-east-1
    Remediation: Remove public ACL grants and bucket policy statements that allow Principal '*', then enable S3 Block Public Access on the bucket.

[HIGH] IAM-001  IAM user has console access but no MFA device
    Resource:    arn:aws:iam::123456789012:user/alice
    Region:      global
    Remediation: Enable an MFA device for the user, or remove console access if the user only needs programmatic access.

[MEDIUM] S3-002  Block Public Access is not fully enabled (missing: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)
    Resource:    arn:aws:s3:::demo-app-logs
    Region:      us-east-1
    Remediation: Enable all four S3 Block Public Access settings, preferably at the account level so new buckets are covered too.
```

## Demonstration

[docs/DEMO.md](docs/DEMO.md) walks through a controlled before and after: a deliberately misconfigured mock account, the scan findings, the configuration changes that fix them, and the clean re-scan. The results are mocked (moto, no real account) and account details are redacted. Reproduce it with `python demo/run_demo.py`.

## Project layout

```
scanner/
  checks/
    s3.py               public bucket and Block Public Access checks
    security_groups.py  world-open inbound rules
    iam.py              console users without MFA
  models.py             Finding and Severity
  report.py             console, JSON and HTML rendering
  cli.py                argument parsing and exit codes
tests/                  pytest suite using moto (no real AWS calls)
demo/run_demo.py        reproducible mocked before/after scan
docs/                   design decisions, demo output, bug investigation
```

## Development

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Tests run against moto, which mocks AWS locally, so they never touch a real account and need no credentials.

## Adding a check

1. Create a function in `scanner/checks/` that takes a boto3 session and returns a list of `Finding` objects.
2. Register it in `run_scan` in `scanner/cli.py`.
3. Add tests in `tests/` using the `session` fixture.

## Continuous integration

The GitHub Actions workflow was added on October 10, 2026. This is the configuration date; actual run dates and results are recorded in GitHub Actions logs. The workflow is configured to run on pushes and pull requests to `main` via [.github/workflows/ci.yml](.github/workflows/ci.yml):

- **Tests** on Python 3.10, 3.11, 3.12 and 3.13, plus the mocked demo end to end.
- **Secret scanning** with gitleaks across the full git history.
- **Static analysis** with Bandit, failing the build on medium severity or higher.
- **Dependency audit** with pip-audit against known vulnerabilities.

The workflow has read-only repository permissions, and Dependabot proposes weekly updates for the Python dependencies and the GitHub Actions themselves. Bandit also reports two low-severity "hardcoded password" notes in the demo; those are fake values for a mocked account, and the build gate is set to medium and above.

## Design decisions and a bug investigation

- [docs/DESIGN.md](docs/DESIGN.md): why S3, security groups and IAM; why public web ports are rated Low; how severity is assigned; why tests use moto and where moto falls short.
- [docs/investigations/account-level-block-public-access.md](docs/investigations/account-level-block-public-access.md): the first version ignored account-level Block Public Access, producing false positives and wrong severities. Covers reproduction, root cause, fix and regression tests.

## Known limitations

**What a clean report does and does not mean.** No finding means none of the implemented checks fired. It is not an assessment that the account is secure.

**Permission failures.** If the scanner cannot inspect a bucket it reports `S3-000`; if it cannot read account-level Block Public Access it reports `S3-004` and falls back to bucket-level settings. Errors from the EC2 or IAM calls stop the scan with exit code 2 rather than printing a partial report. A report containing `S3-000` or `S3-004` is incomplete, not clean. These findings are LOW severity: `--fail-on high` can return exit code 0 despite incomplete coverage when no HIGH or CRITICAL findings exist. Review these findings separately; the CLI currently has no independent failure gate for incomplete scans.

**What it cannot establish.**
- Security groups: it reads rules only. It does not know whether a group is attached to anything, whether the resource has a public IP or route, or whether network ACLs apply. Rules that reference other groups or prefix lists are not evaluated.
- S3: object-level ACLs, access points, and Organizations-level controls are not examined. Whether a bucket policy is public is AWS's own verdict (`GetBucketPolicyStatus`); the scanner does not parse policy conditions.
- IAM: only users with console access are checked. Roles, federated or SSO users, the root account, and access keys are not.
- Regional scope: security groups are scanned only in the regions you pass with `--region`. S3 and IAM are account-wide.
- Severity levels are judgment calls, documented in [docs/DESIGN.md](docs/DESIGN.md), not a formal scoring system.

**Still needs testing.**
- The tests and demo run on moto, which approximates AWS. For example, moto does not evaluate whether a bucket policy is public, so those tests stub that one call.
- The scanner has not yet been run against a real AWS sandbox account. Until it has, behavior that depends on AWS's own evaluation (policy status, real permission errors, accounts with many buckets or groups) is unverified.

## Roadmap

- Unencrypted EBS volumes and RDS instances
- Access keys older than 90 days
- Root account MFA and usage
- CloudTrail enabled in all regions
- Mapping findings to CIS AWS Foundations Benchmark controls
