# AWS Misconfiguration Scanner

A small, read-only Python tool that scans an AWS account for common security misconfigurations and produces a severity-ranked report. It is built with boto3 and is meant to be easy to read, extend, and run in CI.

## What it checks

| ID | Check | Severity |
|----|-------|----------|
| S3-001 | Bucket is public through its policy or ACL | Critical |
| S3-002 | S3 Block Public Access is not fully enabled | Medium |
| EC2-001 | Security group allows traffic from `0.0.0.0/0` or `::/0` | Critical for all traffic or sensitive ports (SSH, RDP, databases), High for other ports, Low for 80 and 443 |
| IAM-001 | IAM user has console access but no MFA device | High |

The scanner only makes read calls. It never changes anything in your account.

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

[MEDIUM] S3-002  Block Public Access is not fully enabled
    Resource:    arn:aws:s3:::demo-app-logs
    Region:      us-east-1
    Remediation: Enable all four S3 Block Public Access settings on the bucket (or at the account level).
```

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

## Roadmap

- Unencrypted EBS volumes and RDS instances
- Access keys older than 90 days
- Root account MFA and usage
- CloudTrail enabled in all regions
- Mapping findings to CIS AWS Foundations Benchmark controls
