# Design decisions

Each decision below lists the reasoning and what it costs.

## Scope: S3, security groups, IAM

**Why these three.** They are three different failure types (data exposure, network exposure, weak identity protection), and each maps to a control in the CIS AWS Foundations Benchmark with a condition that can be checked mechanically through read-only API calls.

**Tradeoff.** The scope is narrow on purpose. A focused set of checks that state their limits are more useful than many shallow ones. Encryption, logging (CloudTrail), access key age, and root account checks are real gaps and are listed in the roadmap.

## Severity

Severity is a judgment call about exposure and ease of abuse, not a formal score such as CVSS.

| Condition | Severity | Reasoning |
|-----------|----------|-----------|
| Public S3 bucket (ACL or policy, not neutralized) | Critical | Direct data exposure, no credentials needed |
| All traffic, SSH, RDP, or database ports open to the world | Critical | Admin and data services should not face the internet; these are scanned constantly |
| Other port ranges open to the world | High | Unknown service, but internet-reachable |
| **Ports 80 and 443 open to the world** | **Low** | See below |
| Console user without MFA | High | Needs a stolen or guessed password first, so below an open door |
| BPA not fully enabled, no public grant present | Medium | A guardrail is missing, nothing is exposed yet |
| Public grant currently blocked by BPA | Medium | Latent: removing the block exposes it |

**Why public web ports are Low.** Ports 80 and 443 are open to `0.0.0.0/0` on any public website. Rating them High would put a finding on every legitimate web server, and a report full of expected findings trains people to ignore it. They are still reported (as Low) because knowing what is internet-facing is useful. **Cost:** a rule opening 443 on something that should be internal is a real problem the scanner cannot distinguish from a normal web server, since it only sees rules, not what the group is attached to.

**Why IAM only flags users with console access.** MFA protects the console sign-in. A user with only access keys has no console password to protect, so flagging it would be noise. **Cost:** access keys on users without MFA are not examined.

## Effective Block Public Access

BPA exists at bucket and account level, and a setting is in force if it is on at either. The check computes that union before deciding anything. This came out of a real flaw in the first version; the full write-up is in [investigations/account-level-block-public-access.md](investigations/account-level-block-public-access.md).

## Failure handling

- A bucket that cannot be inspected becomes an `S3-000` finding (LOW) and the scan continues.
- If account-level BPA cannot be read, the scanner emits `S3-004` (LOW) and does not assume the account is protected.
- Errors from the EC2 or IAM calls stop the scan with exit code 2 instead of returning a partial report that looks complete.

**Tradeoff.** Reporting incompleteness as a low-severity finding keeps the scan useful with partial permissions, but a reader has to notice it. A report with `S3-000` or `S3-004` entries is incomplete. These findings are LOW severity, so `--fail-on high` can still return exit code 0 when no HIGH or CRITICAL findings exist; that exit code does not establish full scan coverage.

## Testing with moto

**Why moto.** Tests run locally in seconds, need no credentials, cost nothing, cannot touch a real account, and can run in CI. They are also deterministic: a test can create exactly the misconfiguration it needs.

**Cost.** moto approximates AWS and does not match it everywhere. Example found while writing the tests: `get_bucket_policy_status` returns an empty status, so moto cannot say whether a policy is public. The policy tests therefore stub that one call and test how the scanner combines the verdict with the effective settings. Behavior that depends on AWS's own evaluation still needs a run against a real sandbox account, which is listed as outstanding in the README.

## Read-only by design

The scanner makes only `Get*`, `List*`, and `Describe*` calls (see `iam-policy.json`). It can be run with a narrow, auditable role and cannot change the account it inspects. Remediation is described in each finding, never applied.
