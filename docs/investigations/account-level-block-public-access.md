# Investigation: account-level Block Public Access was ignored

Date: October 10, 2026

## Summary

The first version of the S3 check read only bucket-level Block Public Access (BPA) settings. S3 also supports account-level BPA and applies whichever is stricter, so the scanner gave wrong answers in two directions. It is fixed, with regression tests.

## Symptom

Two wrong results from the same root cause:

1. **False positive.** A bucket with no bucket-level configuration was reported as `S3-002` (BPA not fully enabled, MEDIUM) even when the account enforced all four settings.
2. **Wrong severity.** A bucket with a public-read ACL was reported as `S3-001` (CRITICAL, publicly accessible) even when account-level `IgnorePublicAcls` was on, which makes S3 ignore that ACL.

## How it was identified

By reviewing the first version of the check against its own remediation text. The remediation told users to enable account-level BPA, but the code never read that setting, so following the scanner's advice would not have cleared its own finding.

## Reproduction

The setup, inside moto:

1. Create a bucket with no bucket-level BPA.
2. Enable all four BPA settings at the account level.
3. Scan.

Running that against the previous version of `scanner/checks/s3.py` returned one finding, `S3-002` MEDIUM. A second bucket with `public-read` ACL under the same account settings returned `S3-001` CRITICAL. Expected for both: no critical finding, and no finding at all for the first bucket.

## Root cause

The check called `get_public_access_block` for the bucket and treated "not all four settings true" as a finding. The account-level equivalent (`s3control:GetPublicAccessBlock`) was never consulted, and the check did not relate each setting to the kind of exposure it prevents.

## Fix

- Read account-level settings (via `sts:GetCallerIdentity` and `s3control`), and compute the **effective** setting per bucket: a setting is in force if it is on at either level.
- Judge exposure using the effective settings: a public ACL is neutralized by `IgnorePublicAcls`, and a public policy by `RestrictPublicBuckets`.
- Add `S3-003` (MEDIUM) for a public grant that is currently blocked, since it becomes a real exposure if the block is removed.
- Name the missing settings in `S3-002` so the finding says what to fix.
- If account-level settings cannot be read, report `S3-004` (LOW) and fall back to bucket-level settings, instead of assuming the account is protected.

## Regression tests

`tests/test_s3_account_block.py` covers how the two levels interact:

| Test | Behavior locked in |
|------|--------------------|
| `test_regression_account_level_block_clears_false_positive` | Account-level BPA clears a bucket with no bucket config |
| `test_settings_split_across_levels_count_as_complete` | Settings split across both levels combine |
| `test_missing_settings_are_named_in_the_finding` | Only the actually missing settings are named |
| `test_public_acl_blocked_by_account_ignore_setting_is_latent_not_critical` | Neutralized ACL is `S3-003`, not CRITICAL |
| `test_public_acl_without_ignore_setting_stays_critical` | Unrelated settings do not hide a public ACL |
| `test_public_policy_is_critical_until_restrict_public_buckets_is_on` | Policy exposure follows `RestrictPublicBuckets` |
| `test_unreadable_account_settings_are_reported_not_assumed_safe` | Permission failure surfaces as `S3-004` |

I confirmed the first scenario fails against the previous implementation (see Reproduction) and passes now.

## What this does not settle

- moto returns an empty policy status and does not evaluate `IsPublic`, so the policy-exposure test stubs that single AWS verdict. The combination logic is tested; AWS's evaluation of the policy is not. This needs a run against a real sandbox account.
- Access points, Organizations-level controls, and object-level ACLs are not modeled.
