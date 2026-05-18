# Changelog

## [Unreleased]

### Added

- `bks scan --org`: organization-wide scan via `sts:AssumeRole` into every ACTIVE member account in the organization, parallelized and aggregated. Per-account failures (role missing, AccessDenied, throttled) captured as `status=error` in the output without aborting the run. Flags: `--org-role NAME` (default `OrganizationAccountAccessRole`), `--org-accounts IDS`, `--org-skip IDS`. CSV output flattens to one row per phantom user with `account_id` / `account_name` columns prepended.

## [1.1.0] - 2026-05-06

### Breaking

- `--json` and `--csv` on every command write to `output/bks-<command>-<account>-<UTC>.<ext>` instead of streaming to stdout. SOAR pipelines should read the saved-file path from the final stdout line.
- `bks scan --csv` is now flag-only (no `<FILE>` argument).
- `scanner.revoke_key`, `scanner.revoke_short_term_key`, `scanner.cleanup_orphaned_users`, and `scanner.generate_timeline` return `Dict` instead of `bool` / `None`.
- IaC modules moved from `iac/` to `scps/`. Terraform consumers using `source = "...//iac/terraform"` must update to `//scps/terraform`.

### Added

- `--quiet` / `-q` flag for SOAR pipelines, accepted at group and per-command level.
- `--output-dir DIR` global flag (default `./output`) to redirect JSON / CSV reports.
- `--region` global flag plus per-command override.
- `--json` on cleanup, revoke-key, timeline, and report.
- Scan output polish: status-priority sort (AT RISK > ACTIVE > ORPHANED), AT RISK / ORPHANED advisory blocks with remediation commands, severity icons (`▸ ✓ ⚠ ✗`), completion footer.
- Terraform module + CloudFormation template under `scps/`.
- EventBridge `bedrock-api-key-usage` pattern.
- pytest suite (41 cases) on Python 3.10 / 3.11 / 3.12 / 3.13.
- `docs/permissions.md` IAM matrix.
- Black Hat Arsenal US 26 badge.

### Changed

- README reframed as "AWS Bedrock API keys security toolkit".
- Scan banner trimmed from 11 to 2 lines.
- Decoder `security_notes` carries only key-specific findings.

### Fixed

- Python 3.10 / 3.11 f-string compat: `\u` escapes inside expression parts replaced with literal Unicode characters.
- Sigma cross-region rule migrated to 2.x correlation syntax.
- Six Sigma rule IDs regenerated as proper UUIDs.
- CloudTrail Lake queries: schema (`requestParameters` map shape) and Trino dialect fixes.
- CloudWatch Insights `callWithBearerToken` filter quoted as `"true"`.
- Terraform module made remote-source-safe (SCP policies inlined via `jsonencode()`).
- SCP3 condition key corrected to PascalCase `bedrock:BearerTokenType`.

## [1.0.0]

Initial release. See <https://github.com/BeyondTrust/bedrock-keys-security/releases/tag/v1.0.0>.
