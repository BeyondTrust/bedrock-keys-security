# Changelog

## [1.3.1] - 2026-07-08

### Fixed

- `bks revoke-key` and the Bedrock SCPs now also cover the `bedrock-mantle` inference plane. A `bedrock:*`-only deny left a revoked long-term key usable on `bedrock-mantle`.

## [1.3.0] - 2026-06-30

### Added

- [Claude Platform on AWS](https://docs.aws.amazon.com/claude-platform/latest/userguide/welcome.html) coverage. BKS detects, decodes, scans and contains `AeaApiKey-*` phantom users (the `aws-external-anthropic` service auto-provisions them with [`AnthropicLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AnthropicLimitedAccess.html)), the same way it already does for Bedrock.
- `bks scan --service [bedrock|claude-platform|all]`, default `all`. Same flag on `bks cleanup` and `bks scan --org`.
- `bks revoke-key`, `bks timeline` and `bks report` autodetect the service from the username or decoded key prefix.
- `bks revoke-key` on a Claude Platform phantom: inline `aws-external-anthropic:*` deny + delete service-specific credentials + disable the phantom user's IAM access keys.
- `bks decode-key` auto-detects the format; new prefixes `AEAA` (long-term) and `aws-external-anthropic-api-key-` (short-term).
- `bks timeline` accepts short-term keys: decodes the embedded `ASIA`, anchors on `AccessKeyId=`, and surfaces the operator (ARN, source IP, user agent, Identity Center user) behind each call.
- Claude Platform SCPs under `scps/claude-platform/` (full lockout, block phantom-user creation, long-term-only, block phantom access keys, 90-day max, workspace allowlist), with Terraform / CloudFormation modules.
- New SCP `scps/bedrock/2-block-phantom-user-creation.json`.
- Detection content for Claude Platform (Sigma, EventBridge, CloudTrail Lake, Athena, CloudWatch Insights).
- `ClaudePlatformKeyDecoder`, `ClaudePlatformPhantomScanner` and `multi_decoder.decode_any_key()` / `detect_service()` exposed for library users.
- pytest suite expanded with Claude Platform decoder, scanner, timeline, revoke and scan-rendering coverage.

### Breaking

- Bedrock SCPs moved under `scps/bedrock/`. Terraform `source` becomes `/scps/bedrock/terraform`.
- Detection files moved to `detections/<surface>/<format>/`. Update SIEM wildcards to `detections/*/sigma/*.yml`, etc.
- Bedrock short-term decoder field `service` renamed to `sigv4_service`.

## [1.2.1] - 2026-05-19

### Fixed

- `bks --version` reported the wrong version on 1.2.0. `__version__` now reads from package metadata via `importlib.metadata.version()` so it cannot drift from `pyproject.toml`.

## [1.2.0] - 2026-05-19

### Added

- `--org` flag on `scan`: organization-wide scan via `sts:AssumeRole` across every ACTIVE member account, with per-account fail isolation.
- `--org-role NAME` flag on `scan` (default `OrganizationAccountAccessRole`): cross-account role to assume in each member account.
- `--org-accounts IDS` flag on `scan`: scope `--org` to comma-separated 12-digit account IDs.
- `--org-skip IDS` flag on `scan`: exclude comma-separated 12-digit account IDs from `--org`.

## [1.1.0] - 2026-05-06

### Breaking

- `--json` and `--csv` on every command write to `output/bks-<command>-<account>-<UTC>.<ext>` instead of streaming to stdout.
- `bks scan --csv` is now flag-only (no `<FILE>` argument).
- `scanner.revoke_key`, `scanner.revoke_short_term_key`, `scanner.cleanup_orphaned_users`, and `scanner.generate_timeline` return `Dict` instead of `bool` / `None`.
- IaC modules moved from `iac/` to `scps/`. Terraform consumers using `source = "...//iac/terraform"` must update to `//scps/terraform`.

### Added

- `--quiet` / `-q` flag, accepted at group and per-command level.
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
