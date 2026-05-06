# Changelog

All notable changes to BKS are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-05-06

### Breaking

- `bks scan --json` and `bks scan --csv` now write to `output/bks-scan-<account>-<UTC>.<ext>` instead of streaming JSON to stdout or requiring `--csv FILE`. SOAR pipelines should read the file path from the final stdout line (`JSON saved: ...`).
- `bks scan --csv` is now flag-only. The previous `--csv <FILE>` form is no longer accepted.
- `bks decode-key --json` now writes `output/bks-decode-<account>-<UTC>.json` instead of streaming JSON to stdout.
- `bks cleanup --json`, `bks revoke-key --json`, `bks timeline --json` and `bks report --json` are new in this release; each writes a structured JSON result to `output/bks-<command>-<account>-<UTC>.json`. `scanner.revoke_key`, `scanner.revoke_short_term_key`, `scanner.cleanup_orphaned_users` and `scanner.generate_timeline` now return `Dict` instead of the previous `bool` / `None` / partial-`Dict` shapes.
- IaC modules moved from `iac/` to `scps/`. Terraform consumers using `source = "github.com/BeyondTrust/bedrock-keys-security//iac/terraform"` must update to `//scps/terraform`. CloudFormation template path: `scps/cloudformation/scps.yaml`.

### Added

- `--quiet` / `-q` flag for SOAR pipelines. Suppresses banner, table and summary; saved-file paths still print to stdout; errors stay on stderr. Accepted at both group and per-command level (`bks --quiet scan` and `bks scan --quiet` are equivalent across all commands).
- `--output-dir DIR` global flag (default `./output`) lets SOAR / cron operators redirect JSON / CSV reports to `/var/log/bks` or any other path. Directory is created if missing.
- `--region` global flag (default `us-east-1`) plus per-command override.
- Scan output ordered by status priority then creation date: AT RISK > ACTIVE > ORPHANED.
- Scan completion footer with total IAM users, phantom count and elapsed time.
- AT RISK and ORPHANED advisory blocks under the scan table with concrete remediation commands.
- Severity icons (`▸ ✓ ⚠ ✗`) in CLI output.
- Terraform module under `scps/terraform/` with four conditional `aws_organizations_policy` resources and optional OU attachment.
- CloudFormation template at `scps/cloudformation/scps.yaml`, conditional resources, StackSet-friendly.
- `EventBridge bedrock-api-key-usage` pattern under `detections/eventbridge/`.
- pytest suite (27 cases) covering decoder offline behavior and CLI UX (quiet mode, banner shape, scan accounting, cleanup pluralization, decode-key format-line, output-path generation).
- GitHub Actions matrix on Python 3.10, 3.11, 3.12 and 3.13.
- `docs/permissions.md` IAM permissions matrix per command.
- Black Hat Arsenal US 26 acceptance badge and Talks entry.

### Changed

- README reframed from phantom-user-centric to "AWS Bedrock API keys security toolkit" across H1, tl;dr, Motivation, `pyproject.toml` description and CLI top-level docstring.
- Scan banner trimmed from 11 to 2 lines, with blank-line spacing before the table and spinner.
- Decoder `security_notes` now carries only key-specific findings. The four generic ABSK education lines that fired on every long-term decode were removed; secondary keys keep the `+N` marker note.
- README, detection rules and code comments scrubbed of em dashes and Oxford commas. Tier-2 and tier-3 dedup passes across `detections/README.md`, four Sigma descriptions, scanner and decoder docstrings.

### Security

- **Path traversal in `bks decode-key --json`** (high severity, internally found): the `account_id` parsed from a long-term ABSK key flowed unsanitized into the output filename. A crafted key with `account_id=../../etc/PWNED` could write the JSON forensic output anywhere the user has filesystem write access (e.g. `~/.ssh/authorized_keys`, `~/.bashrc`). `build_output_path` now validates `account_id` against `^\d{12}$` and falls back to `unknown` for any non-conforming value. The raw value is still recorded in the JSON content for forensic visibility.
- **CSV injection in `bks scan --csv`** (medium severity): IAM allows `=` in usernames (charset `[\w+=,.@-]`), so a hostile actor with `iam:CreateUser` could plant `BedrockAPIKey-=cmd|...` whose row triggered RCE in a SOC analyst's Excel on open. Cells starting with `= + - @ \t \r` are now prefixed with `'` to neutralize formula evaluation.
- **JSON / CSV outputs now written with `0600` permissions** to avoid disclosure on shared hosts. Reports include IAM usernames, ARNs, access key IDs, CloudTrail events with source IPs and user-agents, and policy details.
- **Filename timestamp resolution upgraded from second to microsecond** (`bks-<command>-<account>-YYYYMMDDTHHMMSSffffffZ.<ext>`), eliminating silent overwrites when concurrent runs fire in the same second (real for SOAR pipelines and cron jobs).

### Fixed

- Python 3.10 / 3.11 f-string compat: `\u` escapes inside f-string expression parts replaced with literal Unicode characters. PEP 701 relaxed this in 3.12; the issue was previously hidden by local Python 3.14 testing.
- Sigma cross-region rule rewritten with 2.x correlation syntax (the 1.0.0 pipe form was rejected by pySigma).
- Six Sigma rule IDs regenerated as proper UUIDs (1.0.0 had placeholder strings rejected by pySigma).
- CloudTrail Lake queries: five distinct dialect bugs fixed around `requestParameters` shape, time bucketing and timestamp arithmetic.
- CloudWatch Insights `callWithBearerToken` filter quoted as `"true"` (CloudTrail-to-CWL serialization quirk).
- Terraform module made remote-source-safe: SCP policies inlined via `jsonencode()`. The 1.0.0 `${path.module}/../../scps/*.json` reference broke when consuming via `source = "git::..."`.
- SCP3 condition key corrected to PascalCase `bedrock:BearerTokenType`. Validated end-to-end against a real AWS Organization in 1.1.0.

## [1.0.0]

Initial release. See <https://github.com/BeyondTrust/bedrock-keys-security/releases/tag/v1.0.0>.
