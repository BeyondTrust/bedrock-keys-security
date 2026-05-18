# The AWS Bedrock API keys security toolkit

**tl;dr:** AWS Bedrock API keys behave nothing like regular AWS credentials. BKS includes an offline decoder, phantom user discovery, incident response, automated cleanup, preventive SCPs and SIEM-ready detection content.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/bedrock-keys-security.svg)](https://pypi.org/project/bedrock-keys-security/)
[![Black Hat Arsenal US 26](https://img.shields.io/badge/Black%20Hat-Arsenal%20US%2026-black)](https://blackhat.com/us-26/arsenal/schedule/index.html#bedrock-keys-security-bks-hunting-phantom-iam-users-created-by-aws-bedrock-api-keys-52541)
[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/MrCloudSec.svg?style=social&label=Follow%20the%20author)](https://twitter.com/MrCloudSec)

**Contents**: [Quickstart](#quickstart) · [Motivation](#motivation) · [Installation](#installation) · [Usage](#usage) · [Prevention](#prevention-with-service-control-policies) · [Detection](#detection-content) · [Migration to STS](#migration-to-sts) · [Talks](#talks) · [Contributing](#contributing)

## Quickstart

```bash
pip install bedrock-keys-security
bks scan --profile your-aws-profile
```

`bks scan` discovers every `BedrockAPIKey-*` phantom user in the account, categorizes risk (`AT RISK` / `ACTIVE` / `ORPHANED`) and prints a summary table.

```bash
# Decode a leaked key offline (no AWS credentials needed)
bks decode-key "ABSKQmVkcm9ja..."

# Scan every active member account in the organization
bks scan --org --profile mgmt-account

# Investigate a phantom user across every region with CloudTrail coverage
bks timeline BedrockAPIKey-xxxx --all-regions --days 30

# Emergency revocation: deny Bedrock + delete API keys + disable AKIA pivots
bks revoke-key BedrockAPIKey-xxxx
```

Detection content (Sigma, CloudTrail Lake, Athena, EventBridge, CloudWatch Insights) lives in [`detections/`](detections/). SCP policies and their Terraform / CloudFormation modules live in [`scps/`](scps/).

## Motivation

AWS Bedrock API keys behave unlike regular AWS credentials. They authenticate via bearer tokens instead of SigV4, and they embed the AWS account ID and IAM username in plain base64.

The most damaging behavior: when a user creates a long-term Bedrock API key through the AWS Console, AWS silently provisions an IAM user named `BedrockAPIKey-xxxx` and attaches the [`AmazonBedrockLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html) managed policy.

Despite its name, the policy is effectively administrative: 48 actions across `bedrock:*` (44) and `bedrock-mantle:*` (4) covering create / read / update / delete across all Bedrock resources, plus cross-service reconnaissance (`iam:ListRoles`, `kms:DescribeKey`, `ec2:Describe{Vpcs,Subnets,SecurityGroups}`). Full action list in the AWS doc linked above.

These phantom users are never automatically cleaned up. They accumulate over time, creating an expanding attack surface that most organizations don't know exists.

### Attack Paths

![Attack Paths Diagram](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/attack-paths.jpeg)

**LLMjacking:** An attacker who obtains a leaked key can spin up workers across all AWS regions to consume foundation model capacity. Worst-case exposure depends on the default Bedrock service quota and the model price; for Claude Opus 4.7 at list pricing (May 2026), this works out to roughly $18,000/day per region.

![LLMjacking Attack Flow](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/llm-jacking.jpeg)

**Privilege Escalation:** If an attacker creates an IAM access key on the phantom user, or if one already exists, they gain persistent IAM credentials (`AKIA...`) that extend well beyond Bedrock. From there, they can pivot to S3, Secrets Manager and other services, even after the original Bedrock key expires.

> **Deep-dive:** [AWS Bedrock API Keys Security Guide, Part 1: Risks, Vulnerabilities and Attack Techniques](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-api-keys) and [Part 2: Detection, Prevention and Response](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response) on the BeyondTrust Phantom Labs blog.

## Installation

Install from PyPI:

```bash
pip install bedrock-keys-security
```

Or install from source:

```bash
git clone https://github.com/BeyondTrust/bedrock-keys-security.git
cd bedrock-keys-security
pip install .
```

Verify the installation:

```bash
bks --version
```

Required AWS permissions per command: see [docs/permissions.md](docs/permissions.md).

## Usage

### Scanning

Run a scan to discover all phantom IAM users in your account:

```bash
bks scan                      # scan with default profile
bks scan --profile prod       # use a specific AWS profile
bks scan --region eu-west-1   # override the default us-east-1 region
bks scan --json               # save JSON to output/
bks scan --csv                # save CSV to output/
bks scan --verbose            # detailed output
bks --quiet scan --json       # SOAR pipelines: only the saved-file path goes to stdout

# Org-wide scan: AssumeRole into every active member account and aggregate
bks scan --org                                              # uses OrganizationAccountAccessRole
bks scan --org --org-role MyOrgScanRole                     # custom cross-account role
bks scan --org --org-accounts 111111111111,222222222222     # scope to specific accounts
bks scan --org --org-skip 333333333333 --json               # exclude an account, save JSON
```

#### Org-wide scan

Run from the management account or a delegated admin. `bks` calls
`organizations:ListAccounts` and fans out across every ACTIVE member
account in parallel via `sts:AssumeRole`. Per-account failures (role
missing, AccessDenied) are captured per-account and never abort the
run; failed accounts are surfaced in the final report.

The aggregate JSON shape (`output/bks-scan-org-<mgmt-account>-<UTC>.json`):

```json
{
  "scan_metadata": {
    "mode": "org",
    "management_account_id": "111111111111",
    "role_assumed": "OrganizationAccountAccessRole",
    "accounts_total": 12, "accounts_scanned": 11, "accounts_failed": 1,
    "scan_time": "2026-05-10T14:30:22+00:00"
  },
  "summary": { "total": 17, "active": 4, "orphaned": 11, "at_risk": 2 },
  "accounts": [
    { "account_id": "222222222222", "account_name": "prod",
      "status": "ok", "summary": {"total": 3, "active": 1, "orphaned": 2, "at_risk": 0},
      "phantom_users": [ ... ] },
    { "account_id": "333333333333", "account_name": "sandbox",
      "status": "error", "error": "AssumeRole arn:...: AccessDenied",
      "summary": {"total": 0, "active": 0, "orphaned": 0, "at_risk": 0} }
  ]
}
```

`--csv` flattens this to one row per phantom user with `account_id` / `account_name` columns prepended.

Example output:

```
bks v1.1.0  BedrockAPIKey-* phantom user scanner
Account: 123456789012  Region: us-east-1

+--------------------+------------+-------------------+---------------+----------+
| Username           | Created    |   Active API Keys |   Access Keys | Status   |
+====================+============+===================+===============+==========+
| BedrockAPIKey-h42z | 2026-03-12 |                 1 |             2 | AT RISK  |
| BedrockAPIKey-x8q1 | 2026-04-22 |                 1 |             0 | ACTIVE   |
| BedrockAPIKey-aaa1 | 2025-11-08 |                 0 |             0 | ORPHANED |
+--------------------+------------+-------------------+---------------+----------+

Summary:
  Total phantom users: 3
  At Risk: 1 (IAM access keys found)
  Active: 1 (live Bedrock API keys)
  Orphaned: 1 (safe to cleanup)

⚠ AT RISK · 1 phantom user with persistent IAM credentials
   - BedrockAPIKey-h42z  (2 access keys)

   These keys inherit Bedrock admin + IAM/VPC/KMS reconnaissance from
   AmazonBedrockLimitedAccess, and persist after Bedrock key revocation.

   → bks revoke-key <username>   emergency containment
   → bks report     <username>   forensic report

▸ ORPHANED · 1 phantom user with no active credentials
   These accumulate over time as privilege-escalation pivots. Cleanup
   shrinks the attack surface; no live workflow is affected.

   → bks cleanup --dry-run   preview deletions
   → bks cleanup             delete with confirmation


Scan complete  127 IAM users  ·  3 phantoms  ·  1.4s
```

JSON / CSV reports are written to `output/bks-scan-<account>-<UTC-timestamp>.<ext>` (the directory is created automatically). Override the destination with the global `--output-dir DIR` flag (e.g. `bks --output-dir /var/log/bks scan --json`). The JSON shape:

```json
{
  "scan_metadata": {
    "account_id": "123456789012",
    "region": "us-east-1",
    "scan_time": "2026-05-06T14:30:22+00:00",
    "caller_arn": "arn:aws:iam::123456789012:user/security"
  },
  "summary": { "total": 3, "active": 1, "orphaned": 1, "at_risk": 1 },
  "phantom_users": [
    { "username": "BedrockAPIKey-h42z", "status": "AT RISK", "created": "2026-03-12T09:14:08+00:00", "...": "..." }
  ]
}
```

Each phantom user is categorized by risk level:
- **AT RISK:** Has IAM access keys with `bedrock:*` and recon permissions. Revoking the Bedrock key does not disable them.
- **ACTIVE:** Has valid Bedrock API credentials
- **ORPHANED:** No active credentials remaining (safe to delete)

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/scan-example.png" alt="Scan Example" width="600">

### Cleanup

Remove orphaned phantom users that no longer have active credentials:

```bash
bks cleanup --dry-run         # preview what would be deleted
bks cleanup                   # delete with confirmation prompt
bks cleanup --force           # skip confirmation (use with caution)
bks cleanup --json            # save cleanup result as JSON to output/
```

Only ORPHANED users are affected. ACTIVE and AT RISK users are never deleted automatically.

### Incident Response

When a key is compromised, `bks` provides emergency response capabilities:

```bash
bks revoke-key BedrockAPIKey-xxxx                 # emergency key revocation
bks revoke-key BedrockAPIKey-xxxx --force         # skip confirmation
bks revoke-key BedrockAPIKey-xxxx --json          # save revocation result to output/
bks timeline BedrockAPIKey-xxxx                   # CloudTrail timeline (last 7 days, configured region)
bks timeline BedrockAPIKey-xxxx --days 30         # extended timeline
bks timeline BedrockAPIKey-xxxx --all-regions     # fan out across every region with CloudTrail coverage
bks timeline BedrockAPIKey-xxxx --json            # save events list as JSON to output/
bks report BedrockAPIKey-xxxx                     # full incident report
bks report BedrockAPIKey-xxxx --output report.txt # save text report to FILE
bks report BedrockAPIKey-xxxx --json              # save report data as JSON to output/
```

`revoke-key` applies an inline `Deny: bedrock:*` policy, deletes all Bedrock service-specific credentials and disables IAM access keys (`AKIA*`) on the phantom user, closing the privilege-escalation pivot in the same operation.

`timeline --all-regions` is recommended whenever LLMjacking is suspected. Bedrock data-plane events (`InvokeModel`, `Converse`, `CallWithBearerToken`) are recorded in the region they ran, not the home region; a single-region timeline misses cross-region fan-out by design.

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/revoke-key.png" alt="Revoke Key" width="600">

### Key Decoding

Decode leaked Bedrock API keys offline, no AWS credentials required:

```bash
bks decode-key "ABSKQmVkcm9ja0FQSUtleS..."          # print analysis to terminal
bks decode-key "bedrock-api-key-YmVkcm9ja..." --json # save JSON to output/
```

Extracts the embedded IAM username, AWS account ID, region and key format. Useful for triaging keys found on GitHub, Pastebin or other public sources. With `--json`, writes `output/bks-decode-<account>-<UTC-timestamp>.json`.

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/long-term-key.png" alt="Long-term Key Decode" width="480">

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/short-term-key.png" alt="Short-term Key Decode" width="480">

## Prevention with Service Control Policies

Four SCPs are provided for organizational enforcement. Apply via AWS Organizations.

| SCP | File | Purpose |
|---|---|---|
| Block all keys (recommended) | `scps/1-block-all-keys.json` | Deny creation + usage org-wide |
| Enforce 90-day max | `scps/2-enforce-90day-max.json` | Limit damage window |
| Block long-term only | `scps/3-block-long-term-only.json` | Allow short-term, block ABSK |
| Block phantom escalation | `scps/4-block-phantom-access-keys.json` | Close privesc pivot |

Deploy any SCP via:

```bash
aws organizations create-policy \
  --name <NAME> \
  --type SERVICE_CONTROL_POLICY \
  --content file://scps/<FILE>

aws organizations attach-policy \
  --policy-id p-xxxxx \
  --target-id <ROOT_OR_OU_ID>
```

> **Note:** Always test SCPs on non-production OUs before applying broadly.

### Infrastructure as Code

The same four SCPs are available as ready-to-deploy modules:

- **Terraform**: [`scps/terraform/`](scps/terraform/) wraps the four SCPs as `aws_organizations_policy` resources with optional OU attachment.
- **CloudFormation**: [`scps/cloudformation/scps.yaml`](scps/cloudformation/scps.yaml) is a single template with conditional resources, StackSet-friendly.

Both default to enabling `Block-Bedrock-API-Keys` plus `Block-Phantom-User-Escalation`, the recommended baseline pair.

## Detection Content

SIEM-ready detection rules for the full attack chain are in [`detections/`](detections/): 6 Sigma rules, 2 CloudTrail Lake queries, 2 Athena queries, 5 EventBridge patterns and 1 CloudWatch Insights query. Coverage spans bearer-token usage, key creation, phantom-user creation, AKIA escalation, cross-region fan-out and suspicious user-agents.

> **Deep-dive:** Detection strategies, deployment guidance for CloudWatch, EventBridge and SIEM platforms in [AWS Bedrock API Keys Security Guide, Part 2: Detection, Prevention and Response](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response).

## Migration to STS

Most teams do not need Bedrock API keys. AWS STS temporary credentials are the recommended approach:

- Automatically expire (1 to 12 hours)
- No phantom users created
- Standard AWS SigV4 signing (not bearer tokens)
- No persistent credentials to leak

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/BedrockRole \
  --role-session-name bedrock-session \
  --duration-seconds 3600

export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws bedrock-runtime converse \
  --model-id us.anthropic.claude-opus-4-7 \
  --messages '[{"role":"user","content":[{"text":"hello"}]}]'
```

API keys may still be necessary for legacy applications hardcoded for bearer tokens, third-party tools without SigV4 support or vendor software lacking STS integration. In those cases, use short-term keys with a maximum 12-hour lifetime and enforce restrictions with the SCPs above.

## Talks

- **Black Hat USA 2026 Arsenal** (upcoming, August 2026): *Bedrock Keys Security (BKS): Hunting Phantom IAM Users Created by AWS Bedrock API Keys* ([session](https://blackhat.com/us-26/arsenal/schedule/index.html#bedrock-keys-security-bks-hunting-phantom-iam-users-created-by-aws-bedrock-api-keys-52541))
- **BSides Seattle 2026**: *The Phantom of the Infrastructure: Investigating the Hidden IAM Risks in Bedrock API Keys* ([slides](docs/bsides-seattle-2026.pdf), [video](https://www.youtube.com/watch?v=v3wvjb9Gu-c))
- **RootedCON Madrid 2026**: *The Phantom of the Infrastructure: The Invisible Threat in Bedrock API Keys*

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR workflow and review requirements.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contact

- Issues and bugs: [GitHub Issues](https://github.com/BeyondTrust/bedrock-keys-security/issues)
- Twitter: [@btphantomlabs](https://x.com/btphantomlabs)

## References

- [AWS Bedrock API Keys Security Guide, Part 1: Risks, Vulnerabilities and Attack Techniques](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-api-keys) (BeyondTrust Phantom Labs)
- [AWS Bedrock API Keys Security Guide, Part 2: Detection, Prevention and Response](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response) (BeyondTrust Phantom Labs)
- [AWS Bedrock API Keys User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
- [AWS Security Blog: Securing Bedrock API Keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/)
- [AWS SCP Examples for Bedrock](https://github.com/aws-samples/service-control-policy-examples/tree/main/Service-specific-controls/Amazon-Bedrock)
- [AWS Customer Playbook Framework: Bedrock EventBridge CFN](https://github.com/aws-samples/aws-customer-playbook-framework/tree/main/detections/cfn)
- [CloudTrail Logging for Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)
