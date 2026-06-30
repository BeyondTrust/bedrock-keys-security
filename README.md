# The AWS Bedrock API keys security toolkit

**tl;dr:** AWS Bedrock API keys behave nothing like regular AWS credentials: generating one silently creates a hidden IAM user (a *phantom user*) with a broad managed policy attached. BKS hunts these phantom users across both Bedrock and [Claude Platform on AWS](https://docs.aws.amazon.com/claude-platform/latest/userguide/welcome.html) keys, with an offline key decoder, incident response, automated cleanup, preventive SCPs and SIEM-ready detection content.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/bedrock-keys-security.svg)](https://pypi.org/project/bedrock-keys-security/)
[![Black Hat Arsenal US 26](https://img.shields.io/badge/Black%20Hat-Arsenal%20US%2026-black)](https://blackhat.com/us-26/arsenal/schedule/index.html#bedrock-keys-security-bks-hunting-phantom-iam-users-created-by-aws-bedrock-api-keys-52541)
[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/MrCloudSec.svg?style=social&label=Follow%20the%20author)](https://twitter.com/MrCloudSec)

**Contents**: [Quickstart](#quickstart) · [Motivation](#motivation) · [Installation](#installation) · [Usage](#usage) · [Prevention](#prevention-with-service-control-policies-scps) · [Detection](#detection-content) · [Migration to STS](#migration-to-sts) · [Talks](#talks) · [Contributing](#contributing)

## Quickstart

```bash
pip install bedrock-keys-security
bks scan --profile your-aws-profile
```

`bks scan` discovers every phantom user in the account (`BedrockAPIKey-*` and `AeaApiKey-*`), categorizes risk (`AT RISK` / `ACTIVE` / `ORPHANED`) and prints a summary table.

```bash
# Decode a leaked key offline (no AWS credentials needed)
# Auto-detects whether the API key is a Bedrock (ABSK, bedrock-api-key-)
# or a Claude Platform on AWS (AEAA, aws-external-anthropic-api-key-) format.
bks decode-key "ABSKQmVkcm9ja..."
bks decode-key "AEAAQWVhQXBpS2V5..."

# Scan every active member account in the organization
bks scan --org --profile mgmt-account

# Default scan covers both Bedrock and Claude Platform surfaces.
bks scan --profile your-profile

# Scope to a single surface (one output file) with --service:
bks scan --service bedrock --profile your-profile
bks scan --service claude-platform --profile your-profile

# Investigate a phantom user across every region with CloudTrail coverage
bks timeline BedrockAPIKey-xxxx --all-regions --days 30

# Emergency revocation: deny Bedrock + delete API keys + disable IAM access-key pivots
bks revoke-key BedrockAPIKey-xxxx
```

## Motivation

AWS Bedrock API keys behave unlike regular AWS credentials. They authenticate via bearer tokens instead of SigV4, and they embed the AWS account ID and IAM username in plain base64.

The most damaging behavior: when a user creates a long-term Bedrock API key through the AWS Console, AWS **silently provisions an IAM user** named `BedrockAPIKey-xxxx` and attaches the [`AmazonBedrockLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html) managed policy.

Despite its name, the policy is **effectively administrative**. As of July 2026 (version v8) it grants 48 actions across `bedrock:*` (44) and `bedrock-mantle:*` (4) covering create / read / update / delete across all Bedrock resources, plus cross-service reconnaissance (`iam:ListRoles`, `kms:DescribeKey`, `ec2:Describe{Vpcs,Subnets,SecurityGroups}`).

These phantom users are never automatically cleaned up. They accumulate over time, creating an expanding attack surface that most organizations don't know exists. The same trap applies to Claude Platform on AWS keys, whose phantom users carry the workspace-scoped [`AnthropicLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AnthropicLimitedAccess.html) policy, which keeps their blast radius tighter than Bedrock's, as the next section explains.

### Attack Paths

![Attack Paths Diagram](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/attack-paths.jpeg)

**LLMjacking:** An attacker who obtains a leaked key, Bedrock or Claude Platform, can spin up workers across AWS regions to burn foundation-model capacity on your account. Worst-case exposure depends on the service quota and the model price; for Claude Opus 4.8 at list pricing (2026), this works out to **roughly $18,000/day per region**.

![LLMjacking Attack Flow](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/llm-jacking.jpeg)

**Privilege Escalation:** A Bedrock API key is a bearer token, so it only reaches `bedrock:*`. The IAM, KMS and EC2 reconnaissance that [`AmazonBedrockLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html) also grants (`iam:ListRoles`, `kms:DescribeKey`, `ec2:Describe*`) is unreachable with a bearer token, since those actions require SigV4-signed requests.

Creating an IAM access key on the phantom user unlocks exactly that gap: standard long-term credentials that exercise the full policy, map roles, keys and network for lateral movement, and keep working after the Bedrock API key is rotated or revoked.

**This pivot is Bedrock-specific:** on Claude Platform, [`AnthropicLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AnthropicLimitedAccess.html) is workspace-scoped, so an access key on a Claude Platform phantom user reaches nothing beyond the key's own surface, no escalation. That is why `bks scan` flags Bedrock phantoms holding access keys as `AT RISK` but Claude Platform ones only `ACTIVE`.

> **Deep-dive:** [AWS Bedrock API Keys Security Guide, Part 1: Risks, Vulnerabilities and Attack Techniques](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-api-keys) on the BeyondTrust Phantom Labs blog.

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
bks --quiet scan --json       # quiet mode: only the saved-file path goes to stdout

# Scope to one surface (default scans both Bedrock and Claude Platform)
bks scan --service bedrock
bks scan --service claude-platform

# Org-wide scan: AssumeRole into every active member account and aggregate
bks scan --org                                              # uses OrganizationAccountAccessRole
bks scan --org --org-role MyOrgScanRole                     # custom cross-account role
bks scan --org --org-accounts 111111111111,222222222222     # scope to specific accounts
bks scan --org --org-skip 333333333333 --json               # exclude an account, save JSON
```

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/scan-example.png" alt="Scan Example" width="600">

Each phantom user is categorized by risk level:
- **AT RISK:** Has an IAM access key, which leads to full access to the [`AmazonBedrockLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html) policy (`bedrock:*` plus IAM/KMS/EC2 reconnaissance). Revoking the Bedrock key does not disable it. (`AT RISK` is a Bedrock-only status because [`AnthropicLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AnthropicLimitedAccess.html) grants no IAM/KMS/EC2 reconnaissance).
- **ACTIVE:** Has valid Bedrock API credentials
- **ORPHANED:** No active credentials remaining (safe to delete)

JSON / CSV reports are written to `output/` (auto-created), one file per scanned surface. Override the location with the global `--output-dir` flag (`bks --output-dir DIR scan`). The per-surface JSON shape (Bedrock shown; the Claude Platform summary omits `at_risk`):

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

#### Org-wide scan

Run from the management account or a delegated admin. `bks` calls
`organizations:ListAccounts` and scans every ACTIVE member
account in parallel via `sts:AssumeRole`.

The scan writes a single combined report (`output/bks-scan-org-<mgmt-account>-<UTC>.json`):

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

### Cleanup

Remove orphaned phantom users that no longer have active credentials:

```bash
bks cleanup --dry-run         # preview what would be deleted
bks cleanup                   # delete with confirmation prompt
bks cleanup --force           # skip confirmation (use with caution)
bks cleanup --json            # save cleanup result as JSON to output/
```

Covers both `BedrockAPIKey-*` and `AeaApiKey-*` orphans; scope to one surface with `--service`. Only ORPHANED users are deleted, never ACTIVE or AT RISK.

### Incident Response

When a key is compromised, `bks` provides emergency response capabilities:

```bash
# revoke-key: a phantom username (BedrockAPIKey-* / AeaApiKey-*), a long-term key, or a short-term key
bks revoke-key AeaApiKey-xxxx
bks revoke-key bedrock-api-key-xxxx                  # short-term

# timeline: a phantom username (BedrockAPIKey-* / AeaApiKey-*), a long-term key, or a short-term key (add --all-regions when LLMjacking is suspected)
bks timeline BedrockAPIKey-xxxx --all-regions
bks timeline aws-external-anthropic-api-key-xxx      # short-term

# report: a phantom username or long-term key (short-term: use timeline / revoke-key)
bks report AeaApiKey-xxxx
```

`revoke-key` on a long-term key or a `BedrockAPIKey-*` / `AeaApiKey-*` username denies the service (`bedrock:*` or `aws-external-anthropic:*`), deletes the service-specific credentials and disables any IAM access keys (`AKIA*`), closing the privilege-escalation pivot in one step. On a short-term key it decodes the embedded `ASIA` (a temporary STS access key), finds who used it in CloudTrail, and denies the principal's already-issued sessions via `aws:TokenIssueTime`, killing the leaked key while newer sessions keep working.

`timeline` traces a phantom user or key's activity through CloudTrail, showing who used it, when and from where. Add `--all-regions` when LLMjacking is suspected.

`report` gathers the details, API credentials, IAM access keys and attached policies of a phantom IAM user into a single incident report, as text or `--json`.

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/revoke-key.png" alt="Revoke Key" width="600">

### Key Decoding

Decode leaked Bedrock and Claude Platform API keys offline, no AWS credentials required:

```bash
bks decode-key "ABSKQmVkcm9ja0FQSUtleS..."                   # Bedrock long-term
bks decode-key "aws-external-anthropic-api-key-..." --json   # Claude Platform short-term, saves JSON
```

Auto-detects the format and extracts the AWS account ID, plus the IAM username from a long-term key or the temporary STS access key and region from a short-term key. With `--json`, writes `output/bks-decode-<account>-<UTC-timestamp>.json`.

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/long-term-key.png" alt="Long-term Key Decode" width="480">

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/short-term-key.png" alt="Short-term Key Decode" width="480">

## Prevention with Service Control Policies (SCPs)

Long-term API keys are static credentials that never expire on their own, and each one provisions a phantom IAM user, so every key left in place adds lasting risk.

Service Control Policies (SCPs) address this preventively: applied at the org root or an organizational unit (OU), an SCP caps what every account can do. A single policy can:

- block API key creation and use entirely,
- restrict creation to short-term keys, or
- cap key lifetime across the whole organization.

| # | Bedrock | Claude Platform | Purpose |
|---|---|---|---|
| 1 | [`scps/bedrock/1-block-all-keys.json`](scps/bedrock/1-block-all-keys.json) | [`scps/claude-platform/1-block-all-keys.json`](scps/claude-platform/1-block-all-keys.json) | Deny creation and usage org-wide |
| 2 | [`scps/bedrock/2-block-phantom-user-creation.json`](scps/bedrock/2-block-phantom-user-creation.json) | [`scps/claude-platform/2-block-phantom-user-creation.json`](scps/claude-platform/2-block-phantom-user-creation.json) | Deny `iam:CreateUser` on the phantom-user prefix and deny attaching the service managed policy elsewhere |
| 3 | [`scps/bedrock/3-block-long-term-only.json`](scps/bedrock/3-block-long-term-only.json) | [`scps/claude-platform/3-block-long-term-only.json`](scps/claude-platform/3-block-long-term-only.json) | Allow short-term, block long-term API keys |
| 4 | [`scps/bedrock/4-block-phantom-access-keys.json`](scps/bedrock/4-block-phantom-access-keys.json) | [`scps/claude-platform/4-block-phantom-access-keys.json`](scps/claude-platform/4-block-phantom-access-keys.json) | Close the privilege escalation pivot from phantom user to an IAM access key (`AKIA`) |
| 5 | [`scps/bedrock/5-enforce-90day-max.json`](scps/bedrock/5-enforce-90day-max.json) | [`scps/claude-platform/5-enforce-90day-max.json`](scps/claude-platform/5-enforce-90day-max.json) | Cap the API key lifetime to 90 days |
| 6 | N/A | [`scps/claude-platform/6-workspace-allowlist.json`](scps/claude-platform/6-workspace-allowlist.json) | Restrict a specific Claude Platform workspace to an allowlist of principals |

Deploy any SCP via:

```bash
aws organizations create-policy \
  --name <NAME> \
  --type SERVICE_CONTROL_POLICY \
  --content file://scps/<SURFACE>/<FILE>

aws organizations attach-policy \
  --policy-id p-xxxxx \
  --target-id <ROOT_OR_OU_ID>
```

> **Note:** Always test SCPs on non-production OUs before applying broadly.

### Infrastructure as Code

Ready-to-deploy Terraform and CloudFormation modules ship for both surfaces: Bedrock ([Terraform](scps/bedrock/terraform/), [CloudFormation](scps/bedrock/cloudformation/scps.yaml)) and Claude Platform ([Terraform](scps/claude-platform/terraform/), [CloudFormation](scps/claude-platform/cloudformation/scps.yaml)).

## Detection Content

SIEM-ready detection rules for the full attack chain live in [`detections/`](detections/), one set per surface: [`detections/bedrock/`](detections/bedrock/) and [`detections/claude-platform/`](detections/claude-platform/). Each surface ships Sigma rules, CloudTrail Lake and Athena queries, EventBridge patterns and a CloudWatch Insights query. Coverage spans API key usage, key creation, phantom-user creation, privilege escalation (Bedrock only), cross-region use and suspicious user-agents.

The Bedrock rules fire on any trail by default; the Claude Platform rules need [CloudTrail data-event logging](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html#logging-data-events) enabled. Setup and the per-event cost are in [`detections/README.md`](detections/README.md#tuning-notes).

> **Deep-dive:** Detection strategies, deployment guidance for CloudWatch, EventBridge and SIEM platforms in [AWS Bedrock API Keys Security Guide, Part 2: Detection, Prevention and Response](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response).

## Migration to STS

Most teams do not need API keys at all. Both Bedrock and Claude Platform on AWS accept standard SigV4-signed requests backed by AWS STS temporary credentials, which is the recommended approach:

- Automatically expire (15 minutes to 12 hours)
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
  --model-id us.anthropic.claude-opus-4-8 \
  --messages '[{"role":"user","content":[{"text":"hello"}]}]'
```

API keys may still be necessary for third-party tools or vendor software that only accept a bearer token and cannot use SigV4 or STS. In those cases, use short-term keys with a maximum 12-hour lifetime and constrain them with the SCPs above.

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
