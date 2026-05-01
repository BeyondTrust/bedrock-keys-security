# Bedrock API Keys Security

Security toolkit for AWS Bedrock API keys. Discover phantom IAM users, decode leaked keys, automate cleanup, and enforce preventive controls.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/bedrock-keys-security.svg)](https://pypi.org/project/bedrock-keys-security/)
[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/MrCloudSec.svg?style=social&label=Follow%20the%20author)](https://twitter.com/MrCloudSec)

## Quickstart

```bash
pip install bedrock-keys-security
bks scan --profile your-aws-profile
```

That's it. The scanner discovers every `BedrockAPIKey-*` phantom user in the account, categorizes risk (`ACTIVE` / `ORPHANED` / `AT RISK`), and prints a summary table.

```bash
# Decode a leaked key offline (no AWS credentials needed)
bks decode-key "ABSKQmVkcm9ja..."

# Investigate a phantom user across every region with CloudTrail coverage
bks timeline BedrockAPIKey-xxxx --all-regions --days 30

# Emergency revocation: deny Bedrock + delete API keys + disable AKIA pivots
bks revoke-key BedrockAPIKey-xxxx
```

Detection content (Sigma, CloudTrail Lake, Athena, EventBridge, CloudWatch Insights) lives in [`detections/`](detections/). Terraform and CloudFormation for the SCPs live in [`iac/`](iac/).

## Motivation

When a user creates a long-term Bedrock API key through the AWS Console, AWS silently provisions an IAM user named `BedrockAPIKey-xxxx` and attaches the [`AmazonBedrockLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html) managed policy. Despite its name, this policy grants broad permissions:

- 47 `bedrock:*` actions covering full Bedrock administration: `Get*`, `List*`, `CallWithBearerToken`, plus explicit `Create*`/`Delete*`/`Update*`/`Stop*` on guardrails, custom models, provisioned throughput, evaluation jobs, inference profiles, prompt routers, and automated reasoning policies.
- `iam:ListRoles` (identity enumeration)
- `kms:DescribeKey` (encryption key discovery)
- `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups` (network and firewall reconnaissance)

The policy v8 also lists 4 `bedrock-mantle:*` actions and 3 `aws-marketplace:*` actions. The marketplace actions are scoped to internal Bedrock service flows and cannot be invoked directly with a leaked API key.

These phantom users are never automatically cleaned up. They accumulate over time, creating an expanding attack surface that most organizations don't know exists.

### Attack Paths

![Attack Paths Diagram](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/attack-paths.jpeg)

**LLMjacking:** An attacker who obtains a leaked key can spin up workers across all AWS regions to consume foundation model capacity. The default Bedrock service quota and Claude Opus 4.7 pricing put the worst-case exposure at up to $18,000/day per region.

![LLMjacking Attack Flow](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/llm-jacking.jpeg)

**Privilege Escalation:** If an attacker creates an IAM access key on the phantom user, or if one already exists, they gain persistent IAM credentials (`AKIA...`) that extend well beyond Bedrock. From there, they can pivot to S3, Secrets Manager, and other services, even after the original Bedrock key expires.

## What This Toolkit Provides

Bedrock API keys [launched in July 2025](https://aws.amazon.com/blogs/machine-learning/accelerate-ai-development-with-amazon-bedrock-api-keys/). Within 14 days, keys were already leaking on public GitHub. This toolkit provides:

- **Discovery:** Scan your account for phantom IAM users and categorize their risk
- **Incident Response:** Emergency key revocation, CloudTrail timelines, and forensic reports
- **Key Decoding:** Offline analysis of leaked keys to extract account and identity information
- **Prevention:** Service Control Policies to block or restrict API key usage at the org level

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

After installation, the `bks` command is available globally. Requires Python 3.10+ and AWS credentials. Minimum IAM permissions by command:

| Command | IAM Permissions Required |
|---|---|
| `scan` | `iam:ListUsers`, `iam:ListServiceSpecificCredentials`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies` |
| `cleanup` | All scan permissions + `iam:DeleteAccessKey`, `iam:DeleteServiceSpecificCredential`, `iam:DetachUserPolicy`, `iam:DeleteUserPolicy`, `iam:DeleteUser` |
| `revoke-key` | `iam:PutUserPolicy`, `iam:ListServiceSpecificCredentials`, `iam:DeleteServiceSpecificCredential`, `iam:ListAccessKeys`, `iam:UpdateAccessKey` |
| `timeline` | `cloudtrail:LookupEvents` (+ `cloudtrail:DescribeTrails` and `ec2:DescribeRegions` when using `--all-regions`) |
| `report` | `iam:GetUser`, `iam:ListServiceSpecificCredentials`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies` |
| `decode-key` | None (offline) |

All commands except `decode-key` also call `sts:GetCallerIdentity` to confirm the active session.

## Usage

### Scanning

Run a scan to discover all phantom IAM users in your account:

```bash
bks scan                      # scan with default profile
bks scan --profile prod       # use a specific AWS profile
bks scan --json               # machine-readable output
bks scan --csv output.csv     # export to CSV
bks scan --verbose            # detailed output
```

Each phantom user is categorized by risk level:
- **ACTIVE:** Has valid Bedrock API credentials
- **ORPHANED:** No active credentials remaining (safe to delete)
- **AT RISK:** Has IAM access keys that grant `bedrock:*`, recon permissions, and persist independently of the API key

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/scan-example.png" alt="Scan Example" width="600">

### Cleanup

Remove orphaned phantom users that no longer have active credentials:

```bash
bks cleanup --dry-run         # preview what would be deleted
bks cleanup                   # delete with confirmation prompt
bks cleanup --force           # skip confirmation (use with caution)
```

Only ORPHANED users are affected. ACTIVE and AT RISK users are never deleted automatically.

### Incident Response

When a key is compromised, `bks` provides emergency response capabilities:

```bash
bks revoke-key BedrockAPIKey-xxxx                 # emergency key revocation
bks revoke-key BedrockAPIKey-xxxx --force         # skip confirmation
bks timeline BedrockAPIKey-xxxx                   # CloudTrail timeline (last 7 days, configured region)
bks timeline BedrockAPIKey-xxxx --days 30         # extended timeline
bks timeline BedrockAPIKey-xxxx --all-regions     # fan out across every region with CloudTrail coverage
bks report BedrockAPIKey-xxxx                     # full incident report
bks report BedrockAPIKey-xxxx --output report.txt
```

`revoke-key` applies an inline `Deny: bedrock:*` policy, deletes all Bedrock service-specific credentials, and disables IAM access keys (`AKIA*`) on the phantom user, closing the privilege-escalation pivot in the same operation.

`timeline --all-regions` is recommended whenever LLMjacking is suspected. It runs `cloudtrail:DescribeTrails` to map coverage, enumerates enabled regions via `ec2:DescribeRegions`, and fans the lookup out across every region with an active trail. Bedrock data-plane events (`InvokeModel`, `Converse`, `CallWithBearerToken`) are recorded in the region where Bedrock was called, so a single-region timeline misses cross-region fan-out by design.

<img src="https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/revoke-key.png" alt="Revoke Key" width="600">

### Key Decoding

Decode leaked Bedrock API keys offline, no AWS credentials required:

```bash
bks decode-key "ABSKQmVkcm9ja0FQSUtleS..."
bks decode-key "bedrock-api-key-YmVkcm9ja..." --json
```

Extracts the embedded IAM username, AWS account ID, region, and key format. Useful for triaging keys found on GitHub, Pastebin, or other public sources.

![Long-term Key Decode](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/long-term-key.png)

![Short-term Key Decode](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/short-term-key.png)

## Prevention with Service Control Policies

Four SCPs are provided for organizational enforcement. Apply them to OUs via AWS Organizations.

### 1. Block All API Keys (Recommended)

The simplest approach: block creation and usage of all Bedrock API keys:

```bash
aws organizations create-policy \
  --name Block-Bedrock-API-Keys \
  --type SERVICE_CONTROL_POLICY \
  --content file://scps/1-block-all-keys.json
```

### 2. Enforce 90-Day Maximum Lifetime

If API keys are required, limit the damage window:

```bash
aws organizations create-policy \
  --content file://scps/2-enforce-90day-max.json \
  --type SERVICE_CONTROL_POLICY
```

### 3. Block Long-Term Keys Only

Allow short-term keys while blocking the more dangerous long-term (ABSK) keys:

```bash
aws organizations create-policy \
  --content file://scps/3-block-long-term-only.json \
  --type SERVICE_CONTROL_POLICY
```

### 4. Block Phantom Escalation

Prevent IAM access key creation on phantom users. This blocks the privilege escalation path:

```bash
aws organizations create-policy \
  --content file://scps/4-block-phantom-access-keys.json \
  --type SERVICE_CONTROL_POLICY
```

> **Note:** Always test SCPs on non-production OUs before applying broadly.

### Infrastructure as Code

The same four SCPs are available as ready-to-deploy modules:

- **Terraform**: [`iac/terraform/`](iac/terraform/) wraps the four SCPs as `aws_organizations_policy` resources with optional OU attachment. Reads policy bodies from `scps/*.json` so the module and the JSON cannot drift.
- **CloudFormation**: [`iac/cloudformation/scps.yaml`](iac/cloudformation/scps.yaml) is a single template with conditional resources, StackSet-friendly.

Both default to enabling `Block-Bedrock-API-Keys` plus `Block-Phantom-User-Escalation`, the recommended baseline pair.

## Detection Content

SOC-grade detection rules for the full attack chain are in [`detections/`](detections/):

| Format | Coverage |
|---|---|
| Sigma (6 rules) | Bearer token usage baseline, long-term key creation, phantom-user creation, phantom-user AKIA escalation, cross-region bearer token fan-out, suspicious user-agent invocation |
| CloudTrail Lake (2 queries) | Per-principal invocation rate spikes, IAM pivot detection |
| Athena (2 queries) | Cross-region bearer token reuse, top-N principals by InvokeModel count |
| EventBridge (4 patterns) | Real-time alerts on Bedrock key creation, phantom user creation, AKIA escalation, and console-login pivot |
| CloudWatch Insights (1 query) | Per-principal usage breakdown for native AWS monitoring |

## Recommended Alternative: STS Temporary Credentials

Most teams do not need Bedrock API keys. AWS STS temporary credentials are the recommended approach:

- Automatically expire (1–12 hours)
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

aws bedrock invoke-model --model-id anthropic.claude-opus-4-7...
```

API keys may still be necessary for legacy applications hardcoded for bearer tokens, third-party tools without SigV4 support, or vendor software lacking STS integration. In those cases, use short-term keys with a maximum 12-hour lifetime and enforce restrictions with the SCPs above.

## Research Findings

- Phantom IAM users are never automatically cleaned up by AWS
- `AmazonBedrockLimitedAccess` grants `bedrock:*` plus reconnaissance permissions
- Keys leaked to GitHub within approximately 2 weeks of creation (median)
- Criminal groups generate $1M+/year through LLMjacking operations with leaked keys

<!-- **Further Reading:**
- Blog: [BeyondTrust - AWS Bedrock API Keys Security Research](https://beyondtrust.com/blog/bedrock-api-keys-security) -->

## Talks

- **BSides Seattle 2026**: *The Phantom of the Infrastructure: Investigating the Hidden IAM Risks in Bedrock API Keys* ([slides](docs/bsides-seattle-2026.pdf), [video](https://www.youtube.com/watch?v=v3wvjb9Gu-c))
- **RootedCON Madrid 2026**: *The Phantom of the Infrastructure: The Invisible Threat in Bedrock API Keys*

## Contributing

Contributions are welcome. Useful additions include IaC templates (Terraform/CloudFormation), additional attack scenarios, and GovCloud support.

Standard GitHub workflow: fork, branch, commit, pull request.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contact

- Issues and bugs: [GitHub Issues](https://github.com/BeyondTrust/bedrock-keys-security/issues)
- Twitter: [@btphantomlabs](https://x.com/btphantomlabs)

## References

- [AWS Bedrock API Keys User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
- [AWS Security Blog: Securing Bedrock API Keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/)
- [AWS SCP Examples for Bedrock](https://github.com/aws-samples/service-control-policy-examples/tree/main/Service-specific-controls/Amazon-Bedrock)
- [CloudTrail Logging for Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)
