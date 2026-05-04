# Bedrock API Keys Security

**Find and contain phantom IAM users from Bedrock keys.**

Security toolkit for AWS Bedrock API keys: phantom user discovery, offline key decoder, incident response, automated cleanup, and preventive SCPs.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/bedrock-keys-security.svg)](https://pypi.org/project/bedrock-keys-security/)
[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/MrCloudSec.svg?style=social&label=Follow%20the%20author)](https://twitter.com/MrCloudSec)

**Contents**: [Quickstart](#quickstart) · [Motivation](#motivation) · [Installation](#installation) · [Usage](#usage) · [Prevention](#prevention-with-service-control-policies) · [Detection](#detection-content) · [Migration to STS](#migration-to-sts) · [Talks](#talks) · [Contributing](#contributing)

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

When a user creates a long-term Bedrock API key through the AWS Console, AWS silently provisions an IAM user named `BedrockAPIKey-xxxx` and attaches the [`AmazonBedrockLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonBedrockLimitedAccess.html) managed policy.

Despite its name, the policy is effectively administrative: 47 `bedrock:*` actions covering create / read / update / delete across all Bedrock resources, plus cross-service reconnaissance (`iam:ListRoles`, `kms:DescribeKey`, `ec2:Describe{Vpcs,Subnets,SecurityGroups}`). Full action list in the AWS doc linked above.

These phantom users are never automatically cleaned up. They accumulate over time, creating an expanding attack surface that most organizations don't know exists.

### Attack Paths

![Attack Paths Diagram](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/attack-paths.jpeg)

**LLMjacking:** An attacker who obtains a leaked key can spin up workers across all AWS regions to consume foundation model capacity. The default Bedrock service quota and Claude Opus 4.7 pricing put the worst-case exposure at up to $18,000/day per region.

![LLMjacking Attack Flow](https://raw.githubusercontent.com/BeyondTrust/bedrock-keys-security/main/docs/images/llm-jacking.jpeg)

**Privilege Escalation:** If an attacker creates an IAM access key on the phantom user, or if one already exists, they gain persistent IAM credentials (`AKIA...`) that extend well beyond Bedrock. From there, they can pivot to S3, Secrets Manager, and other services, even after the original Bedrock key expires.

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

`timeline --all-regions` is recommended whenever LLMjacking is suspected. Bedrock data-plane events (`InvokeModel`, `Converse`, `CallWithBearerToken`) are recorded in the region they ran, not the home region; a single-region timeline misses cross-region fan-out by design.

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

- **Terraform**: [`iac/terraform/`](iac/terraform/) wraps the four SCPs as `aws_organizations_policy` resources with optional OU attachment.
- **CloudFormation**: [`iac/cloudformation/scps.yaml`](iac/cloudformation/scps.yaml) is a single template with conditional resources, StackSet-friendly.

Both default to enabling `Block-Bedrock-API-Keys` plus `Block-Phantom-User-Escalation`, the recommended baseline pair.

## Detection Content

SOC-grade detection rules for the full attack chain are in [`detections/`](detections/): 6 Sigma rules, 2 CloudTrail Lake queries, 2 Athena queries, 5 EventBridge patterns, and 1 CloudWatch Insights query. Coverage spans bearer-token usage, key creation, phantom-user creation, AKIA escalation, cross-region fan-out, and suspicious user-agents.

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

aws bedrock invoke-model --model-id anthropic.claude-opus-4-7...
```

API keys may still be necessary for legacy applications hardcoded for bearer tokens, third-party tools without SigV4 support, or vendor software lacking STS integration. In those cases, use short-term keys with a maximum 12-hour lifetime and enforce restrictions with the SCPs above.

**Further reading:** [BeyondTrust: AWS Bedrock API Keys Security Guide, Part 1](https://www.beyondtrust.com/blog/entry/aws-bedrock-security-api-keys).

## Talks

- **BSides Seattle 2026**: *The Phantom of the Infrastructure: Investigating the Hidden IAM Risks in Bedrock API Keys* ([slides](docs/bsides-seattle-2026.pdf), [video](https://www.youtube.com/watch?v=v3wvjb9Gu-c))
- **RootedCON Madrid 2026**: *The Phantom of the Infrastructure: The Invisible Threat in Bedrock API Keys*

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, PR workflow, and review requirements.

## License

Apache 2.0. See [LICENSE](LICENSE).

## Contact

- Issues and bugs: [GitHub Issues](https://github.com/BeyondTrust/bedrock-keys-security/issues)
- Twitter: [@btphantomlabs](https://x.com/btphantomlabs)

## References

- [AWS Bedrock API Keys User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
- [AWS Security Blog: Securing Bedrock API Keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/)
- [AWS SCP Examples for Bedrock](https://github.com/aws-samples/service-control-policy-examples/tree/main/Service-specific-controls/Amazon-Bedrock)
- [AWS Customer Playbook Framework: Bedrock EventBridge CFN](https://github.com/aws-samples/aws-customer-playbook-framework/tree/main/detections/cfn)
- [CloudTrail Logging for Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)
