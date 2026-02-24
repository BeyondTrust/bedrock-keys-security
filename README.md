# Bedrock API Keys Security

Tools and research for securing AWS Bedrock API keys and the phantom IAM users they create.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

## tl;dr

AWS Bedrock API keys (launched July 2025) introduce multiple security risks: overprivileged default policies, bearer token auth, and keys already leaking to GitHub within 14 days of launch. Long-term keys additionally create phantom IAM users (`BedrockAPIKey-xxxx`) with admin permissions that persist indefinitely. Criminal orgs make $1M/year from stolen keys, with fraudulent charges up to $14K/day per region. This repo covers detection, preventive SCPs, incident response, and key decoding for all Bedrock API key types.

## What's Here

**One CLI tool:**
- `bedrock-keys` - Find phantom users, decode leaked keys, clean up orphans

**Four SCPs to lock this down:**
1. Block all API keys (just don't use them)
2. Enforce 90-day max lifetime (if you must use them)
3. Block long-term keys only (short-term are slightly less bad)
4. Block IAM access key escalation on phantoms (prevents the really bad stuff)

**Documentation:**
- Attack paths and exploitation techniques
- What "AmazonBedrockLimitedAccess" actually gives you (spoiler: it's not limited)

## The Problem

Here's what happens when you click "Create API Key" in the Bedrock console:

1. AWS silently creates an IAM user named `BedrockAPIKey-xxxx`
2. That user gets the `AmazonBedrockLimitedAccess` policy (it's `bedrock:*` plus recon)
3. **The phantom user never gets deleted** - not when the key expires, not when you delete it
4. Attackers can create IAM access keys on these phantoms for privilege escalation
5. Leaked keys are worth ~$1M/year to criminal groups running LLMjacking operations

## What Attackers Do With These

### That "Limited" Policy Isn't

`AmazonBedrockLimitedAccess` sounds safe. It's not:

- `bedrock:*` on all resources (full admin)
- `iam:ListRoles` (enumerate your identities)
- `kms:DescribeKey` (find your encryption keys)
- `ec2:Describe*` (map your network)

### Two Attack Paths I See

![Attack Paths Diagram](docs/images/attack-paths.jpeg)

**1. LLMjacking (up to $14K/day per region)**

![LLMjacking Attack Flow](docs/images/llm-jacking.jpeg)

Attacker finds your key on GitHub, spins up workers across all AWS regions, hammers Claude Opus 24/7, sells the outputs. Your bill goes parabolic.

**2. Privilege Escalation (the scarier one)**

Attacker uses the Bedrock key to call `CreateAccessKey` on the phantom user. Now they have persistent AKIA credentials. From there they can pivot to S3, Secrets Manager, whatever else you've got. The original Bedrock key can expire - they don't care, they've already escalated.

## Quick Start

### Get It Running

```bash
git clone https://github.com/BeyondTrust/bedrock-keys-security.git
cd bedrock-keys-security
pip install -r requirements.txt
```

You need Python 3.9+ and AWS credentials with IAM read permissions (`iam:ListUsers`, `iam:ListServiceSpecificCredentials`, `iam:ListAccessKeys`).

### Scan Your Account

```bash
./bedrock-keys
```

Finds:
- Phantom users with active API keys
- Orphaned phantoms (safe to delete)
- **Escalated phantoms** - ones with IAM access keys (you have a problem)

## The Tool

### bedrock-keys

Find phantoms, decode leaked keys, clean up orphans.

```bash
./bedrock-keys                      # scan your account
./bedrock-keys --profile prod       # different AWS profile
./bedrock-keys --json               # machine-readable
./bedrock-keys --csv output.csv     # spreadsheet it
./bedrock-keys --cleanup --dry-run  # see what would get deleted
./bedrock-keys --cleanup            # actually delete orphans
./bedrock-keys --verbose            # all the details
```

What it does:
- Lists all `BedrockAPIKey-*` IAM users
- Checks which ones have active credentials
- **Flags escalated users** (ones with IAM access keys - this is bad)
- Can auto-delete the orphans
- Export for tracking/reporting

Example output:

![Scan Example](docs/images/scan-example.png)

### Incident Response

Emergency response when keys are compromised.

```bash
./bedrock-keys --revoke-key BedrockAPIKey-xxxx              # Emergency key revocation
./bedrock-keys --timeline BedrockAPIKey-xxxx                # CloudTrail timeline (last 7 days)
./bedrock-keys --timeline BedrockAPIKey-xxxx --days 30      # Timeline for last 30 days
./bedrock-keys --report BedrockAPIKey-xxxx                  # Generate incident report
./bedrock-keys --report BedrockAPIKey-xxxx --output report.txt  # Save report to file
```

![Revoke Key](docs/images/revoke-key.png)

### Key Decoding

Decode leaked keys offline (no AWS creds needed).

```bash
./bedrock-keys --decode-key "ABSKQmVkcm9ja0FQSUtleS..."
./bedrock-keys --decode-key "bedrock-api-key-YmVkcm9ja..." --json
```

Useful when you find these keys in GitHub/Pastebin/wherever and need to know whose account is compromised.

![Long-term Key Decode](docs/images/long-term-key.png)

![Short-term Key Decode](docs/images/short-term-key.png)

## Better Alternative: Don't Use API Keys

Real talk: 95% of teams don't need Bedrock API keys. Use AWS STS temporary credentials instead.

**Why STS is better:**
- Auto-expires (1-12 hours)
- No phantom users created
- Standard AWS SigV4 signing (not bearer tokens)
- No persistent credentials to leak
- AWS best practice

**Quick example:**

```bash
# Get temporary creds (expires in 1 hour)
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT:role/BedrockRole \
  --role-session-name bedrock-session \
  --duration-seconds 3600

# Use them normally
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

aws bedrock invoke-model --model-id anthropic.claude-3-sonnet...
```

**When you actually need API keys:**
- Legacy apps hardcoded for bearer tokens
- Third-party tools that can't do SigV4 signing
- Vendor software without STS support

If none of these apply, use STS. If they do apply, use short-term keys (12-hour max) and lock down with the SCPs below.

## Prevention (SCPs)

Four policies to lock this down at the org level:

### 1. Block All API Keys (recommended)

If you're not using Bedrock API keys, just block them:

```bash
aws organizations create-policy \
  --name Block-Bedrock-API-Keys \
  --type SERVICE_CONTROL_POLICY \
  --content file://scps/1-block-all-keys.json
```

Blocks creation and usage. Done.

### 2. Enforce 90-Day Max

If you need API keys, at least limit the damage window:

```bash
aws organizations create-policy \
  --content file://scps/2-enforce-90day-max.json \
  --type SERVICE_CONTROL_POLICY
```

No key lives longer than 90 days.

### 3. Short-Term Only

Block the long-term (ABSK) keys, allow short-term:

```bash
aws organizations create-policy \
  --content file://scps/3-block-long-term-only.json \
  --type SERVICE_CONTROL_POLICY
```

### 4. Block Phantom Escalation

Stop attackers from creating IAM access keys on the phantoms:

```bash
aws organizations create-policy \
  --content file://scps/4-block-phantom-access-keys.json \
  --type SERVICE_CONTROL_POLICY
```

This one's important - it blocks the privilege escalation path.

## The Research

**What I found:**
- Phantom IAM users never get cleaned up
- "AmazonBedrockLimitedAccess" is basically `bedrock:*` plus recon permissions
- Keys leak to GitHub within ~2 weeks of creation (median)
- Criminal groups make $1M+/year running LLMjacking operations with leaked keys
- AWS doesn't detect when phantom users get abused

<!-- **Where to read more:**
- Blog: [BeyondTrust - AWS Bedrock API Keys Security Research](https://beyondtrust.com/blog/bedrock-api-keys-security) -->

## Contributing

PRs welcome. Useful additions:
- IaC templates (Terraform/CloudFormation)
- More attack scenarios
- GovCloud support

Standard GitHub flow: fork, branch, commit, PR.

## Testing

Test SCPs on non-prod OUs first. Run bedrock-keys read-only before cleanup.

## License

Apache 2.0 - see [LICENSE](LICENSE).


## Contact

- Issues/bugs: [GitHub Issues](https://github.com/BeyondTrust/bedrock-keys-security/issues)
- Questions: [GitHub Discussions](https://github.com/BeyondTrust/bedrock-keys-security/discussions)
- Twitter: [@btphantomlabs](https://x.com/btphantomlabs)

## References

- [AWS Bedrock API Keys User Guide](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys.html)
- [AWS Security Blog: Securing Bedrock API Keys](https://aws.amazon.com/blogs/security/securing-amazon-bedrock-api-keys-best-practices-for-implementation-and-management/)
- [AWS SCP Examples for Bedrock](https://github.com/aws-samples/service-control-policy-examples/tree/main/Service-specific-controls/Amazon-Bedrock)
- [CloudTrail Logging for Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)

---

If you find phantoms in your account, star this and share it with your team.
