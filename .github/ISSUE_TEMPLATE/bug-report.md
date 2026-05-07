---
name: "🐛 Bug Report"
about: "Report a reproducible defect in BKS"
title: "[BUG] "
labels: ["type: bug", "triage-needed"]
---

## Summary
One-line summary of the bug:

## Affected Component
- [ ] CLI command (`bks scan` / `bks cleanup` / `bks revoke-key` / `bks timeline` / `bks report` / `bks decode-key`)
- [ ] Library import (`from bedrock_keys_security import ...`)
- [ ] Detection content (Sigma / EventBridge / CloudTrail Lake / Athena / CloudWatch Insights)
- [ ] SCP template (`scps/*.json`)
- [ ] IaC module (`scps/terraform/` or `scps/cloudformation/`)
- [ ] Documentation
- [ ] Other:

**Specific file or command**: e.g. `bks scan`, `detections/sigma/bedrock-bearer-token-usage.yml`, `scps/1-block-all-keys.json`

## Steps to Reproduce
Minimal reproducible steps. Include the exact command, query, or deployment:

```bash
# Example
bks scan --profile my-profile --region us-east-1
```

## Current Behavior
What happens. Paste full output or event payload (sanitize account IDs, ARNs and credentials):

```
[paste output here]
```

## Expected Behavior
What should happen instead?

## Environment

**For CLI / library issues**:
- **BKS version**: `bks --version` or `pip show bedrock-keys-security`
- **Install method**: pip / git clone / Docker / other
- **Python version**: `python --version`
- **OS**: macOS / Linux / Windows / WSL
- **AWS region**:
- **AWS authentication**: profile / env vars / IAM role / SSO

**For detection content issues**:
- **SIEM / target platform**: Splunk / Sentinel / Elastic / native AWS / other
- **CloudTrail data event selectors enabled**: yes / no / unsure
- **Bedrock usage scale (approximate)**: API key count, monthly invocation volume

**For SCP / IaC issues**:
- **AWS Organizations status**: enabled / single account
- **Target OU or root**:
- **Terraform / CloudFormation version**:

## Verbose Logs (CLI only, if applicable)
Run with `--verbose` and paste here:

```
[paste verbose log here]
```

## AWS API Behavior (if applicable)
Only if the bug stems from an unexpected AWS response:
- **Service**: IAM / Bedrock / CloudTrail / STS / Organizations
- **Operation**:
- **Error code**:
- **Region-specific**: yes / no / unsure

## Workaround (optional)

```
(describe any temporary fix or workaround, even partial)
```

## Additional Context
Recent AWS changes, IAM policy changes, network restrictions, anything relevant.
