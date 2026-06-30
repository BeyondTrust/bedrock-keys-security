# Detection Content

Ready-to-use rules for API key abuse and the phantom IAM user attack
chain, covering both Bedrock and Claude Platform on AWS. The files are about
nine distinct signals, each shipped for several stacks (Sigma, EventBridge,
CloudWatch Insights, Athena, CloudTrail Lake); deploy the format your stack
uses.

## Layout

Two surface folders, `bedrock/` and `claude-platform/`, each split by format
(`sigma/`, `athena/`, `cloudtrail-lake/`, `cloudwatch-insights/`, `eventbridge/`).
Load all rules of one format, from both surfaces at once, with a `*`:

```bash
# Sigma → Splunk
sigma-cli convert --target splunk detections/*/sigma/*.yml

# CloudWatch Insights
cat detections/*/cloudwatch-insights/*.txt

# EventBridge patterns
for f in detections/*/eventbridge/*.json; do ... ; done
```

## Bedrock detections (`bedrock/`)

### Sigma (`bedrock/sigma/`)

| File | Severity | Detects |
|---|---|---|
| `api-key-usage.yml` | low | **Primary signal.** Any Bedrock API key request (`additionalEventData.callWithBearerToken = true`). |
| `api-key-creation.yml` | medium | `iam:CreateServiceSpecificCredential` for `bedrock.amazonaws.com` (a new long-term Bedrock key was generated). |
| `phantom-user-creation.yml` | medium | `iam:CreateUser` where `userName` starts with `BedrockAPIKey-` (Console-based provisioning sequence). |
| `phantom-user-access-key-creation.yml` | high | `iam:CreateAccessKey` on a `BedrockAPIKey-*` user; the documented privilege-escalation pivot. |
| `cross-region-api-key-use.yml` | high | Same API key principal calling Bedrock from 2+ regions in 30 min (LLMjacking). |
| `suspicious-user-agent.yml` | low | **Hunting only.** API-key Bedrock calls from non-SDK clients (`python-requests`, `aiohttp`, `curl`). Easy to evade and noisy; allowlist before alerting. |

### CloudTrail Lake (`bedrock/cloudtrail-lake/`)

| File | Detects |
|---|---|
| `llmjacking-invocation-spike.sql` | Per-principal invocation rate >100/5 min on Bedrock (LLMjacking burst). Tune the threshold and allowlist known principals before alerting. |
| `phantom-user-iam-pivot.sql` | `iam:CreateAccessKey` on `BedrockAPIKey-*` phantom users with the actor identity. |

### Athena (`bedrock/athena/`)

| File | Detects |
|---|---|
| `cross-region-api-key-use.sql` | Bedrock API key used in 2+ regions within 1 hour. |
| `spend-anomaly.sql` | Top-N principals by Bedrock `InvokeModel` count over 7 days. |

### EventBridge (`bedrock/eventbridge/`)

| File | Detects |
|---|---|
| `api-key-usage.json` | **Primary signal.** Any Bedrock API call where `additionalEventData.callWithBearerToken = true`. |
| `api-key-creation.json` | `iam:CreateServiceSpecificCredential` with `serviceName=bedrock.amazonaws.com`. Every match is a new long-term Bedrock key. |
| `phantom-user-creation.json` | `iam:CreateUser` with `userName` prefix `BedrockAPIKey-`. |
| `phantom-user-access-key-creation.json` | `iam:CreateAccessKey` with `userName` prefix `BedrockAPIKey-`. The privilege-escalation pivot. |
| `phantom-user-console-login.json` | `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` with `userName` prefix `BedrockAPIKey-`. |

### CloudWatch Logs Insights (`bedrock/cloudwatch-insights/`)

| File | Use |
|---|---|
| `api-key-usage.txt` | Per-principal Bedrock API key usage breakdown. Run against your CloudTrail log group; alarm on result count > 100/hour. |

## Claude Platform detections (`claude-platform/`)

### Sigma (`claude-platform/sigma/`)

| File | Severity | Detects |
|---|---|---|
| `api-key-usage.yml` | low | **Primary signal.** Any aws-external-anthropic call with `requestParameters.callWithBearerToken = true`. |
| `api-key-creation.yml` | medium | `iam:CreateServiceSpecificCredential` for `aws-external-anthropic.amazonaws.com` (a new long-term Claude Platform key was generated, including secondary `+1` keys on an existing phantom). |
| `long-term-api-key-use.yml` | medium | Long-term Claude Platform API key specifically (`bearerTokenType = LONG_TERM`). |
| `phantom-user-creation.yml` | medium | `iam:CreateUser` where `userName` starts with `AeaApiKey-` (Claude Platform console provisioning). |
| `cross-region-api-key-use.yml` | high | Same API key principal calling Claude Platform from 2+ regions in 30 min (LLMjacking). |
| `suspicious-user-agent.yml` | low | **Hunting only.** API-key Claude Platform calls from non-SDK clients (`python-requests`, `aiohttp`, `curl`). Easy to evade and noisy; allowlist before alerting. |

### CloudTrail Lake (`claude-platform/cloudtrail-lake/`)

| File | Detects |
|---|---|
| `llmjacking-invocation-spike.sql` | Per-principal API-key-authenticated rate >100/5 min on Claude Platform (LLMjacking burst). Tune the threshold and allowlist known principals before alerting. |

### Athena (`claude-platform/athena/`)

| File | Detects |
|---|---|
| `cross-region-api-key-use.sql` | Claude Platform API key used in 2+ regions within 1 hour. |
| `api-key-use-by-type.sql` | Claude Platform API key use per principal, broken down by `bearerTokenType` (LONG_TERM vs SHORT_TERM). |
| `spend-anomaly.sql` | Top-N principals by Claude Platform API-key-authenticated call count over 7 days, broken down by `bearerTokenType`. |

### EventBridge (`claude-platform/eventbridge/`)

| File | Detects |
|---|---|
| `api-key-usage.json` | **Primary signal.** Any aws-external-anthropic event with `requestParameters.callWithBearerToken = true`. |
| `api-key-creation.json` | `iam:CreateServiceSpecificCredential` with `serviceName=aws-external-anthropic.amazonaws.com`. Every match is a new long-term Claude Platform key. |
| `phantom-user-creation.json` | `iam:CreateUser` with `userName` prefix `AeaApiKey-`. |

### CloudWatch Logs Insights (`claude-platform/cloudwatch-insights/`)

| File | Use |
|---|---|
| `api-key-usage.txt` | Per-principal Claude Platform API key usage broken down by `bearerTokenType`. |

## Tuning notes

- **Unlike Bedrock, Claude Platform model calls are logged as data events, not management** ([Claude Platform monitoring guide](https://docs.aws.amazon.com/claude-platform/latest/userguide/monitoring.html)), so the rules `cross-region-api-key-use` and `llmjacking-invocation-spike` need a CloudTrail data-event selector for `AWS::AWSExternalAnthropic::Workspace`, or they never fire:

  ```bash
  aws cloudtrail put-event-selectors \
    --trail-name <YOUR_TRAIL_NAME> \
    --advanced-event-selectors '[
      {"Name": "Management events",
       "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
      {"Name": "Claude Platform data events",
       "FieldSelectors": [
         {"Field": "eventCategory", "Equals": ["Data"]},
         {"Field": "resources.type", "Equals": ["AWS::AWSExternalAnthropic::Workspace"]}
       ]}
    ]'
  ```

- **No access-key escalation rule for Claude Platform phantom users:** the [`AnthropicLimitedAccess`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AnthropicLimitedAccess.html) policy on these phantom users is workspace-scoped and grants no IAM, KMS or EC2 reconnaissance, so an IAM access key on one is no escalation, and `bks scan` never marks these `AT RISK`.
