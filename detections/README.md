# Detection Content

Detection rules and copy-paste deployment templates for Bedrock API key abuse and the phantom IAM user attack chain. Each file is independently usable: drop into your SIEM / EventBridge / CloudWatch Insights / CloudTrail Lake / Athena directly.

The primary CloudTrail detection signal for any Bedrock API key request is the field `additionalEventData.callWithBearerToken = true` — present for both long-term and short-term keys, absent from standard SigV4 requests.

## Sigma rules (`sigma/`)

| File | Severity | Detects |
|---|---|---|
| `bedrock-bearer-token-usage.yml` | low | **Primary signal.** Any Bedrock API key request (`callWithBearerToken = true`). Foundation rule — layer higher-confidence rules on top. |
| `bedrock-api-key-creation.yml` | medium | `iam:CreateServiceSpecificCredential` for `bedrock.amazonaws.com` (a new long-term ABSK key was generated). |
| `phantom-user-creation.yml` | medium | `iam:CreateUser` where `userName` starts with `BedrockAPIKey-` (Console-based provisioning sequence). |
| `phantom-user-access-key-creation.yml` | high | `iam:CreateAccessKey` on a `BedrockAPIKey-*` user — the documented privilege-escalation pivot. |
| `bedrock-cross-region-bearer-token-use.yml` | high | Same bearer principal calling Bedrock from 2+ regions in 30 min — LLMjacking fan-out. |
| `bedrock-suspicious-user-agent.yml` | high | Bearer-token Bedrock calls with non-SDK clients (`python-requests`, `aiohttp`, `curl`). |

## CloudTrail Lake (`cloudtrail-lake/`)

| File | Detects |
|---|---|
| `llmjacking-invocation-spike.sql` | Per-principal invocation rate >100/5 min (LLMjacking burst). |
| `phantom-user-iam-pivot.sql` | `iam:CreateAccessKey` on phantom users with the actor identity. |

## Athena (`athena/`)

| File | Detects |
|---|---|
| `bedrock-bearer-token-cross-region.sql` | Bearer token used in 2+ regions within 1 hour. |
| `bedrock-spend-anomaly.sql` | Top-N principals by InvokeModel count over 7 days. |

## EventBridge (`eventbridge/`)

| File | Use |
|---|---|
| `bedrock-api-key-usage.json` | Drop-in EventBridge rule pattern for every Bedrock API key request. Route to SNS / Lambda / SIEM via API destinations. Minimum-viable detection if no SIEM is in place yet. |

## CloudWatch Logs Insights (`cloudwatch-insights/`)

| File | Use |
|---|---|
| `bearer-token-usage.txt` | Per-principal usage breakdown query. Run against your CloudTrail log group; alarm on result count > 100/hour. |

## Coverage matrix

| Attack stage | Rule(s) |
|---|---|
| Initial creation (long-term key) | `bedrock-api-key-creation.yml`, `phantom-user-creation.yml` |
| Any API key usage (visibility baseline) | `bedrock-bearer-token-usage.yml`, `bedrock-api-key-usage.json`, `bearer-token-usage.txt` |
| Persistence pivot (phantom user → AKIA) | `phantom-user-access-key-creation.yml`, `phantom-user-iam-pivot.sql` |
| LLMjacking detection | `bedrock-cross-region-bearer-token-use.yml`, `bedrock-suspicious-user-agent.yml`, `llmjacking-invocation-spike.sql`, `bedrock-bearer-token-cross-region.sql` |
| Spend / capacity abuse | `bedrock-spend-anomaly.sql` |

## Tuning notes

- All rules assume CloudTrail management events are flowing. For Bedrock data-plane visibility (`InvokeModel`), enable Bedrock CloudTrail data events at the trail level.
- Threshold values (rate, region count, time window) are conservative defaults. Tune per environment volume.
- The phantom user pattern `BedrockAPIKey-*` is exact for AWS Console-created long-term keys. STS-derived short-term bearer tokens do not create phantom users.
- The `callWithBearerToken` field is the most reliable signal: it appears on every key type and is absent from SigV4 requests. Build your visibility baseline from this rule first, then layer the higher-confidence detections on top.
