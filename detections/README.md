# Detection Content

Detection rules for Bedrock API key abuse and the phantom IAM user attack chain.

| File | Format | Detects |
|---|---|---|
| `sigma/bedrock-api-key-creation.yml` | Sigma | Creation of a Bedrock service-specific credential (long-term ABSK key). Use as baseline visibility. |
| `sigma/phantom-user-access-key-creation.yml` | Sigma | Creation of an IAM access key (`AKIA*`) on a `BedrockAPIKey-*` user — the privilege escalation pivot. |
| `sigma/bedrock-cross-region-bearer-token-use.yml` | Sigma | Same `BedrockAPIKey-*` principal calling Bedrock from multiple regions within a short window — typical LLMjacking pattern. |
| `cloudtrail-lake/llmjacking-invocation-spike.sql` | CloudTrail Lake | High invocation rate (>100 calls / 5 min) from a single Bedrock bearer principal. |
| `cloudtrail-lake/phantom-user-iam-pivot.sql` | CloudTrail Lake | IAM access key created on a phantom user, with the actor identity. |
| `athena/bedrock-bearer-token-cross-region.sql` | Athena | Bearer token used in 2+ regions within 1 hour, suggesting fan-out. |
| `athena/bedrock-spend-anomaly.sql` | Athena | Top-N principals by InvokeModel count over a window — surfaces runaway keys. |

## Coverage matrix

| Attack stage | Rule |
|---|---|
| Initial creation (long-term key) | `bedrock-api-key-creation.yml` |
| Persistence pivot (phantom user → AKIA) | `phantom-user-access-key-creation.yml`, `phantom-user-iam-pivot.sql` |
| LLMjacking detection | `bedrock-cross-region-bearer-token-use.yml`, `llmjacking-invocation-spike.sql`, `bedrock-bearer-token-cross-region.sql` |
| Spend / capacity abuse | `bedrock-spend-anomaly.sql` |

## Tuning notes

- All rules assume CloudTrail management events are flowing. For Bedrock data-plane visibility (`InvokeModel`), enable Bedrock CloudTrail data events at the trail level.
- Threshold values (rate, region count, time window) are conservative defaults. Tune per environment volume.
- The phantom user pattern `BedrockAPIKey-*` is exact for AWS Console-created long-term keys. STS-derived short-term bearer tokens do not create phantom users.
