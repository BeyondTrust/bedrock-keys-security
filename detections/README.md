# Detection Content

Drop-in rules for Bedrock API key abuse and the phantom IAM user attack chain. Each file is independently deployable to your SIEM, EventBridge, CloudWatch Insights, CloudTrail Lake or Athena.

## Sigma rules (`sigma/`)

| File | Severity | Detects |
|---|---|---|
| `bedrock-bearer-token-usage.yml` | low | **Primary signal.** Any Bedrock API key request (`callWithBearerToken = true`). Foundation rule; layer higher-confidence rules on top. |
| `bedrock-api-key-creation.yml` | medium | `iam:CreateServiceSpecificCredential` for `bedrock.amazonaws.com` (a new long-term ABSK key was generated). |
| `phantom-user-creation.yml` | medium | `iam:CreateUser` where `userName` starts with `BedrockAPIKey-` (Console-based provisioning sequence). |
| `phantom-user-access-key-creation.yml` | high | `iam:CreateAccessKey` on a `BedrockAPIKey-*` user; the documented privilege-escalation pivot. |
| `bedrock-cross-region-bearer-token-use.yml` | high | Same bearer principal calling Bedrock from 2+ regions in 30 min (LLMjacking fan-out). |
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

Five patterns. `bedrock-api-key-usage.json` targets `aws.bedrock` and catches every Bedrock API call authenticated with a bearer token (the runtime visibility baseline, mirrors the Sigma `bedrock-bearer-token-usage.yml`). The other four target `aws.iam` (us-east-1 since IAM is global) and cover the lifecycle of phantom users and their credentials. CloudTrail must be delivering management events to EventBridge for any of these to fire. Verify with an active multi-region trail.

| File | Severity | Detects |
|---|---|---|
| `bedrock-api-key-usage.json` | low | **Primary signal.** Any Bedrock API call where `additionalEventData.callWithBearerToken = true`. Foundation pattern; layer higher-confidence rules on top. |
| `bedrock-api-key-creation.json` | medium | `iam:CreateServiceSpecificCredential` with `serviceName=bedrock.amazonaws.com`. Every match is a new long-term Bedrock key (and therefore a new phantom user). |
| `phantom-user-creation.json` | medium | `iam:CreateUser` with `userName` prefix `BedrockAPIKey-`. Catches the phantom user provisioning event itself. |
| `phantom-user-access-key-creation.json` | high | `iam:CreateAccessKey` with `userName` prefix `BedrockAPIKey-`. The privilege-escalation pivot: phantom user gains persistent IAM credentials beyond Bedrock. |
| `phantom-user-console-login.json` | high | `iam:CreateLoginProfile` / `iam:UpdateLoginProfile` with `userName` prefix `BedrockAPIKey-`. There is no legitimate workflow that gives a phantom user console access; treat any hit as compromise. |

## CloudWatch Logs Insights (`cloudwatch-insights/`)

| File | Use |
|---|---|
| `bearer-token-usage.txt` | Per-principal usage breakdown query. Run against your CloudTrail log group; alarm on result count > 100/hour. |

## Coverage matrix

| Attack stage | Rule(s) |
|---|---|
| Initial creation (long-term key) | `bedrock-api-key-creation.yml`, `phantom-user-creation.yml`, EventBridge `bedrock-api-key-creation.json` + `phantom-user-creation.json` |
| Any API key usage (visibility baseline) | `bedrock-bearer-token-usage.yml`, `bearer-token-usage.txt`, EventBridge `bedrock-api-key-usage.json` |
| Persistence pivot (phantom user → AKIA / console) | `phantom-user-access-key-creation.yml`, `phantom-user-iam-pivot.sql`, EventBridge `phantom-user-access-key-creation.json` + `phantom-user-console-login.json` |
| LLMjacking detection | `bedrock-cross-region-bearer-token-use.yml`, `bedrock-suspicious-user-agent.yml`, `llmjacking-invocation-spike.sql`, `bedrock-bearer-token-cross-region.sql` |
| Spend / capacity abuse | `bedrock-spend-anomaly.sql` |

## Tuning notes

- **Bedrock data events are NOT logged by default.** Management events (`CreateServiceSpecificCredential`, `CreateUser`, `CreateAccessKey`, etc.) ship to every trail automatically. Data-plane events (`InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream`, `Retrieve`, `RetrieveAndGenerate`) require an explicit data-event selector. Without it, the LLMjacking spike, suspicious user-agent, cross-region bearer, and spend-anomaly rules silently match nothing.

  Verify your current selectors first to avoid wiping management coverage:

  ```bash
  aws cloudtrail get-event-selectors --trail-name <YOUR_TRAIL_NAME>
  ```

  Then add a Bedrock data-event selector alongside the existing management one:

  ```bash
  aws cloudtrail put-event-selectors \
    --trail-name <YOUR_TRAIL_NAME> \
    --advanced-event-selectors '[
      {"Name": "Management events",
       "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]},
      {"Name": "Bedrock data events",
       "FieldSelectors": [
         {"Field": "eventCategory", "Equals": ["Data"]},
         {"Field": "resources.type", "Equals": ["AWS::Bedrock::Model"]}
       ]}
    ]'
  ```

  Cost: $0.10 per 100k data events (per CloudTrail pricing). For LLMjacking visibility, non-optional. See [Bedrock CloudTrail logging](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html) and [CloudTrail data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html#logging-data-events).

- Thresholds (rate, region count, time window) are conservative defaults. Tune per environment volume.
- `BedrockAPIKey-*` phantom users only exist for AWS Console-created long-term keys. STS-derived short-term bearer tokens do not create phantom users; aggregate by `userIdentity.principalId` to catch them.
- Build the visibility baseline from `bedrock-bearer-token-usage.yml` first (it fires on every API key request), then layer the higher-confidence rules on top.
