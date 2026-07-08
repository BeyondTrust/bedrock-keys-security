# Bedrock API Key Service Control Policies

Preventive controls for the `bedrock.amazonaws.com` service-specific
credential surface and the `BedrockAPIKey-*` phantom user pattern. Bearer-token
denies cover both Bedrock inference planes, `bedrock` and `bedrock-mantle`.

Apply at the AWS Organizations OU level or attach individually to test
accounts.

## Policies

| File | What it does | When to use |
|------|--------------|-------------|
| `1-block-all-keys.json` | Deny `iam:CreateServiceSpecificCredential` for `bedrock.amazonaws.com` and deny `bedrock:CallWithBearerToken` + `bedrock-mantle:CallWithBearerToken` org-wide | Full lockout of Bedrock API keys in accounts that should never use them |
| `2-block-phantom-user-creation.json` | Deny `iam:CreateUser` matching `BedrockAPIKey-*` and deny attaching `AmazonBedrockLimitedAccess` to any principal | Prevent the auto-provisioned phantom user from being created and stop the managed policy from being attached to arbitrary identities |
| `3-block-long-term-only.json` | Deny `bedrock:CallWithBearerToken` and `bedrock-mantle:CallWithBearerToken` when `bearerTokenType = LONG_TERM` | Allow short-term API key use while killing static ABSK keys |
| `4-block-phantom-access-keys.json` | Deny `iam:CreateAccessKey`, `iam:CreateLoginProfile`, MFA actions on `BedrockAPIKey-*` users | Prevent escalation of phantom users into general-purpose IAM users |
| `5-enforce-90day-max.json` | Deny `iam:CreateServiceSpecificCredential` for `bedrock.amazonaws.com` when `iam:ServiceSpecificCredentialAgeDays` > 90 | Cap the API key lifetime to 90 days |
