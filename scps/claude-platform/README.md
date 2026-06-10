# Claude Platform on AWS Service Control Policies

Preventive controls for the Claude Platform on AWS surface
(`aws-external-anthropic.amazonaws.com`).

Apply at the AWS Organizations OU level or attach individually to test
accounts.

## Policies

| File | What it does | When to use |
|------|--------------|-------------|
| `1-block-all-keys.json` | Deny `iam:CreateServiceSpecificCredential` for `aws-external-anthropic.amazonaws.com`, deny `aws-external-anthropic:CallWithBearerToken`, deny `iam:CreateUser` for `AeaApiKey-*` and deny `sts:GetWebIdentityToken` to Anthropic audiences | Full lockout of the platform in accounts that should never use it |
| `2-block-phantom-user-creation.json` | Deny `iam:CreateUser` matching `AeaApiKey-*` and deny attaching `AnthropicLimitedAccess` to any principal | Block new long-term keys and keep `AnthropicLimitedAccess` off arbitrary identities |
| `3-block-long-term-only.json` | Deny `aws-external-anthropic:CallWithBearerToken` when `aws-external-anthropic:BearerTokenType = LONG_TERM` | Allow short-term API key use while killing static keys |
| `4-block-phantom-access-keys.json` | Deny `iam:CreateAccessKey`, `iam:CreateLoginProfile` and MFA actions on `AeaApiKey-*` users | Defense-in-depth: keep the phantom from gaining general-purpose IAM credentials |
| `5-enforce-90day-max.json` | Deny `iam:CreateServiceSpecificCredential` for the Claude Platform service when `iam:ServiceSpecificCredentialAgeDays` > 90 | Cap the API key lifetime to 90 days |
| `6-workspace-allowlist.json` | Restrict `aws-external-anthropic:*` on a specific workspace to an allowlist of principals. Replace `REPLACE_WITH_WORKSPACE_ID`, `REPLACE_WITH_PERMITTED_ROLE` and `REPLACE_WITH_PERMITTED_USER` before deploying | Protect production workspaces from compromised IAM identities |
