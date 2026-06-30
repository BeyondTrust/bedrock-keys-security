# Terraform: Claude Platform on AWS SCPs

Terraform module that mirrors the JSON SCPs in `scps/claude-platform/`
as `aws_organizations_policy` resources, ready to attach to OUs.

## Usage

```hcl
module "claude_platform_scps" {
  source = "./scps/claude-platform/terraform"

  # Pick which SCPs to create. Defaults: only "block_all_keys" and "block_phantom_access_keys".
  enable_block_all_keys              = true
  enable_block_phantom_user_creation = false
  enable_block_long_term_only        = false
  enable_block_phantom_access_keys   = true
  enable_enforce_90day_max           = false

  # Workspace allowlist requires the workspace ID and the allowlisted principals.
  enable_workspace_allowlist = false
  workspace_id               = "wrkspc_REPLACE_WITH_REAL_ID"
  permitted_principal_arns = [
    "arn:aws:iam::*:role/ProductionDeployer*",
    "arn:aws:iam::*:user/workspace-admin",
  ]

  # Optional: attach to OUs immediately.
  target_ou_ids = ["ou-xxxx-aaaaaaaa", "ou-xxxx-bbbbbbbb"]
}
```

## Requirements

- Terraform >= 1.5
- AWS provider >= 5.0
- Caller must have `organizations:CreatePolicy` and (if `target_ou_ids` is set)
  `organizations:AttachPolicy` in the management account.

## Outputs

| Name | Description |
|---|---|
| `policy_ids` | Map of SCP name to policy ID (only for enabled SCPs). |
| `policy_arns` | Map of SCP name to policy ARN. |

## Test on a non-prod OU first

SCPs are evaluated as deny-only at the org level. Apply to a sandbox OU,
verify behaviour with `bks scan --service claude-platform --profile sandbox`,
then promote.
