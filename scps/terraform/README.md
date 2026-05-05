# Terraform: Bedrock API key SCPs

Terraform module that mirrors the four JSON SCPs in `scps/` as
`aws_organizations_policy` resources, ready to attach to OUs.

## Usage

```hcl
module "bedrock_scps" {
  source = "./scps/terraform"

  # Pick which SCPs to create. Defaults: only "block_all_keys".
  enable_block_all_keys              = true
  enable_enforce_90day_max           = false
  enable_block_long_term_only        = false
  enable_block_phantom_access_keys   = true

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
| `policy_ids` | Map of SCP name → policy ID (only for enabled SCPs). |
| `policy_arns` | Map of SCP name → policy ARN. |

## Test on a non-prod OU first

SCPs are evaluated as deny-only at the org level. Apply to a sandbox OU,
verify behaviour with `bks scan --profile sandbox`, then promote.
