locals {
  scps = {
    block_all_keys = {
      enabled     = var.enable_block_all_keys
      name        = "Block-Bedrock-API-Keys"
      description = "Deny creation and use of any Bedrock API key (long or short term)."
      policy_file = "${path.module}/../../scps/1-block-all-keys.json"
    }
    enforce_90day_max = {
      enabled     = var.enable_enforce_90day_max
      name        = "Enforce-Bedrock-90Day-Max"
      description = "Limit Bedrock service-specific credential lifetime to 90 days."
      policy_file = "${path.module}/../../scps/2-enforce-90day-max.json"
    }
    block_long_term_only = {
      enabled     = var.enable_enforce_90day_max == false ? var.enable_block_long_term_only : false
      name        = "Block-Long-Term-Bedrock-Keys"
      description = "Deny long-term (ABSK) bearer tokens; allow short-term."
      policy_file = "${path.module}/../../scps/3-block-long-term-only.json"
    }
    block_phantom_access_keys = {
      enabled     = var.enable_block_phantom_access_keys
      name        = "Block-Phantom-User-Escalation"
      description = "Deny IAM access key, console login, and MFA on BedrockAPIKey-* phantom users."
      policy_file = "${path.module}/../../scps/4-block-phantom-access-keys.json"
    }
  }

  enabled_scps = { for k, v in local.scps : k => v if v.enabled }

  # All enabled SCPs × all target OU IDs
  attachments = {
    for pair in setproduct(keys(local.enabled_scps), var.target_ou_ids) :
    "${pair[0]}-${pair[1]}" => { scp_key = pair[0], ou_id = pair[1] }
  }
}

resource "aws_organizations_policy" "bedrock_scp" {
  for_each = local.enabled_scps

  name        = each.value.name
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = file(each.value.policy_file)

  tags = var.tags
}

resource "aws_organizations_policy_attachment" "bedrock_scp" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.bedrock_scp[each.value.scp_key].id
  target_id = each.value.ou_id
}
