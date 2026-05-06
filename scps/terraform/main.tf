# Policies are inlined (not loaded from ../*.json) so the module is
# self-contained as a remote source. Keep bodies below in sync with the
# four JSON files in this module's parent directory.

locals {
  scps = {
    block_all_keys = {
      enabled     = var.enable_block_all_keys
      name        = "Block-Bedrock-API-Keys"
      description = "Deny creation of long-term Bedrock API keys and use of any Bedrock API key (long or short term)."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Effect   = "Deny"
            Action   = "iam:CreateServiceSpecificCredential"
            Resource = "*"
            Condition = {
              StringEquals = {
                "iam:ServiceSpecificCredentialServiceName" = "bedrock.amazonaws.com"
              }
            }
          },
          {
            Effect   = "Deny"
            Action   = "bedrock:CallWithBearerToken"
            Resource = "*"
          },
        ]
      })
    }

    enforce_90day_max = {
      enabled     = var.enable_enforce_90day_max
      name        = "Enforce-Bedrock-90Day-Max"
      description = "Limit Bedrock service-specific credential lifetime to 90 days."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "Enforce90DayMaxExpiry"
            Effect   = "Deny"
            Action   = ["iam:CreateServiceSpecificCredential"]
            Resource = "*"
            Condition = {
              StringEquals = {
                "iam:ServiceSpecificCredentialServiceName" = "bedrock.amazonaws.com"
              }
              NumericGreaterThan = {
                "iam:ServiceSpecificCredentialAgeDays" = "90"
              }
            }
          },
        ]
      })
    }

    block_long_term_only = {
      enabled     = var.enable_block_long_term_only
      name        = "Block-Long-Term-Bedrock-Keys"
      description = "Deny long-term (ABSK) bearer tokens; allow short-term."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Effect   = "Deny"
            Action   = "bedrock:CallWithBearerToken"
            Resource = "*"
            Condition = {
              StringEquals = {
                "bedrock:BearerTokenType" = "LONG_TERM"
              }
            }
          },
        ]
      })
    }

    block_phantom_access_keys = {
      enabled     = var.enable_block_phantom_access_keys
      name        = "Block-Phantom-User-Escalation"
      description = "Deny IAM access key, console login and MFA on BedrockAPIKey-* phantom users."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "BlockPhantomUserAccessKeyCreation"
            Effect   = "Deny"
            Action   = ["iam:CreateAccessKey"]
            Resource = "arn:aws:iam::*:user/BedrockAPIKey-*"
          },
          {
            Sid      = "BlockPhantomUserConsoleAccess"
            Effect   = "Deny"
            Action   = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
            Resource = "arn:aws:iam::*:user/BedrockAPIKey-*"
          },
          {
            Sid    = "BlockPhantomUserMFADevices"
            Effect = "Deny"
            Action = ["iam:EnableMFADevice", "iam:CreateVirtualMFADevice"]
            Resource = [
              "arn:aws:iam::*:user/BedrockAPIKey-*",
              "arn:aws:iam::*:mfa/BedrockAPIKey-*",
            ]
          },
        ]
      })
    }
  }

  enabled_scps = { for k, v in local.scps : k => v if v.enabled }

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
  content     = each.value.policy

  tags = var.tags
}

resource "aws_organizations_policy_attachment" "bedrock_scp" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.bedrock_scp[each.value.scp_key].id
  target_id = each.value.ou_id
}
