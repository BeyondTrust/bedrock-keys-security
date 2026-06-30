# Policies are inlined (not loaded from ../*.json) so the module is
# self-contained as a remote source. Keep bodies below in sync with the
# JSON files in this module's parent directory (scps/claude-platform/).

locals {
  scps = {
    block_all_keys = {
      enabled     = var.enable_block_all_keys
      name        = "Block-Claude-Platform-API-Keys"
      description = "Deny creation and use of any Claude Platform API key (long or short term) and block the OIDC token-issuance path."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "BlockClaudePlatformCredentialCreation"
            Effect   = "Deny"
            Action   = "iam:CreateServiceSpecificCredential"
            Resource = "*"
            Condition = {
              StringEquals = {
                "iam:ServiceSpecificCredentialServiceName" = "aws-external-anthropic.amazonaws.com"
              }
            }
          },
          {
            Sid      = "BlockClaudePlatformApiKeyUse"
            Effect   = "Deny"
            Action   = "aws-external-anthropic:CallWithBearerToken"
            Resource = "*"
          },
          {
            Sid      = "BlockClaudePlatformPhantomUserCreation"
            Effect   = "Deny"
            Action   = "iam:CreateUser"
            Resource = "arn:aws:iam::*:user/AeaApiKey-*"
          },
          {
            Sid      = "BlockClaudePlatformWebIdentityToken"
            Effect   = "Deny"
            Action   = ["sts:GetWebIdentityToken", "sts:TagGetWebIdentityToken"]
            Resource = "*"
            Condition = {
              "ForAnyValue:StringEquals" = {
                "sts:IdentityTokenAudience" = [
                  "https://api.anthropic.com",
                  "https://platform.claude.com",
                ]
              }
            }
          },
        ]
      })
    }

    block_phantom_user_creation = {
      enabled     = var.enable_block_phantom_user_creation
      name        = "Block-Claude-Platform-Phantom-User-Creation"
      description = "Deny iam:CreateUser matching AeaApiKey-* and deny attaching AnthropicLimitedAccess to any principal."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "BlockClaudePlatformPhantomUserCreation"
            Effect   = "Deny"
            Action   = "iam:CreateUser"
            Resource = "arn:aws:iam::*:user/AeaApiKey-*"
          },
          {
            Sid      = "BlockAnthropicLimitedAccessAttachment"
            Effect   = "Deny"
            Action   = ["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"]
            Resource = "*"
            Condition = {
              ArnEquals = {
                "iam:PolicyARN" = "arn:aws:iam::aws:policy/AnthropicLimitedAccess"
              }
            }
          },
        ]
      })
    }

    block_long_term_only = {
      enabled     = var.enable_block_long_term_only
      name        = "Block-Long-Term-Claude-Platform-Keys"
      description = "Deny long-term Claude Platform API keys; allow short-term."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "BlockClaudePlatformLongTermApiKeyUse"
            Effect   = "Deny"
            Action   = "aws-external-anthropic:CallWithBearerToken"
            Resource = "*"
            Condition = {
              StringEquals = {
                "aws-external-anthropic:BearerTokenType" = "LONG_TERM"
              }
            }
          },
        ]
      })
    }

    block_phantom_access_keys = {
      enabled     = var.enable_block_phantom_access_keys
      name        = "Block-Claude-Platform-Phantom-User-Escalation"
      description = "Deny IAM access key, console login and MFA on AeaApiKey-* phantom users."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "BlockClaudePlatformPhantomAccessKeyCreation"
            Effect   = "Deny"
            Action   = ["iam:CreateAccessKey"]
            Resource = "arn:aws:iam::*:user/AeaApiKey-*"
          },
          {
            Sid      = "BlockClaudePlatformPhantomConsoleAccess"
            Effect   = "Deny"
            Action   = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
            Resource = "arn:aws:iam::*:user/AeaApiKey-*"
          },
          {
            Sid    = "BlockClaudePlatformPhantomMFADevices"
            Effect = "Deny"
            Action = ["iam:EnableMFADevice", "iam:CreateVirtualMFADevice"]
            Resource = [
              "arn:aws:iam::*:user/AeaApiKey-*",
              "arn:aws:iam::*:mfa/AeaApiKey-*",
            ]
          },
        ]
      })
    }

    enforce_90day_max = {
      enabled     = var.enable_enforce_90day_max
      name        = "Enforce-Claude-Platform-90Day-Max"
      description = "Cap Claude Platform service-specific credential lifetime at 90 days (blocks Never expires)."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "EnforceClaudePlatform90DayMaxExpiry"
            Effect   = "Deny"
            Action   = ["iam:CreateServiceSpecificCredential"]
            Resource = "*"
            Condition = {
              StringEquals = {
                "iam:ServiceSpecificCredentialServiceName" = "aws-external-anthropic.amazonaws.com"
              }
              NumericGreaterThan = {
                "iam:ServiceSpecificCredentialAgeDays" = "90"
              }
            }
          },
        ]
      })
    }

    workspace_allowlist = {
      enabled     = var.enable_workspace_allowlist
      name        = "Claude-Platform-Workspace-Allowlist"
      description = "Restrict aws-external-anthropic:* on a specific workspace to an allowlist of principals."
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
          {
            Sid      = "DenyUnauthorizedAccessToProtectedWorkspace"
            Effect   = "Deny"
            Action   = "aws-external-anthropic:*"
            Resource = "arn:aws:aws-external-anthropic:*:*:workspace/${var.workspace_id}"
            Condition = {
              ArnNotLike = {
                "aws:PrincipalArn" = var.permitted_principal_arns
              }
            }
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

resource "aws_organizations_policy" "claude_platform_scp" {
  for_each = local.enabled_scps

  name        = each.value.name
  description = each.value.description
  type        = "SERVICE_CONTROL_POLICY"
  content     = each.value.policy

  tags = var.tags
}

resource "aws_organizations_policy_attachment" "claude_platform_scp" {
  for_each = local.attachments

  policy_id = aws_organizations_policy.claude_platform_scp[each.value.scp_key].id
  target_id = each.value.ou_id
}
