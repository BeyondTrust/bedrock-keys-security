variable "enable_block_all_keys" {
  description = "Create the Block-Claude-Platform-API-Keys SCP (recommended baseline)."
  type        = bool
  default     = true
}

variable "enable_block_phantom_user_creation" {
  description = "Create the Block-Claude-Platform-Phantom-User-Creation SCP (deny iam:CreateUser on AeaApiKey-* and attaching AnthropicLimitedAccess)."
  type        = bool
  default     = false
}

variable "enable_block_long_term_only" {
  description = "Create the Block-Long-Term-Claude-Platform-Keys SCP (allow short-term keys)."
  type        = bool
  default     = false
}

variable "enable_block_phantom_access_keys" {
  description = "Create the Block-Claude-Platform-Phantom-User-Escalation SCP (recommended baseline)."
  type        = bool
  default     = true
}

variable "enable_enforce_90day_max" {
  description = "Create the Enforce-Claude-Platform-90Day-Max SCP."
  type        = bool
  default     = false
}

variable "enable_workspace_allowlist" {
  description = "Create the Workspace-Allowlist SCP. Requires workspace_id and permitted_principal_arns."
  type        = bool
  default     = false
}

variable "workspace_id" {
  description = "Claude Platform workspace ID (e.g. wrkspc_<26-char-ulid>). Required when enable_workspace_allowlist = true."
  type        = string
  default     = ""
}

variable "permitted_principal_arns" {
  description = "ARNs allowed to invoke aws-external-anthropic:* on the protected workspace. Wildcards allowed (ArnNotLike). Required when enable_workspace_allowlist = true."
  type        = list(string)
  default     = []
}

variable "target_ou_ids" {
  description = "Optional OU IDs to attach the enabled SCPs to. Empty = create only."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every created policy."
  type        = map(string)
  default = {
    "ManagedBy" = "bedrock-keys-security"
    "Source"    = "https://github.com/BeyondTrust/bedrock-keys-security"
  }
}
