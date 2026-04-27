variable "enable_block_all_keys" {
  description = "Create the Block-Bedrock-API-Keys SCP (recommended baseline)."
  type        = bool
  default     = true
}

variable "enable_enforce_90day_max" {
  description = "Create the Enforce-90Day-Max-Lifetime SCP."
  type        = bool
  default     = false
}

variable "enable_block_long_term_only" {
  description = "Create the Block-Long-Term-Bedrock-Keys SCP (allow short-term keys)."
  type        = bool
  default     = false
}

variable "enable_block_phantom_access_keys" {
  description = "Create the Block-Phantom-User-Escalation SCP (recommended baseline)."
  type        = bool
  default     = true
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
