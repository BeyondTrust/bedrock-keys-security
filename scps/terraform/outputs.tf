output "policy_ids" {
  description = "Map of SCP key → AWS Organizations policy ID."
  value       = { for k, p in aws_organizations_policy.bedrock_scp : k => p.id }
}

output "policy_arns" {
  description = "Map of SCP key → AWS Organizations policy ARN."
  value       = { for k, p in aws_organizations_policy.bedrock_scp : k => p.arn }
}
