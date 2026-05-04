# Infrastructure as Code

CloudFormation and Terraform for the four SCPs in [`../scps/`](../scps/).
Two interchangeable shapes for the same four policies:

- [`terraform/`](terraform/) — module wrapping the four SCPs as
  `aws_organizations_policy` resources, with optional OU attachment.
- [`cloudformation/scps.yaml`](cloudformation/scps.yaml) — single
  CloudFormation template with conditional resources, StackSet-friendly.

Both default to enabling `Block-Bedrock-API-Keys` plus
`Block-Phantom-User-Escalation` as the recommended baseline pair.

## Detection IaC lives elsewhere

This folder is preventive controls only. For detection IaC see:

- [`../detections/eventbridge/`](../detections/eventbridge/) — raw
  EventBridge event patterns covering long-term key creation, phantom
  user creation, AKIA escalation, and console-login pivot.
- [aws-samples / aws-customer-playbook-framework / detections/cfn](https://github.com/aws-samples/aws-customer-playbook-framework/tree/main/detections/cfn) —
  ready-to-deploy CloudFormation template for Bedrock EventBridge
  monitoring.
