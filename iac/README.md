# Infrastructure as Code

Terraform module and CloudFormation template that deploy the four SCPs in [`../scps/`](../scps/). Pick one:

- [`terraform/`](terraform/): `aws_organizations_policy` resources with optional OU attachment.
- [`cloudformation/scps.yaml`](cloudformation/scps.yaml): conditional resources, StackSet-friendly.

Both default to `Block-Bedrock-API-Keys` + `Block-Phantom-User-Escalation` as the baseline pair.

For detection IaC, see [`../detections/eventbridge/`](../detections/eventbridge/) and the [aws-samples Bedrock EventBridge CFN template](https://github.com/aws-samples/aws-customer-playbook-framework/tree/main/detections/cfn).
