# Required AWS Permissions per Command

`bks` requires the following IAM permissions per command. All commands except `decode-key` also call `sts:GetCallerIdentity` to confirm the active session.

| Command | IAM Permissions Required |
|---|---|
| `scan` | `iam:ListUsers`, `iam:ListServiceSpecificCredentials`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies` |
| `cleanup` | All `scan` permissions + `iam:DeleteAccessKey`, `iam:DeleteServiceSpecificCredential`, `iam:DetachUserPolicy`, `iam:DeleteUserPolicy`, `iam:DeleteUser` |
| `revoke-key` | `iam:PutUserPolicy`, `iam:ListServiceSpecificCredentials`, `iam:DeleteServiceSpecificCredential`, `iam:ListAccessKeys`, `iam:UpdateAccessKey` |
| `timeline` | `cloudtrail:LookupEvents` (plus `cloudtrail:DescribeTrails` and `ec2:DescribeRegions` when using `--all-regions`) |
| `report` | `iam:GetUser`, `iam:ListServiceSpecificCredentials`, `iam:ListAccessKeys`, `iam:ListAttachedUserPolicies`, `iam:ListUserPolicies` |
| `decode-key` | None (offline) |

For least-privilege deployment, attach only the permissions for the commands you intend to use.
