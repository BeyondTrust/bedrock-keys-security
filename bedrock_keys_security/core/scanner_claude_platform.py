"""AWS scanner for AeaApiKey-* phantom IAM users.

Mirrors PhantomUserScanner for the Bedrock surface. The Claude Platform
on AWS service auto-provisions an IAM user named ``AeaApiKey-*`` each
time a long-term API key is created in the platform console. The backing
IAM user receives the AWS-managed ``AnthropicLimitedAccess`` policy and
holds the API key as a service-specific credential with
``ServiceName=aws-external-anthropic.amazonaws.com``.

The API key surfaces through the standard ``iam:ListServiceSpecificCredentials``
API just like Bedrock long-term keys (same ``ACCA*`` credential ID
prefix, same ``<username>-at-<account>`` alias shape). Revocation can be
performed per credential with ``iam:DeleteServiceSpecificCredential``
without needing to delete the backing IAM user.

Risk categorization differs from the Bedrock scanner: the Claude
Platform scanner does not emit ``AT RISK``. ``AnthropicLimitedAccess``
is workspace-scoped and an ``AKIA*`` access key created on the phantom
user inherits the same surface as the API key, so there is no
escalation pivot to flag. Status is ``ACTIVE`` if any live credential
(service-specific or ``AKIA``) is present and ``ORPHANED`` otherwise.
"""

import csv
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

import click
from botocore.exceptions import ClientError

from bedrock_keys_security.core.scanner_base import BasePhantomScanner
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.csv_helpers import (
    csv_safe as _csv_safe,
    json_default as _json_default,
)


BACKING_USER_PREFIX = "AeaApiKey-"
MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AnthropicLimitedAccess"
SERVICE_PRINCIPAL = "aws-external-anthropic.amazonaws.com"
SERVICE_SPECIFIC_CREDENTIAL_SERVICE = "aws-external-anthropic.amazonaws.com"


class ClaudePlatformPhantomScanner(BasePhantomScanner):
    """Scanner for AeaApiKey-* phantom IAM users provisioned by Claude Platform on AWS.

    Inherits the shared enumeration, IAM credential checks, CloudTrail
    helpers, delete flow, cleanup flow and short-term revoke flow
    from :class:`BasePhantomScanner`. The service-specific bits below
    override the long-term revoke (Claude Platform `aws-external-anthropic`
    deny + SSC delete), the status semantics (no ``AT RISK``) and the
    table / JSON / CSV / incident output schemas.
    """

    BACKING_USER_PREFIX = "AeaApiKey-"
    SERVICE_SPECIFIC_CREDENTIAL_SERVICE = "aws-external-anthropic.amazonaws.com"
    SERVICE_LABEL = "Claude Platform"
    CREDENTIAL_COUNT_KEY = "claude_platform_credentials"
    ACTIVE_CREDENTIAL_COUNT_KEY = "active_claude_platform_credentials"
    NOTABLE_MANAGED_POLICY_ARN = MANAGED_POLICY_ARN
    NOTABLE_POLICY_FLAG_FIELD = "has_anthropic_policy"
    # Denying aws-external-anthropic:* also breaks the OIDC chain implicitly:
    # AnthropicLimitedAccess conditions sts:GetWebIdentityToken on
    # aws:CalledViaLast = aws-external-anthropic.amazonaws.com, so the service
    # deny short-circuits it without needing a separate STS deny.
    REVOKE_DENY_ACTION = ["aws-external-anthropic:*"]
    REVOKE_DENY_SID = "DenyClaudePlatformUsage"
    # No AT RISK on this surface; AKIA on AeaApiKey-* is not an escalation pivot.
    _STATUS_PRIORITY = {'ACTIVE': 0, 'ORPHANED': 1}

    def _service_tag(self) -> str:
        return "claude-platform"

    def _decode_short_term(self, key: str) -> Dict:
        from bedrock_keys_security.core.decoder_claude_platform import (
            ClaudePlatformKeyDecoder,
        )
        return ClaudePlatformKeyDecoder.decode_short_term_key(key)

    def _short_term_issuer_not_found_hint(self) -> str:
        return (
            "No CloudTrail events found for this short-term key's ASIA. Its use "
            "(ListWorkspaces, GetWorkspace, vault ops) is logged as management "
            "events keyed by this ASIA; `bks timeline "
            "<aws-external-anthropic-api-key-...>` lists them. If the only use "
            "was inference, enable the AWS::AWSExternalAnthropic::Workspace "
            "data-event selector. To contain the key, revoke the backing "
            "phantom user: `bks revoke-key <AeaApiKey-username>`."
        )

    def categorize_status(self, user_data: Dict) -> str:
        """Categorize user status: ACTIVE or ORPHANED.

        Unlike the Bedrock scanner, the Claude Platform scanner does not emit
        AT RISK on AKIA-present users. The AKIA inherits AnthropicLimitedAccess
        which is workspace-scoped (no IAM, VPC or KMS reconnaissance), so it
        grants the same effective abuse surface as the API key it sits next to.
        The escalation-pivot semantic that AT RISK encodes for Bedrock does not
        apply here. The "Access Keys" column in scan output still surfaces the
        AKIA count so an operator can investigate.

        - ACTIVE: has live Claude Platform service-specific credentials or AKIA
        - ORPHANED: neither credential type is live
        """
        has_credential = (
            user_data.get('active_claude_platform_credentials', 0) > 0
            or user_data.get('active_access_keys', 0) > 0
        )
        return 'ACTIVE' if has_credential else 'ORPHANED'

    def _revoke_verify_hint(self) -> str:
        return (
            "Verify with: bks scan --service claude-platform should report the "
            "user as ORPHANED.\n"
        )

    def generate_json_report(self, phantoms: List[Dict]) -> str:
        """Generate JSON report."""
        report = {
            'scan_metadata': {
                'service': 'claude-platform',
                'account_id': self.account_id,
                'region': self.region,
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'caller_arn': self.caller_arn,
            },
            'summary': {
                'total': len(phantoms),
                'active': len([u for u in phantoms if u['status'] == 'ACTIVE']),
                'orphaned': len([u for u in phantoms if u['status'] == 'ORPHANED']),
            },
            'phantom_users': phantoms,
        }

        return json.dumps(report, indent=2, default=_json_default)

    def collect_incident_data(self, username: str) -> Dict:
        """Side-effect-free fetch of incident-report data for a Claude Platform phantom user.

        Returns a structured Dict suitable for JSON serialization or text formatting.
        Errors during IAM lookups are appended to ``result['errors']`` rather than raised.
        """
        data: Dict = {
            "service": "claude-platform",
            "username": username,
            "account_id": self.account_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "user": None,
            "claude_platform_credentials": [],
            "iam_access_keys": [],
            "attached_policies": [],
            "inline_policies": [],
            "has_anthropic_policy": False,
            "errors": [],
        }
        try:
            user = self.iam.get_user(UserName=username)['User']
            data["user"] = {
                "user_id": user['UserId'],
                "arn": user['Arn'],
                "created": user['CreateDate'].astimezone(timezone.utc).isoformat(),
            }

            creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName=SERVICE_SPECIFIC_CREDENTIAL_SERVICE,
            )['ServiceSpecificCredentials']
            data["claude_platform_credentials"] = [
                {
                    "credential_id": c['ServiceSpecificCredentialId'],
                    "credential_alias": c.get('ServiceCredentialAlias'),
                    "status": c['Status'],
                    "created": c['CreateDate'].astimezone(timezone.utc).isoformat(),
                    "expires": (
                        c['ExpirationDate'].astimezone(timezone.utc).isoformat()
                        if c.get('ExpirationDate')
                        else None
                    ),
                }
                for c in creds
            ]

            access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            data["iam_access_keys"] = [
                {
                    "access_key_id": k['AccessKeyId'],
                    "status": k['Status'],
                    "created": k['CreateDate'].astimezone(timezone.utc).isoformat(),
                }
                for k in access_keys
            ]

            attached = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            inline = self.iam.list_user_policies(UserName=username)['PolicyNames']
            data["attached_policies"] = [
                {"policy_name": p['PolicyName'], "policy_arn": p['PolicyArn']}
                for p in attached
            ]
            data["inline_policies"] = list(inline)
            data["has_anthropic_policy"] = any(
                p['PolicyArn'] == MANAGED_POLICY_ARN for p in attached
            )
        except ClientError as e:
            data["errors"].append(str(e))
        return data

    def generate_incident_report(self, username: str, output_file: Optional[str] = None,
                                 data: Optional[Dict] = None) -> str:
        """Generate a text incident report for a Claude Platform phantom user.

        ``data`` optionally reuses an already-collected snapshot so
        ``report --json --output`` does not fetch the same IAM data twice.
        """
        if data is None:
            data = self.collect_incident_data(username)
        report_lines: List[str] = []

        sep = "=" * 80
        report_lines.append(sep)
        report_lines.append("  CLAUDE PLATFORM ON AWS API KEY INCIDENT REPORT")
        report_lines.append(sep)
        report_lines.append("")
        ts = datetime.fromisoformat(data["generated_at"]).strftime('%Y-%m-%d %H:%M:%S UTC')
        report_lines.append(f"Generated: {ts}")
        report_lines.append(f"Username: {username}")
        report_lines.append(f"Account ID: {self.account_id}")
        report_lines.append("")

        report_lines.append("PHANTOM USER DETAILS")
        report_lines.append("-" * 80)
        if data["user"]:
            user = data["user"]
            user_created = datetime.fromisoformat(user["created"]).strftime('%Y-%m-%d %H:%M:%S UTC')
            report_lines.append(f"User ID: {user['user_id']}")
            report_lines.append(f"ARN: {user['arn']}")
            report_lines.append(f"Created: {user_created}")
            report_lines.append("")

        report_lines.append("CLAUDE PLATFORM API CREDENTIALS")
        report_lines.append("-" * 80)
        if data["claude_platform_credentials"]:
            for cred in data["claude_platform_credentials"]:
                cred_created = datetime.fromisoformat(
                    cred["created"]
                ).strftime('%Y-%m-%d %H:%M:%S UTC')
                report_lines.append(f"  ID: {cred['credential_id']}")
                report_lines.append(f"  Alias: {cred.get('credential_alias', '')}")
                report_lines.append(f"  Status: {cred['status']}")
                report_lines.append(f"  Created: {cred_created}")
                if cred.get("expires"):
                    cred_expires = datetime.fromisoformat(
                        cred["expires"]
                    ).strftime('%Y-%m-%d %H:%M:%S UTC')
                    report_lines.append(f"  Expires: {cred_expires}")
                report_lines.append("")
        else:
            report_lines.append("  No credentials found")
            report_lines.append("")

        report_lines.append("ANTHROPIC MANAGED POLICY ATTACHMENT")
        report_lines.append("-" * 80)
        if data["has_anthropic_policy"]:
            report_lines.append(f"  AnthropicLimitedAccess attached: {MANAGED_POLICY_ARN}")
        else:
            report_lines.append(
                "  AnthropicLimitedAccess NOT attached. Even if a credential is live, "
                "the API key cannot reach Claude Platform without this policy."
            )
        report_lines.append("")

        report_lines.append("IAM ACCESS KEYS (ESCALATION CHECK)")
        report_lines.append("-" * 80)
        access_keys = data["iam_access_keys"]
        if access_keys:
            n_keys = len(access_keys)
            key_word = "key" if n_keys == 1 else "keys"
            report_lines.append(f"  WARNING: {n_keys} IAM access {key_word} found.")
            for key in access_keys:
                key_created = datetime.fromisoformat(key["created"]).strftime('%Y-%m-%d %H:%M:%S UTC')
                report_lines.append(f"    Key ID: {key['access_key_id']}")
                report_lines.append(f"    Status: {key['status']}")
                report_lines.append(f"    Created: {key_created}")
            report_lines.append("")
        else:
            report_lines.append("  No access keys found")
            report_lines.append("")

        report_lines.append("ATTACHED POLICIES")
        report_lines.append("-" * 80)
        if data["attached_policies"]:
            report_lines.append("  Managed Policies:")
            for policy in data["attached_policies"]:
                report_lines.append(f"    - {policy['policy_name']} ({policy['policy_arn']})")
        if data["inline_policies"]:
            report_lines.append("  Inline Policies:")
            for policy_name in data["inline_policies"]:
                report_lines.append(f"    - {policy_name}")
        if not data["attached_policies"] and not data["inline_policies"]:
            report_lines.append("  No policies attached")
        report_lines.append("")

        for err in data["errors"]:
            report_lines.append(f"ERROR: {err}")
            report_lines.append("")

        report_lines.append(sep)
        report_content = '\n'.join(report_lines)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_content)
                try:
                    os.chmod(output_file, 0o600)
                except OSError:
                    pass
                output.success(f"Report saved to: {output_file}")
            except IOError as e:
                output.error(f"Failed to save report: {e}")
        elif not output._quiet_mode:
            click.echo(report_content)

        return report_content

    def generate_csv_report(self, phantoms: List[Dict], output_file: str):
        """Generate CSV report and save to file. Always writes (header-only if no phantoms).

        Cells starting with ``= + - @ \\t \\r`` are prefixed with ``'`` to neutralize
        Excel / Google Sheets formula injection. IAM allows ``=`` in usernames so a
        hostile actor could plant a phantom user named ``AeaApiKey-=cmd|...`` whose
        CSV row triggers RCE in the SOC analyst's spreadsheet on open.
        """
        fieldnames = [
            'username', 'user_id', 'created', 'status',
            'active_claude_platform_credentials', 'claude_platform_credentials',
            'has_anthropic_policy',
            'active_access_keys', 'access_keys',
            'access_key_ids', 'attached_policies', 'inline_policies',
        ]

        try:
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()

                for user in phantoms:
                    row = user.copy()
                    row['created'] = (
                        user['created'].isoformat()
                        if isinstance(user['created'], datetime)
                        else user['created']
                    )
                    row['access_key_ids'] = ','.join(user.get('access_key_ids', []))
                    row['attached_policies'] = ','.join(user.get('attached_policies', []))
                    row['inline_policies'] = ','.join(user.get('inline_policies', []))

                    writer.writerow({k: _csv_safe(v) for k, v in row.items()})

        except IOError as e:
            output.error(f"Failed to write CSV file: {e}")
            sys.exit(1)
