"""AWS scanner for BedrockAPIKey-* phantom IAM users"""

import csv
import json
import os
import sys
import click
from datetime import datetime, timezone
from typing import Dict, List, Optional
from botocore.exceptions import ClientError

from bedrock_keys_security.core.scanner_base import BasePhantomScanner
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.csv_helpers import csv_safe as _csv_safe, json_default as _json_default


class PhantomUserScanner(BasePhantomScanner):
    """Scanner for BedrockAPIKey-* phantom IAM users.

    Inherits the shared enumeration, IAM credential checks, CloudTrail
    lookup helpers and short-term revoke flow from
    :class:`BasePhantomScanner`. The service-specific bits below override
    the ``revoke_key`` long-term flow (Bedrock-specific deny + SSC delete),
    the AT RISK status semantics on AKIA presence, and the table / JSON /
    CSV / incident output schemas.
    """

    BACKING_USER_PREFIX = "BedrockAPIKey-"
    SERVICE_SPECIFIC_CREDENTIAL_SERVICE = "bedrock.amazonaws.com"
    SERVICE_LABEL = "Bedrock"
    CREDENTIAL_COUNT_KEY = "bedrock_credentials"
    ACTIVE_CREDENTIAL_COUNT_KEY = "active_bedrock_credentials"
    REVOKE_DENY_ACTION = "bedrock:*"
    REVOKE_DENY_SID = "DenyBedrockAPIKeyUsage"

    def _decode_short_term(self, key: str) -> Dict:
        from bedrock_keys_security.core.decoder import BedrockKeyDecoder
        return BedrockKeyDecoder.decode_short_term_key(key)

    def _short_term_revoke_banner(self) -> str:
        return "⚠️  EMERGENCY TOKEN REVOCATION (short-term)"

    def categorize_status(self, user_data: Dict) -> str:
        """Categorize user status: ACTIVE, ORPHANED or AT RISK"""
        has_active_bedrock = user_data.get('active_bedrock_credentials', 0) > 0
        has_access_keys = user_data.get('active_access_keys', 0) > 0

        if has_access_keys:
            return 'AT RISK'
        elif has_active_bedrock:
            return 'ACTIVE'
        else:
            return 'ORPHANED'

    def _revoke_verify_hint(self) -> str:
        return (
            "Verify: AWS_BEARER_TOKEN_BEDROCK=<key> aws bedrock list-foundation-models  "
            "(expect AccessDenied)\n"
        )

    def collect_incident_data(self, username: str) -> Dict:
        """Side-effect-free fetch of all incident-report data for a phantom user.

        Returns a structured Dict suitable for JSON serialization or text formatting.
        Errors during IAM lookups are appended to result['errors'] rather than raised.
        """
        data: Dict = {
            "service": "bedrock",
            "username": username,
            "account_id": self.account_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "user": None,
            "bedrock_credentials": [],
            "iam_access_keys": [],
            "attached_policies": [],
            "inline_policies": [],
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
                ServiceName='bedrock.amazonaws.com',
            )['ServiceSpecificCredentials']
            data["bedrock_credentials"] = [
                {
                    "credential_id": c['ServiceSpecificCredentialId'],
                    "status": c['Status'],
                    "created": c['CreateDate'].astimezone(timezone.utc).isoformat(),
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
        except ClientError as e:
            data["errors"].append(str(e))
        return data

    def generate_incident_report(self, username: str, output_file: Optional[str] = None,
                                 data: Optional[Dict] = None) -> str:
        """Generate human-readable incident report (text format) for phantom user.

        Backed by collect_incident_data; the JSON variant is exposed via
        the report --json flag in commands/report.py. ``data`` optionally reuses
        an already-collected snapshot so ``report --json --output`` does not
        fetch the same IAM data twice.
        """
        if data is None:
            data = self.collect_incident_data(username)
        report_lines: List[str] = []

        report_lines.append("═" * 80)
        report_lines.append("  AWS BEDROCK API KEY INCIDENT REPORT")
        report_lines.append("═" * 80)
        report_lines.append("")
        ts = datetime.fromisoformat(data["generated_at"]).strftime('%Y-%m-%d %H:%M:%S UTC')
        report_lines.append(f"Generated: {ts}")
        report_lines.append(f"Username: {username}")
        report_lines.append(f"Account ID: {self.account_id}")
        report_lines.append("")

        report_lines.append("PHANTOM USER DETAILS")
        report_lines.append("─" * 80)
        if data["user"]:
            user = data["user"]
            user_created = datetime.fromisoformat(user["created"]).strftime('%Y-%m-%d %H:%M:%S UTC')
            report_lines.append(f"User ID: {user['user_id']}")
            report_lines.append(f"ARN: {user['arn']}")
            report_lines.append(f"Created: {user_created}")
            report_lines.append("")

        report_lines.append("BEDROCK API CREDENTIALS")
        report_lines.append("─" * 80)
        if data["bedrock_credentials"]:
            for cred in data["bedrock_credentials"]:
                cred_created = datetime.fromisoformat(cred["created"]).strftime('%Y-%m-%d %H:%M:%S UTC')
                report_lines.append(f"  ID: {cred['credential_id']}")
                report_lines.append(f"  Status: {cred['status']}")
                report_lines.append(f"  Created: {cred_created}")
                report_lines.append("")
        else:
            report_lines.append("  No credentials found")
            report_lines.append("")

        report_lines.append("IAM ACCESS KEYS (ESCALATION CHECK)")
        report_lines.append("─" * 80)
        access_keys = data["iam_access_keys"]
        if access_keys:
            n_keys = len(access_keys)
            key_word = "key" if n_keys == 1 else "keys"
            report_lines.append(f"  ⚠️  WARNING: {n_keys} IAM access {key_word} found!")
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
        report_lines.append("─" * 80)
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

        report_lines.append("═" * 80)
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

    def generate_json_report(self, phantoms: List[Dict]) -> str:
        """Generate JSON report"""
        report = {
            'scan_metadata': {
                'account_id': self.account_id,
                'region': self.region,
                'scan_time': datetime.now(timezone.utc).isoformat(),
                'caller_arn': self.caller_arn
            },
            'summary': {
                'total': len(phantoms),
                'active': len([u for u in phantoms if u['status'] == 'ACTIVE']),
                'orphaned': len([u for u in phantoms if u['status'] == 'ORPHANED']),
                'at_risk': len([u for u in phantoms if u['status'] == 'AT RISK'])
            },
            'phantom_users': phantoms
        }

        return json.dumps(report, indent=2, default=_json_default)

    def generate_csv_report(self, phantoms: List[Dict], output_file: str):
        """Generate CSV report and save to file. Always writes (header-only if no phantoms).

        Cells starting with `= + - @ \\t \\r` are prefixed with `'` to neutralize
        Excel / Google Sheets formula injection. IAM allows `=` in usernames
        (charset `[\\w+=,.@-]`), so a hostile actor could plant a phantom user
        named `BedrockAPIKey-=cmd|...` whose CSV row triggers RCE in the SOC
        analyst's spreadsheet on open.
        """
        fieldnames = [
            'username', 'user_id', 'created', 'status',
            'active_bedrock_credentials', 'bedrock_credentials',
            'active_access_keys', 'access_keys',
            'access_key_ids', 'attached_policies', 'inline_policies'
        ]

        try:
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()

                for user in phantoms:
                    row = user.copy()
                    row['created'] = user['created'].isoformat() if isinstance(user['created'], datetime) else user['created']
                    row['access_key_ids'] = ','.join(user.get('access_key_ids', []))
                    row['attached_policies'] = ','.join(user.get('attached_policies', []))
                    row['inline_policies'] = ','.join(user.get('inline_policies', []))

                    writer.writerow({k: _csv_safe(v) for k, v in row.items()})

        except IOError as e:
            output.error(f"Failed to write CSV file: {e}")
            sys.exit(1)
