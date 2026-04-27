"""AWS scanner for BedrockAPIKey-* phantom IAM users"""

import csv
import json
import sys
import click
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
from typing import Dict, List, Optional
from botocore.exceptions import ClientError

from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.aws import AWSSession


class PhantomUserScanner:
    """
    Scanner for BedrockAPIKey-* phantom IAM users
    """

    def __init__(self, aws_session: AWSSession, verbose: bool = False):
        self.verbose = verbose
        self.iam = aws_session.iam
        self.sts = aws_session.sts
        self.cloudtrail = aws_session.cloudtrail
        self.account_id = aws_session.account_id
        self.caller_arn = aws_session.caller_arn
        self.region = aws_session.region

    def find_phantom_users(self) -> List[Dict]:
        """Find all IAM users starting with 'BedrockAPIKey-'"""
        if self.verbose:
            output.info("Scanning for phantom IAM users...")

        phantom_users = []

        try:
            paginator = self.iam.get_paginator('list_users')

            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']

                    if username.startswith('BedrockAPIKey-'):
                        if self.verbose:
                            output.info(f"Found phantom user: {username}")

                        user_data = {
                            'username': username,
                            'user_id': user['UserId'],
                            'arn': user['Arn'],
                            'created': user['CreateDate'],
                            'path': user['Path']
                        }

                        user_data.update(self.check_credentials(username))
                        user_data.update(self.check_access_keys(username))
                        user_data.update(self.check_policies(username))
                        user_data['status'] = self.categorize_status(user_data)

                        phantom_users.append(user_data)

            if self.verbose:
                output.success(f"Found {len(phantom_users)} phantom users")

        except ClientError as e:
            output.error(f"Failed to list IAM users: {e}")
            sys.exit(1)

        return phantom_users

    def check_credentials(self, username: str) -> Dict:
        """Check user's service-specific credentials (Bedrock API keys)"""
        try:
            response = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName='bedrock.amazonaws.com'
            )

            credentials = response.get('ServiceSpecificCredentials', [])
            active_creds = [c for c in credentials if c['Status'] == 'Active']

            if self.verbose and active_creds:
                key_word = "key" if len(active_creds) == 1 else "keys"
                output.warning(f"{username}: {len(active_creds)} active Bedrock API {key_word}")

            return {
                'bedrock_credentials': len(credentials),
                'active_bedrock_credentials': len(active_creds),
                'credential_details': active_creds
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return {
                    'bedrock_credentials': 0,
                    'active_bedrock_credentials': 0,
                    'credential_details': []
                }
            else:
                output.warning(f"Could not check credentials for {username}: {e}")
                return {
                    'bedrock_credentials': 0,
                    'active_bedrock_credentials': 0,
                    'credential_details': []
                }

    def check_access_keys(self, username: str) -> Dict:
        """Check for IAM access keys (AKIA...) - HIGH RISK indicator"""
        try:
            response = self.iam.list_access_keys(UserName=username)
            access_keys = response.get('AccessKeyMetadata', [])
            active_keys = [k for k in access_keys if k['Status'] == 'Active']

            if active_keys and self.verbose:
                key_word = "key" if len(active_keys) == 1 else "keys"
                output.high_risk(f"{username}: {len(active_keys)} IAM access {key_word} found (AT RISK)")

            return {
                'access_keys': len(access_keys),
                'active_access_keys': len(active_keys),
                'access_key_ids': [k['AccessKeyId'] for k in active_keys]
            }

        except ClientError as e:
            output.warning(f"Could not check access keys for {username}: {e}")
            return {
                'access_keys': 0,
                'active_access_keys': 0,
                'access_key_ids': []
            }

    def check_policies(self, username: str) -> Dict:
        """Check attached policies for the user"""
        try:
            attached = self.iam.list_attached_user_policies(UserName=username)
            attached_policies = attached.get('AttachedPolicies', [])

            inline = self.iam.list_user_policies(UserName=username)
            inline_policies = inline.get('PolicyNames', [])

            policy_names = [p['PolicyName'] for p in attached_policies] + inline_policies

            if self.verbose and policy_names:
                output.info(f"  [POLICY] {username}: {', '.join(policy_names)}")

            return {
                'attached_policies': [p['PolicyName'] for p in attached_policies],
                'inline_policies': inline_policies,
                'total_policies': len(attached_policies) + len(inline_policies)
            }

        except ClientError as e:
            output.warning(f"Could not check policies for {username}: {e}")
            return {
                'attached_policies': [],
                'inline_policies': [],
                'total_policies': 0
            }

    def categorize_status(self, user_data: Dict) -> str:
        """Categorize user status: ACTIVE, ORPHANED, or AT RISK"""
        has_active_bedrock = user_data.get('active_bedrock_credentials', 0) > 0
        has_access_keys = user_data.get('active_access_keys', 0) > 0

        if has_access_keys:
            return 'AT RISK'
        elif has_active_bedrock:
            return 'ACTIVE'
        else:
            return 'ORPHANED'

    def delete_phantom_user(self, username: str, dry_run: bool = False) -> bool:
        """Delete a phantom IAM user and all associated resources"""
        try:
            if dry_run:
                click.echo(output.yellow(f"[DRY-RUN] Would delete user: {username}"))

                access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                if access_keys:
                    click.echo(output.yellow(f"  - Would delete {len(access_keys)} access {'key' if len(access_keys) == 1 else 'keys'}"))

                service_creds = self.iam.list_service_specific_credentials(UserName=username)['ServiceSpecificCredentials']
                if service_creds:
                    click.echo(output.yellow(f"  - Would delete {len(service_creds)} Bedrock API {'key' if len(service_creds) == 1 else 'keys'}"))

                attached = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
                if attached:
                    click.echo(output.yellow(f"  - Would detach {len(attached)} managed {'policy' if len(attached) == 1 else 'policies'}"))

                inline = self.iam.list_user_policies(UserName=username)['PolicyNames']
                if inline:
                    click.echo(output.yellow(f"  - Would delete {len(inline)} inline polic(y/ies)"))

                return True

            if self.verbose:
                output.info(f"Deleting phantom user: {username}")

            # 1. Delete all access keys
            access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if self.verbose:
                    output.info(f"  [DELETE] Access key: {key['AccessKeyId']}")
                self.iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])

            # 2. Delete all service-specific credentials (Bedrock API keys)
            service_creds = self.iam.list_service_specific_credentials(UserName=username)['ServiceSpecificCredentials']
            for cred in service_creds:
                if self.verbose:
                    output.info(f"  [DELETE] Bedrock API key: {cred['ServiceSpecificCredentialId']}")
                self.iam.delete_service_specific_credential(
                    UserName=username,
                    ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId']
                )

            # 3. Detach all managed policies
            attached = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached:
                if self.verbose:
                    output.info(f"  [DETACH] Policy: {policy['PolicyName']}")
                self.iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])

            # 4. Delete all inline policies
            inline = self.iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline:
                if self.verbose:
                    output.info(f"  [DELETE] Inline policy: {policy_name}")
                self.iam.delete_user_policy(UserName=username, PolicyName=policy_name)

            # 5. Delete the user
            if self.verbose:
                output.info(f"  [DELETE] IAM user: {username}")
            self.iam.delete_user(UserName=username)

            output.success(f"Deleted phantom user: {username}")
            return True

        except ClientError as e:
            output.error(f"Failed to delete {username}: {e}")
            return False

    def cleanup_orphaned_users(self, phantoms: List[Dict], dry_run: bool = False, force: bool = False) -> Dict:
        """Clean up orphaned phantom users (no active credentials)"""
        orphaned_users = [u for u in phantoms if u['status'] == 'ORPHANED']

        if not orphaned_users:
            click.echo(f"\n{output.green('No orphaned phantom users found. Nothing to clean up.')}\n")
            return {'total': 0, 'deleted': 0, 'failed': 0}

        click.echo(f"\n{output.bold(f'Orphaned Phantom Users Found: {len(orphaned_users)}')}")
        click.echo(f"{output.yellow('The following users have no active credentials and can be safely deleted:')}\n")

        for user in orphaned_users:
            created_date = user['created'].strftime('%Y-%m-%d')
            click.echo(f"  \u2022 {user['username']} (created: {created_date})")

        click.echo()

        # Safety check: Never delete ACTIVE or AT RISK users
        unsafe_users = [u for u in phantoms if u['status'] in ['ACTIVE', 'AT RISK']]
        if unsafe_users and not force:
            click.echo(output.red(f"[WARNING] Found {len(unsafe_users)} users with active credentials."))
            click.echo(output.red("These will NOT be deleted for safety:"))
            for user in unsafe_users:
                click.echo(f"  \u2022 {user['username']} ({user['status']})")
            click.echo()

        # Confirmation prompt (unless forced or dry-run)
        if not dry_run and not force:
            if not click.confirm(click.style(f"Delete {len(orphaned_users)} orphaned phantom {'user' if len(orphaned_users) == 1 else 'users'}?", fg="yellow"), default=False):
                output.info("Cleanup cancelled by user.")
                return {'total': len(orphaned_users), 'deleted': 0, 'failed': 0}

        # Perform cleanup
        stats = {'total': len(orphaned_users), 'deleted': 0, 'failed': 0}

        click.echo()
        for user in orphaned_users:
            success = self.delete_phantom_user(user['username'], dry_run=dry_run)
            if success:
                stats['deleted'] += 1
            else:
                stats['failed'] += 1

        # Print summary
        click.echo(f"\n{output.bold('Cleanup Summary:')}")
        if dry_run:
            click.echo(f"  {output.yellow('Mode: DRY-RUN (simulation only)')}")
        click.echo(f"  Total orphaned users: {stats['total']}")
        deleted = stats['deleted']
        click.echo(f"  {output.green(f'Successfully deleted: {deleted}')}")
        if stats['failed'] > 0:
            failed = stats['failed']
            click.echo(f"  {output.red(f'Failed: {failed}')}")
        click.echo()

        return stats

    def revoke_key(self, username: str, dry_run: bool = False) -> bool:
        """Emergency revocation of Bedrock API key"""
        click.echo(f"\n{click.style('\u26a0\ufe0f  EMERGENCY KEY REVOCATION', fg='red', bold=True)}")
        click.echo(f"{output.yellow(f'Username: {username}')}\n")

        if dry_run:
            click.echo(output.yellow(f"[DRY-RUN] Would revoke all Bedrock API keys for: {username}"))
            return True

        if not click.confirm(click.style("This will immediately revoke all Bedrock API keys. Continue?", fg="yellow"), default=False):
            output.info("Revocation cancelled.")
            return False

        try:
            output.info("Applying inline deny policy...")

            policy_name = f"EmergencyRevocation-{int(datetime.now(timezone.utc).timestamp())}"
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DenyBedrockAPIKeyUsage",
                    "Effect": "Deny",
                    "Action": "bedrock:*",
                    "Resource": "*"
                }]
            }

            self.iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document)
            )
            output.success(f"Deny policy applied: {policy_name}")

            output.info("Deleting Bedrock API credentials...")

            creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName='bedrock.amazonaws.com'
            )['ServiceSpecificCredentials']

            for cred in creds:
                self.iam.delete_service_specific_credential(
                    UserName=username,
                    ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId']
                )
                output.success(f"Deleted credential: {cred['ServiceSpecificCredentialId']}")

            if not creds:
                output.info("No active credentials found")

            click.echo(f"\n{click.style('\u2713 Key revocation complete', fg='green', bold=True)}")
            output.info("Verify with CloudTrail monitoring (should see Access Denied)\n")
            return True

        except ClientError as e:
            output.error(f"Revocation failed: {e}")
            return False

    def generate_timeline(self, username: str, days: int = 7) -> None:
        """Generate CloudTrail timeline for phantom user activity"""
        click.echo(f"\n{output.bold('CloudTrail Timeline Analysis')}")
        click.echo(output.cyan(f"Username: {username}"))
        click.echo(output.cyan(f"Time range: Last {days} days") + "\n")

        try:
            start_time = datetime.now(timezone.utc) - timedelta(days=days)

            output.info("Querying CloudTrail (this may take a moment)...\n")

            response = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'Username',
                    'AttributeValue': username
                }],
                StartTime=start_time,
                MaxResults=50
            )

            events = response.get('Events', [])

            if not events:
                click.echo(output.yellow(f"No CloudTrail events found for {username}") + "\n")
                return

            event_word = "event" if len(events) == 1 else "events"
            click.echo(f"{output.bold(f'Found {len(events)} {event_word}:')}\n")

            for event in events:
                event_data = json.loads(event['CloudTrailEvent'])
                event_time = event['EventTime'].strftime('%Y-%m-%d %H:%M:%S UTC')
                event_name = event['EventName']
                event_source = event_data.get('eventSource', 'unknown')
                source_ip = event_data.get('sourceIPAddress', 'unknown')
                error_code = event_data.get('errorCode', '')

                line = f"{event_time} | {event_name:40} | {event_source:30} | IP: {source_ip}"
                if error_code:
                    click.echo(output.red(line))
                    click.echo(output.red(f"    \u2514\u2500 Error: {error_code}"))
                elif 'Delete' in event_name or 'Create' in event_name:
                    click.echo(output.yellow(line))
                else:
                    click.echo(output.cyan(line))

            output.success("Timeline generation complete")
            output.info("Review events above for suspicious activity\n")

        except ClientError as e:
            output.error(f"Failed to query CloudTrail: {e}\n")

    def generate_incident_report(self, username: str, output_file: Optional[str] = None) -> str:
        """Generate comprehensive incident report for phantom user"""
        report_lines = []

        report_lines.append("\u2550" * 80)
        report_lines.append("  AWS BEDROCK API KEY INCIDENT REPORT")
        report_lines.append("\u2550" * 80)
        report_lines.append("")
        report_lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        report_lines.append(f"Username: {username}")
        report_lines.append(f"Account ID: {self.account_id}")
        report_lines.append("")

        try:
            report_lines.append("PHANTOM USER DETAILS")
            report_lines.append("\u2500" * 80)
            user = self.iam.get_user(UserName=username)['User']
            report_lines.append(f"User ID: {user['UserId']}")
            report_lines.append(f"ARN: {user['Arn']}")
            report_lines.append(f"Created: {user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
            report_lines.append("")

            report_lines.append("BEDROCK API CREDENTIALS")
            report_lines.append("\u2500" * 80)
            creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName='bedrock.amazonaws.com'
            )['ServiceSpecificCredentials']

            if creds:
                for cred in creds:
                    report_lines.append(f"  ID: {cred['ServiceSpecificCredentialId']}")
                    report_lines.append(f"  Status: {cred['Status']}")
                    report_lines.append(f"  Created: {cred['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    report_lines.append("")
            else:
                report_lines.append("  No credentials found")
                report_lines.append("")

            report_lines.append("IAM ACCESS KEYS (ESCALATION CHECK)")
            report_lines.append("\u2500" * 80)
            access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']

            if access_keys:
                report_lines.append(f"  \u26a0\ufe0f  WARNING: {len(access_keys)} IAM access {'key' if len(access_keys) == 1 else 'keys'} found!")
                for key in access_keys:
                    report_lines.append(f"    Key ID: {key['AccessKeyId']}")
                    report_lines.append(f"    Status: {key['Status']}")
                    report_lines.append(f"    Created: {key['CreateDate'].strftime('%Y-%m-%d %H:%M:%S UTC')}")
                report_lines.append("")
            else:
                report_lines.append("  No access keys found")
                report_lines.append("")

            report_lines.append("ATTACHED POLICIES")
            report_lines.append("\u2500" * 80)
            attached = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            inline = self.iam.list_user_policies(UserName=username)['PolicyNames']

            if attached:
                report_lines.append("  Managed Policies:")
                for policy in attached:
                    report_lines.append(f"    - {policy['PolicyName']} ({policy['PolicyArn']})")
            if inline:
                report_lines.append("  Inline Policies:")
                for policy_name in inline:
                    report_lines.append(f"    - {policy_name}")
            if not attached and not inline:
                report_lines.append("  No policies attached")
            report_lines.append("")

        except ClientError as e:
            report_lines.append(f"ERROR: {e}")
            report_lines.append("")

        report_lines.append("\u2550" * 80)

        report_content = '\n'.join(report_lines)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report_content)
                output.success(f"Report saved to: {output_file}")
            except IOError as e:
                output.error(f"Failed to save report: {e}")
        else:
            click.echo(report_content)

        return report_content

    def report_header(self) -> str:
        """Generate report header with context for first-time users"""
        lines = []
        lines.append(f"\n{output.bold('─' * 60)}")
        lines.append(f"{output.bold(output.cyan('  bks — Bedrock Keys Security'))}")
        lines.append(f"{output.bold('─' * 60)}")
        lines.append("")
        lines.append("  AWS Bedrock API keys silently create IAM users")
        lines.append("  (BedrockAPIKey-*) with broad permissions that persist")
        lines.append("  indefinitely — even after the API key is deleted or expired.")
        lines.append("")
        lines.append("  These 'phantom users' are never automatically cleaned")
        lines.append("  up, creating an expanding attack surface.")
        lines.append("")
        lines.append(f"  Docs: {output.cyan('https://github.com/BeyondTrust/bedrock-keys-security')}")
        lines.append(f"{output.bold('─' * 60)}")
        lines.append("")
        lines.append(f"Account: {output.cyan(self.account_id)}")
        lines.append(f"Region:  {self.region}")
        return '\n'.join(lines)

    def _format_summary(self, phantoms: List[Dict], total: int, active: int, orphaned: int, at_risk: int) -> List[str]:
        """Format the summary block shared between report methods"""
        lines = []
        lines.append(f"\n{output.bold('Summary:')}")
        lines.append(f"  Total phantom users: {output.cyan(str(total))}")
        lines.append(f"  Active: {output.green(str(active))}")
        lines.append(f"  Orphaned: {output.yellow(str(orphaned))} (safe to cleanup)")
        lines.append(f"  At Risk: {output.red(str(at_risk))} (IAM access keys found)")

        if at_risk > 0:
            lines.append(f"\n{click.style('AT RISK users detected:', fg='red', bold=True)}")
            lines.append(output.red("These phantom users have IAM access keys (AKIA...) attached."))
            lines.append(output.red("These keys grant bedrock:*, iam:ListRoles, kms:DescribeKey,"))
            lines.append(output.red("ec2:Describe* and persist even if the API key is revoked. Investigate:"))
            for user in phantoms:
                if user['status'] == 'AT RISK':
                    n = user['active_access_keys']
                    key_label = "access key" if n == 1 else "access keys"
                    lines.append(output.red(f"    - {user['username']} ({n} {key_label})"))
            lines.append("")

        if orphaned > 0:
            lines.append(f"\n{output.yellow(f'{orphaned} orphaned phantom users can be cleaned up.')}")
            lines.append(output.yellow("These users have no active credentials and can be safely deleted to reduce your attack surface."))
            lines.append(output.yellow("Run: bks cleanup --dry-run  to preview, or cleanup to delete."))
            lines.append("")

        return lines

    def generate_table_report(self, phantoms: List[Dict]) -> str:
        """Generate formatted table report"""
        if not phantoms:
            return f"\n{output.green('No phantom users found in this account.')}\n"

        table_data = []
        for user in phantoms:
            created_date = user['created'].strftime('%Y-%m-%d')
            table_data.append([
                user['username'],
                created_date,
                user['active_bedrock_credentials'],
                user['active_access_keys'],
                output.style_status(user['status'])
            ])

        total = len(phantoms)
        active = len([u for u in phantoms if u['status'] == 'ACTIVE'])
        orphaned = len([u for u in phantoms if u['status'] == 'ORPHANED'])
        at_risk = len([u for u in phantoms if u['status'] == 'AT RISK'])

        lines = []

        headers = ['Username', 'Created', 'Active API Keys', 'Access Keys', 'Status']
        lines.append(tabulate(table_data, headers=headers, tablefmt='grid'))

        lines.extend(self._format_summary(phantoms, total, active, orphaned, at_risk))

        return '\n'.join(lines)

    def generate_json_report(self, phantoms: List[Dict]) -> str:
        """Generate JSON report"""
        for user in phantoms:
            if isinstance(user.get('created'), datetime):
                user['created'] = user['created'].isoformat()

            for cred in user.get('credential_details', []):
                if isinstance(cred.get('CreateDate'), datetime):
                    cred['CreateDate'] = cred['CreateDate'].isoformat()

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

        return json.dumps(report, indent=2)

    def generate_csv_report(self, phantoms: List[Dict], output_file: str):
        """Generate CSV report and save to file"""
        if not phantoms:
            click.echo(output.yellow("No phantom users to export."))
            return

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

                    writer.writerow(row)

            output.success(f"CSV report saved to: {output_file}")

        except IOError as e:
            output.error(f"Failed to write CSV file: {e}")
            sys.exit(1)
