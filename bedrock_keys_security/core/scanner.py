"""AWS scanner for BedrockAPIKey-* phantom IAM users"""

import csv
import json
import sys
import click
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from tabulate import tabulate
from typing import Dict, List, Optional
from botocore.exceptions import ClientError

from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.aws import AWSSession

# Per-user enrichment fans out 3 IAM API calls (creds, access keys, policies).
# Cap parallelism low enough to stay well under IAM throttling thresholds.
SCAN_MAX_WORKERS = 10


def _json_default(obj):
    """Fallback serializer for json.dumps. Handles datetime fields returned by AWS APIs."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


_CSV_INJECTION_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _csv_safe(value):
    """Neutralize Excel/Sheets formula injection by prefixing dangerous cells with `'`.

    IAM allows `=` in usernames (charset `[\\w+=,.@-]`) so `BedrockAPIKey-=cmd|...`
    is technically a valid user. Without this guard, `bks scan --csv` would emit
    a row that triggers RCE in a SOC analyst's Excel on open.
    """
    if isinstance(value, str) and value and value[0] in _CSV_INJECTION_PREFIXES:
        return "'" + value
    return value


class PhantomUserScanner:
    """
    Scanner for BedrockAPIKey-* phantom IAM users
    """

    def __init__(self, aws_session: AWSSession, verbose: bool = False):
        self.verbose = verbose
        self.aws_session = aws_session
        self.iam = aws_session.iam
        self.sts = aws_session.sts
        self.cloudtrail = aws_session.cloudtrail
        self.account_id = aws_session.account_id
        self.caller_arn = aws_session.caller_arn
        self.region = aws_session.region

    def find_phantom_users(self) -> List[Dict]:
        """Find all BedrockAPIKey-* IAM users and enrich each one in parallel."""
        if self.verbose:
            output.info("Scanning for phantom IAM users...")

        bare_users: List[Dict] = []
        total_users_scanned = 0
        paginator = self.iam.get_paginator('list_users')
        for page in paginator.paginate():
            page_users = page['Users']
            total_users_scanned += len(page_users)
            for user in page_users:
                username = user['UserName']
                if username.startswith('BedrockAPIKey-'):
                    if self.verbose:
                        output.info(f"Found phantom user: {username}")
                    bare_users.append({
                        'username': username,
                        'user_id': user['UserId'],
                        'arn': user['Arn'],
                        'created': user['CreateDate'],
                        'path': user['Path'],
                    })
        self.last_users_scanned = total_users_scanned

        def enrich(user_data: Dict) -> Dict:
            username = user_data['username']
            user_data.update(self.check_credentials(username))
            user_data.update(self.check_access_keys(username))
            user_data.update(self.check_policies(username))
            user_data['status'] = self.categorize_status(user_data)
            return user_data

        phantom_users: List[Dict] = []
        if bare_users:
            with ThreadPoolExecutor(max_workers=min(SCAN_MAX_WORKERS, len(bare_users))) as pool:
                futures = [pool.submit(enrich, u) for u in bare_users]
                for fut in as_completed(futures):
                    phantom_users.append(fut.result())

        # AT RISK > ACTIVE > ORPHANED, then oldest first, then username for determinism.
        _STATUS_PRIORITY = {'AT RISK': 0, 'ACTIVE': 1, 'ORPHANED': 2}
        phantom_users.sort(
            key=lambda u: (
                _STATUS_PRIORITY.get(u.get('status'), 99),
                u['created'],
                u['username'],
            )
        )

        if self.verbose:
            output.success(f"Found {len(phantom_users)} phantom users")

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
        """Categorize user status: ACTIVE, ORPHANED or AT RISK"""
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

            access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if self.verbose:
                    output.info(f"  Deleting access key: {key['AccessKeyId']}")
                self.iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])

            service_creds = self.iam.list_service_specific_credentials(UserName=username)['ServiceSpecificCredentials']
            for cred in service_creds:
                if self.verbose:
                    output.info(f"  Deleting Bedrock API key: {cred['ServiceSpecificCredentialId']}")
                self.iam.delete_service_specific_credential(
                    UserName=username,
                    ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId']
                )

            attached = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            for policy in attached:
                if self.verbose:
                    output.info(f"  Detaching managed policy: {policy['PolicyName']}")
                self.iam.detach_user_policy(UserName=username, PolicyArn=policy['PolicyArn'])

            inline = self.iam.list_user_policies(UserName=username)['PolicyNames']
            for policy_name in inline:
                if self.verbose:
                    output.info(f"  Deleting inline policy: {policy_name}")
                self.iam.delete_user_policy(UserName=username, PolicyName=policy_name)

            if self.verbose:
                output.info(f"  Deleting IAM user: {username}")
            self.iam.delete_user(UserName=username)

            output.success(f"Deleted phantom user: {username}")
            return True

        except ClientError as e:
            output.error(f"Failed to delete {username}: {e}")
            return False

    def cleanup_orphaned_users(self, phantoms: List[Dict], dry_run: bool = False, force: bool = False) -> Dict:
        """Clean up orphaned phantom users (no active credentials).

        Returns a structured Dict suitable for JSON serialization:
            {
                "dry_run": bool,
                "total_orphaned": int,
                "deleted_users": [str, ...],
                "failed_users": [str, ...],
                "skipped_users": [str, ...],   # safety-skipped (ACTIVE / AT RISK)
                "deleted": int, "failed": int, "total": int   # legacy keys for callers
            }
        """
        orphaned_users = [u for u in phantoms if u['status'] == 'ORPHANED']
        unsafe_users = [u for u in phantoms if u['status'] in ('ACTIVE', 'AT RISK')]

        result: Dict = {
            "dry_run": dry_run,
            "total_orphaned": len(orphaned_users),
            "deleted_users": [],
            "failed_users": [],
            "skipped_users": [u['username'] for u in unsafe_users],
        }

        if not orphaned_users:
            if not output._quiet_mode:
                click.echo(f"\n{output.green('No orphaned phantom users found. Nothing to clean up.')}\n")
            result.update({'total': 0, 'deleted': 0, 'failed': 0})
            return result

        n_orphaned = len(orphaned_users)
        if not output._quiet_mode:
            orphaned_word = "User" if n_orphaned == 1 else "Users"
            click.echo(f"\n{output.bold(f'Orphaned Phantom {orphaned_word} Found: {n_orphaned}')}")
            unsafe_msg = (
                "This user has no active credentials and can be safely deleted:"
                if n_orphaned == 1
                else "The following users have no active credentials and can be safely deleted:"
            )
            click.echo(f"{output.yellow(unsafe_msg)}\n")

            for user in orphaned_users:
                created_date = user['created'].strftime('%Y-%m-%d')
                click.echo(f"  • {user['username']} (created: {created_date})")

            click.echo()

            if unsafe_users and not force:
                n_unsafe = len(unsafe_users)
                unsafe_word = "user" if n_unsafe == 1 else "users"
                click.echo(output.red(f"⚠ Found {n_unsafe} {unsafe_word} with active credentials."))
                click.echo(output.red("These will NOT be deleted for safety:"))
                for user in unsafe_users:
                    click.echo(f"  • {user['username']} ({user['status']})")
                click.echo()

        if not dry_run and not force:
            if not click.confirm(click.style(f"Delete {len(orphaned_users)} orphaned phantom {'user' if len(orphaned_users) == 1 else 'users'}?", fg="yellow"), default=False):
                output.info("Cleanup cancelled by user.")
                result.update({'total': len(orphaned_users), 'deleted': 0, 'failed': 0})
                return result

        if not output._quiet_mode:
            click.echo()
        for user in orphaned_users:
            success = self.delete_phantom_user(user['username'], dry_run=dry_run)
            if success:
                result['deleted_users'].append(user['username'])
            else:
                result['failed_users'].append(user['username'])

        if not output._quiet_mode:
            click.echo(f"\n{output.bold('Cleanup Summary:')}")
            if dry_run:
                click.echo(f"  {output.yellow('Mode: DRY-RUN (simulation only)')}")
            click.echo(f"  Total orphaned users: {len(orphaned_users)}")
            n_deleted = len(result['deleted_users'])
            click.echo(f"  {output.green(f'Successfully deleted: {n_deleted}')}")
            if result['failed_users']:
                n_failed = len(result['failed_users'])
                click.echo(f"  {output.red(f'Failed: {n_failed}')}")
            click.echo()

        result['total'] = len(orphaned_users)
        result['deleted'] = len(result['deleted_users'])
        result['failed'] = len(result['failed_users'])
        return result

    def revoke_key(self, username: str, dry_run: bool = False, force: bool = False) -> Dict:
        """Emergency revocation: deny Bedrock, delete service-specific creds, disable IAM access keys.

        Returns a structured Dict:
            {
                "username": str, "key_kind": "long-term", "dry_run": bool,
                "actions": [{"action": str, ..., "success": bool}, ...],
                "success": bool, "cancelled"?: bool, "error"?: str,
            }
        """
        result: Dict = {
            "username": username,
            "key_kind": "long-term",
            "dry_run": dry_run,
            "actions": [],
            "success": False,
        }

        if not output._quiet_mode:
            click.echo(f"\n{click.style('⚠️  EMERGENCY KEY REVOCATION', fg='red', bold=True)}")
            click.echo(f"{output.yellow(f'Username: {username}')}\n")

        if dry_run:
            if not output._quiet_mode:
                click.echo(output.yellow(f"[DRY-RUN] Would revoke all Bedrock API keys and disable IAM access keys for: {username}"))
            result["success"] = True
            return result

        if not force and not click.confirm(
            click.style(
                "This will immediately deny Bedrock, delete API keys and disable IAM access keys. Continue?",
                fg="yellow",
            ),
            default=False,
        ):
            output.info("Revocation cancelled.")
            result["cancelled"] = True
            return result

        try:
            output.info("Applying inline deny policy...")
            policy_name = f"EmergencyRevocation-{int(datetime.now(timezone.utc).timestamp())}"
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "DenyBedrockAPIKeyUsage",
                    "Effect": "Deny",
                    "Action": "bedrock:*",
                    "Resource": "*",
                }],
            }
            self.iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
            )
            output.success(f"Deny policy applied: {policy_name}")
            result["actions"].append({"action": "deny_policy", "policy_name": policy_name, "success": True})

            output.info("Deleting Bedrock API credentials...")
            creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName='bedrock.amazonaws.com',
            )['ServiceSpecificCredentials']

            for cred in creds:
                self.iam.delete_service_specific_credential(
                    UserName=username,
                    ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId'],
                )
                output.success(f"Deleted credential: {cred['ServiceSpecificCredentialId']}")
                result["actions"].append({
                    "action": "delete_ssc",
                    "credential_id": cred['ServiceSpecificCredentialId'],
                    "success": True,
                })

            if not creds:
                output.info("No active Bedrock credentials found")

            output.info("Disabling IAM access keys (AKIA*)...")
            access_keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
            disabled = 0
            for key in access_keys:
                if key['Status'] == 'Active':
                    self.iam.update_access_key(
                        UserName=username,
                        AccessKeyId=key['AccessKeyId'],
                        Status='Inactive',
                    )
                    output.success(f"Disabled access key: {key['AccessKeyId']}")
                    result["actions"].append({
                        "action": "disable_access_key",
                        "access_key_id": key['AccessKeyId'],
                        "success": True,
                    })
                    disabled += 1
            if not access_keys:
                output.info("No IAM access keys found")
            elif disabled == 0:
                output.info("All access keys already inactive")

            if not output._quiet_mode:
                click.echo(f"\n{click.style('✓ Key revocation complete', fg='green', bold=True)}")
                output.info(
                    "Verify: AWS_BEARER_TOKEN_BEDROCK=<key> aws bedrock list-foundation-models  "
                    "(expect AccessDenied)\n"
                )
            result["success"] = True
            return result

        except ClientError as e:
            output.error(f"Revocation failed: {e}")
            result["error"] = str(e)
            return result

    def _issuer_matches_caller(self, issuer_arn: str, issuer_kind: str) -> bool:
        """Return True when the issuer principal is the same one the caller authenticated as.

        Caller arn shapes:
            arn:aws:sts::A:assumed-role/ROLE/session-name
            arn:aws:iam::A:user/UserName
        Issuer arn shapes (from sessionIssuer):
            arn:aws:iam::A:role/ROLE
            arn:aws:iam::A:role/aws-reserved/sso.amazonaws.com/ROLE
            arn:aws:iam::A:user/UserName
        """
        caller = self.caller_arn or ''
        issuer_leaf = issuer_arn.rsplit('/', 1)[-1]
        if issuer_kind == 'role' and ':assumed-role/' in caller:
            caller_role = caller.split(':assumed-role/', 1)[1].split('/', 1)[0]
            return caller_role == issuer_leaf
        if issuer_kind == 'user' and ':user/' in caller:
            caller_user = caller.rsplit('/', 1)[-1]
            return caller_user == issuer_leaf
        return False

    def _find_short_term_issuer(self, access_key_id: str):
        """Look up the sessionIssuer (role or user) that minted an STS access key.

        Returns (arn, name, kind) or (None, None, None) when no usage events are found.
        """
        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            for page in paginator.paginate(
                LookupAttributes=[{'AttributeKey': 'AccessKeyId', 'AttributeValue': access_key_id}],
                PaginationConfig={'MaxItems': 5},
            ):
                for ev in page.get('Events', []):
                    ct = json.loads(ev['CloudTrailEvent'])
                    issuer = (ct.get('userIdentity', {}) or {}).get('sessionContext', {}).get('sessionIssuer', {}) or {}
                    arn = issuer.get('arn')
                    if not arn:
                        continue
                    name = issuer.get('userName') or arn.rsplit('/', 1)[-1]
                    kind = 'role' if ':role/' in arn else 'user'
                    return arn, name, kind
        except ClientError as e:
            output.warning(f"CloudTrail lookup failed: {e}")
        return None, None, None

    def revoke_short_term_key(self, key: str, dry_run: bool = False, force: bool = False) -> Dict:
        """Apply aws:TokenIssueTime deny on the principal that issued an STS bearer token.

        Refuses on SSO-managed roles (PutRolePolicy not allowed) and on self-revoke
        (would kill the caller's own session) unless --force is passed.

        Returns a structured Dict:
            {
                "key_kind": "short-term", "dry_run": bool, "actions": [...],
                "access_key_id"?: str, "issuer_arn"?: str, "issuer_name"?: str,
                "issuer_kind"?: str, "self_revoke"?: bool,
                "success": bool, "cancelled"?: bool, "error"?: str,
            }
        """
        from bedrock_keys_security.core.decoder import BedrockKeyDecoder

        result: Dict = {
            "key_kind": "short-term",
            "dry_run": dry_run,
            "actions": [],
            "success": False,
        }

        if not output._quiet_mode:
            click.echo(f"\n{click.style('⚠️  EMERGENCY TOKEN REVOCATION (short-term)', fg='red', bold=True)}")

        decoded = BedrockKeyDecoder.decode_short_term_key(key)
        if 'error' in decoded:
            output.error(f"Could not decode key: {decoded['error']}")
            result["error"] = decoded['error']
            return result

        access_key_id = decoded.get('access_key_id', 'Unknown')
        account_id = decoded.get('account_id', 'Unknown')
        region = decoded.get('region', 'Unknown')
        result["access_key_id"] = access_key_id

        if not output._quiet_mode:
            click.echo(output.cyan(f"  Access key: {access_key_id}  account: {account_id}  region: {region}"))

        if not access_key_id.startswith('ASIA'):
            output.error("Decoded access key isn't an STS temporary credential (expected ASIA*).")
            result["error"] = "not an STS temporary credential"
            return result

        output.info("Looking up issuing principal via CloudTrail...")
        issuer_arn, issuer_name, issuer_kind = self._find_short_term_issuer(access_key_id)
        if not issuer_arn:
            output.error("Could not identify issuing principal in CloudTrail.")
            output.info("No usage events found for this access key. The key may not have been used yet, "
                        "or coverage gaps exist. Use CloudTrail Lake / Athena with "
                        "responseElements.credentials.accessKeyId match to find the issuance event manually.")
            result["error"] = "issuing principal not found in CloudTrail"
            return result

        result["issuer_arn"] = issuer_arn
        result["issuer_name"] = issuer_name
        result["issuer_kind"] = issuer_kind

        if not output._quiet_mode:
            click.echo(output.cyan(f"  Issuing principal: {issuer_arn}  ({issuer_kind})"))

        if issuer_kind == 'role' and (
            'aws-reserved/sso.amazonaws.com' in issuer_arn
            or issuer_name.startswith('AWSReservedSSO_')
        ):
            output.error("Issuer is an AWS SSO / Identity Center-managed role.")
            output.info(
                "AWS does not allow attaching inline policies directly to SSO-managed roles. "
                "Revoke at the right layer instead: disable / unassign the user in IAM Identity "
                "Center, edit the permission set's inline policy or apply an SCP at the org level."
            )
            result["error"] = "SSO-managed role; PutRolePolicy not allowed"
            return result

        self_revoke = self._issuer_matches_caller(issuer_arn, issuer_kind)
        result["self_revoke"] = self_revoke
        if self_revoke and not output._quiet_mode:
            click.echo(output.red(
                "⚠️  Self-revoke detected: this issuer is the same principal you are authenticated as. "
                "Applying the deny will kill this bks session and any concurrent sessions using the "
                "same role/user."
            ))

        if dry_run:
            if not output._quiet_mode:
                click.echo(output.yellow(
                    f"\n[DRY-RUN] Would apply aws:TokenIssueTime deny on {issuer_kind} '{issuer_name}'"
                ))
            result["success"] = True
            return result

        if self_revoke and not force:
            output.error("Refusing to self-revoke without --force.")
            output.info("Re-run with --force if you really want to deny your own current session.")
            result["error"] = "self-revoke blocked without --force"
            return result

        if not force and not click.confirm(
            click.style(
                f"This will deny ALL actions for sessions issued before now on {issuer_kind} '{issuer_name}'. Continue?",
                fg="yellow",
            ),
            default=False,
        ):
            output.info("Revocation cancelled.")
            result["cancelled"] = True
            return result

        cutoff = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        policy_name = f"BKS-EmergencyTokenRevocation-{int(datetime.now(timezone.utc).timestamp())}"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyAllBeforeCutoff",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"DateLessThan": {"aws:TokenIssueTime": cutoff}},
            }],
        }

        try:
            if issuer_kind == 'role':
                self.iam.put_role_policy(
                    RoleName=issuer_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(policy_document),
                )
            else:
                self.iam.put_user_policy(
                    UserName=issuer_name,
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(policy_document),
                )
            output.success(f"Applied TokenIssueTime deny on {issuer_kind} '{issuer_name}': {policy_name}")
            result["actions"].append({
                "action": "token_issue_time_deny",
                "policy_name": policy_name,
                "cutoff": cutoff,
                "success": True,
            })
            if not output._quiet_mode:
                click.echo(f"\n{click.style('✓ Short-term token revocation complete', fg='green', bold=True)}")
                click.echo(output.cyan(f"All sessions issued by {issuer_arn} before {cutoff} are now denied.\n"))
            result["success"] = True
            return result
        except ClientError as e:
            output.error(f"Failed to apply deny policy: {e}")
            result["error"] = str(e)
            return result

    def discover_trail_coverage(self) -> Dict[str, str]:
        """Map enabled AWS regions to the CloudTrail trail covering them.

        Returns {region: trail_name}. Multi-region / org trails cover all enabled
        regions; single-region trails cover only their HomeRegion. Regions with
        no coverage are absent from the map.
        """
        try:
            trails = self.cloudtrail.describe_trails(includeShadowTrails=True).get('trailList', [])
        except ClientError as e:
            output.warning(f"Could not describe trails: {e}")
            return {}

        broad_trail = next(
            (t.get('Name') for t in trails
             if t.get('IsMultiRegionTrail') or t.get('IsOrganizationTrail')),
            None,
        )

        coverage: Dict[str, str] = {}

        if broad_trail:
            try:
                ec2 = self.aws_session.session.client('ec2', region_name=self.region)
                regions = ec2.describe_regions(AllRegions=False).get('Regions', [])
                for r in regions:
                    coverage[r['RegionName']] = broad_trail
            except ClientError as e:
                output.warning(f"Could not enumerate regions: {e}")
        else:
            for t in trails:
                home = t.get('HomeRegion')
                if home:
                    coverage[home] = t.get('Name', '<unnamed>')

        return coverage

    def _lookup_events_in_region(self, region: str, username: str, start_time: datetime, max_events: int) -> List[Dict]:
        """Page through CloudTrail lookup_events in one region, capped at max_events."""
        client = self.aws_session.session.client('cloudtrail', region_name=region)
        events: List[Dict] = []
        try:
            paginator = client.get_paginator('lookup_events')
            for page in paginator.paginate(
                LookupAttributes=[{'AttributeKey': 'Username', 'AttributeValue': username}],
                StartTime=start_time,
                PaginationConfig={'MaxItems': max_events},
            ):
                for ev in page.get('Events', []):
                    ev['_Region'] = region
                    events.append(ev)
        except ClientError as e:
            output.warning(f"[{region}] CloudTrail lookup failed: {e}")
        return events

    def generate_timeline(self, username: str, days: int = 7, all_regions: bool = False, max_events: int = 1000) -> Dict:
        """Generate CloudTrail timeline for phantom user activity.

        With all_regions=False (default), queries only the configured region.
        With all_regions=True, discovers CloudTrail coverage and iterates every
        region with an active trail, then merges results by EventTime. Useful
        for LLMjacking detection since Bedrock data-plane events are recorded
        in the region where InvokeModel was called.

        Returns a structured Dict:
            {
                "username": str, "days": int, "all_regions": bool,
                "regions_searched": [str], "trail_coverage": {str: str},
                "events": [{...}], "total_events": int,
                "regions_with_activity": [str],
            }
        """
        result: Dict = {
            "username": username,
            "days": days,
            "all_regions": all_regions,
            "regions_searched": [],
            "trail_coverage": {},
            "events": [],
            "total_events": 0,
            "regions_with_activity": [],
        }

        if not output._quiet_mode:
            click.echo(f"\n{output.bold('CloudTrail Timeline Analysis')}")
            click.echo(output.cyan(f"Username:   {username}"))
            click.echo(output.cyan(f"Time range: Last {days} days"))

        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        if all_regions:
            output.info("Discovering CloudTrail coverage...")
            coverage = self.discover_trail_coverage()
            result["trail_coverage"] = coverage
            if not coverage:
                output.warning("No CloudTrail trails found. Falling back to current region's 90-day event history.")
                regions = [self.region]
            else:
                regions = sorted(coverage.keys())
                trail_names = sorted(set(coverage.values()))
                if not output._quiet_mode:
                    click.echo(output.cyan(f"Regions:    {len(regions)} covered by trail(s) {', '.join(trail_names)}"))
        else:
            regions = [self.region]
            if not output._quiet_mode:
                click.echo(output.cyan(f"Regions:    {self.region} (use --all-regions to fan out)"))

        result["regions_searched"] = regions

        if not output._quiet_mode:
            click.echo()
        output.info(f"Querying CloudTrail across {len(regions)} region(s) (this may take a moment)...\n")

        all_events: List[Dict] = []
        if len(regions) == 1:
            all_events = self._lookup_events_in_region(regions[0], username, start_time, max_events)
        else:
            with ThreadPoolExecutor(max_workers=min(SCAN_MAX_WORKERS, len(regions))) as pool:
                futures = {
                    pool.submit(self._lookup_events_in_region, r, username, start_time, max_events): r
                    for r in regions
                }
                for fut in as_completed(futures):
                    all_events.extend(fut.result())

        if not all_events:
            if not output._quiet_mode:
                click.echo(output.yellow(f"No CloudTrail events found for {username}") + "\n")
            return result

        all_events.sort(key=lambda e: e['EventTime'])
        result["total_events"] = len(all_events)

        if not output._quiet_mode:
            event_word = "event" if len(all_events) == 1 else "events"
            n_events = len(all_events)
            click.echo(f"{output.bold(f'Found {n_events} {event_word}:')}\n")

        for event in all_events:
            event_data = json.loads(event['CloudTrailEvent'])
            event_time = event['EventTime']
            event_name = event['EventName']
            event_source = event_data.get('eventSource', 'unknown')
            source_ip = event_data.get('sourceIPAddress', 'unknown')
            error_code = event_data.get('errorCode', '')
            region = event.get('_Region', self.region)
            user_agent = event_data.get('userAgent')

            result["events"].append({
                "event_time": event_time.isoformat(),
                "event_name": event_name,
                "event_source": event_source,
                "source_ip": source_ip,
                "error_code": error_code or None,
                "region": region,
                "user_agent": user_agent,
            })

            if not output._quiet_mode:
                event_time_str = event_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                line = f"{event_time_str} | {region:14} | {event_name:36} | {event_source:30} | IP: {source_ip}"
                if error_code:
                    click.echo(output.red(line))
                    click.echo(output.red(f"    └─ Error: {error_code}"))
                elif 'Delete' in event_name or 'Create' in event_name:
                    click.echo(output.yellow(line))
                else:
                    click.echo(output.cyan(line))

        from collections import Counter
        region_tally = Counter(e.get('_Region', self.region) for e in all_events)
        result["regions_with_activity"] = sorted(region_tally.keys())

        if not output._quiet_mode and len(region_tally) > 1:
            click.echo(f"\n{output.bold('Region breakdown:')} {output.red('⚠ multi-region activity')}")
            for region, count in region_tally.most_common():
                click.echo(f"  {region:14} {count} events")

        output.success("Timeline generation complete")
        output.info("Review events above for suspicious activity\n")
        return result

    def collect_incident_data(self, username: str) -> Dict:
        """Side-effect-free fetch of all incident-report data for a phantom user.

        Returns a structured Dict suitable for JSON serialization or text formatting.
        Errors during IAM lookups are appended to result['errors'] rather than raised.
        """
        data: Dict = {
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
                "created": user['CreateDate'].isoformat(),
            }

            creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName='bedrock.amazonaws.com',
            )['ServiceSpecificCredentials']
            data["bedrock_credentials"] = [
                {
                    "credential_id": c['ServiceSpecificCredentialId'],
                    "status": c['Status'],
                    "created": c['CreateDate'].isoformat(),
                }
                for c in creds
            ]

            access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            data["iam_access_keys"] = [
                {
                    "access_key_id": k['AccessKeyId'],
                    "status": k['Status'],
                    "created": k['CreateDate'].isoformat(),
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

    def generate_incident_report(self, username: str, output_file: Optional[str] = None) -> str:
        """Generate human-readable incident report (text format) for phantom user.

        Backed by collect_incident_data; the JSON variant is exposed via
        the report --json flag in commands/report.py.
        """
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
                output.success(f"Report saved to: {output_file}")
            except IOError as e:
                output.error(f"Failed to save report: {e}")
        elif not output._quiet_mode:
            click.echo(report_content)

        return report_content

    def report_header(self) -> str:
        """Two-line banner: version + scope, account + region.

        The educational paragraph and docs link that previously lived
        here moved to ``bks --help`` so they show up once on first
        encounter rather than on every scan invocation. Commit hash
        stays available via ``bks --version`` for forensic context.
        """
        from bedrock_keys_security import __version__

        lines = [
            f"\n{output.bold(output.cyan(f'bks v{__version__}'))}  BedrockAPIKey-* phantom user scanner",
            f"Account: {output.cyan(self.account_id)}  Region: {self.region}",
        ]
        return '\n'.join(lines) + '\n'

    def _format_summary(self, phantoms: List[Dict], total: int, active: int, orphaned: int, at_risk: int) -> List[str]:
        """Format the summary block shared between report methods"""
        lines = []
        lines.append(f"\n{output.bold('Summary:')}")
        lines.append(f"  Total phantom users: {output.cyan(str(total))}")
        lines.append(f"  At Risk: {output.red(str(at_risk))} (IAM access keys found)")
        lines.append(f"  Active: {output.green(str(active))} (live Bedrock API keys)")
        lines.append(f"  Orphaned: {output.yellow(str(orphaned))} (safe to cleanup)")

        if at_risk > 0:
            user_word = "phantom user" if at_risk == 1 else "phantom users"
            header = click.style(
                f"⚠ AT RISK · {at_risk} {user_word} with persistent IAM credentials",
                fg='red',
                bold=True,
            )
            lines.append(f"\n{header}")
            for user in phantoms:
                if user['status'] == 'AT RISK':
                    n = user['active_access_keys']
                    key_label = "access key" if n == 1 else "access keys"
                    lines.append(output.red(f"   - {user['username']}  ({n} {key_label})"))
            lines.append("")
            lines.append(output.red("   These keys inherit Bedrock admin + IAM/VPC/KMS reconnaissance from"))
            lines.append(output.red("   AmazonBedrockLimitedAccess, and persist after Bedrock key revocation."))
            lines.append("")
            lines.append(f"   {output.cyan('→')} bks revoke-key {output.cyan('<username>')}   emergency containment")
            lines.append(f"   {output.cyan('→')} bks report     {output.cyan('<username>')}   forensic report")
            lines.append("")

        if orphaned > 0:
            user_word = "phantom user" if orphaned == 1 else "phantom users"
            header = click.style(
                f"▸ ORPHANED · {orphaned} {user_word} with no active credentials",
                fg='yellow',
                bold=True,
            )
            lines.append(f"\n{header}")
            lines.append(output.yellow("   These accumulate over time as privilege-escalation pivots. Cleanup"))
            lines.append(output.yellow("   shrinks the attack surface; no live workflow is affected."))
            lines.append("")
            lines.append(f"   {output.cyan('→')} bks cleanup --dry-run   preview deletions")
            lines.append(f"   {output.cyan('→')} bks cleanup             delete with confirmation")
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
