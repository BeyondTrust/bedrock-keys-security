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
        """Find all IAM users starting with 'BedrockAPIKey-' and enrich them in parallel"""
        if self.verbose:
            output.info("Scanning for phantom IAM users...")

        # Phase 1: list users (paginated, sequential, single API call stream)
        bare_users: List[Dict] = []
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
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
        except ClientError as e:
            output.error(f"Failed to list IAM users: {e}")
            sys.exit(1)

        # Phase 2: enrich each user with 3 IAM calls in parallel.
        # boto3 clients are thread-safe at the request level (each request
        # gets its own underlying connection from the pool).
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

        # Preserve the list_users ordering (helpful for stable diffs across runs)
        phantom_users.sort(key=lambda u: u['username'])

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

    def revoke_key(self, username: str, dry_run: bool = False, force: bool = False) -> bool:
        """Emergency revocation: deny Bedrock, delete service-specific creds, disable IAM access keys"""
        click.echo(f"\n{click.style('\u26a0\ufe0f  EMERGENCY KEY REVOCATION', fg='red', bold=True)}")
        click.echo(f"{output.yellow(f'Username: {username}')}\n")

        if dry_run:
            click.echo(output.yellow(f"[DRY-RUN] Would revoke all Bedrock API keys and disable IAM access keys for: {username}"))
            return True

        if not force and not click.confirm(
            click.style(
                "This will immediately deny Bedrock, delete API keys, and disable IAM access keys. Continue?",
                fg="yellow",
            ),
            default=False,
        ):
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
                    disabled += 1
            if not access_keys:
                output.info("No IAM access keys found")
            elif disabled == 0:
                output.info("All access keys already inactive")

            click.echo(f"\n{click.style('\u2713 Key revocation complete', fg='green', bold=True)}")
            output.info("Verify with CloudTrail monitoring (should see Access Denied)\n")
            return True

        except ClientError as e:
            output.error(f"Revocation failed: {e}")
            return False

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
        """Look up the sessionIssuer (role or user) that minted a given STS access key.

        CloudTrail lookup-events filters by AccessKeyId match the events made BY that
        access key, not the issuance event. That is exactly what we need: every usage
        event carries userIdentity.sessionContext.sessionIssuer.arn pointing back at
        the principal that called sts:AssumeRole / GetSessionToken / etc.

        Returns (arn, name, kind) where kind is 'role' or 'user', or (None, None, None)
        if no events were found or no sessionIssuer was attached (e.g. the leaked key
        was never used).
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

    def revoke_short_term_key(self, key: str, dry_run: bool = False, force: bool = False) -> bool:
        """Revoke a short-term Bedrock API key by applying aws:TokenIssueTime deny on the issuing principal.

        Short-term keys are STS bearer tokens. The credential itself can't be deleted
        (the SSC delete API doesn't apply); the only IR move is to deny every session
        issued before now on the principal that minted the token.

        Two guards before the policy is applied:
        - If the issuer is an AWS SSO / Identity Center-managed role
          (path includes aws-reserved/sso.amazonaws.com or name starts with
          AWSReservedSSO_), AWS does not allow PutRolePolicy on it. Refused
          here with a pointer to the right knob (Identity Center permission
          set / SCP).
        - If the issuer is the same principal the caller is currently
          authenticated as, applying the deny would lock the caller out of
          their own session (and any concurrent ones). Refused unless the
          caller passes --force.
        """
        from bedrock_keys_security.core.decoder import BedrockKeyDecoder

        click.echo(f"\n{click.style('⚠️  EMERGENCY TOKEN REVOCATION (short-term)', fg='red', bold=True)}")

        decoded = BedrockKeyDecoder.decode_short_term_key(key)
        if 'error' in decoded:
            output.error(f"Could not decode key: {decoded['error']}")
            return False

        access_key_id = decoded.get('access_key_id', 'Unknown')
        account_id = decoded.get('account_id', 'Unknown')
        region = decoded.get('region', 'Unknown')

        click.echo(output.cyan(f"  Access key: {access_key_id}  account: {account_id}  region: {region}"))

        if not access_key_id.startswith('ASIA'):
            output.error("Decoded access key isn't an STS temporary credential (expected ASIA*).")
            return False

        output.info("Looking up issuing principal via CloudTrail...")
        issuer_arn, issuer_name, issuer_kind = self._find_short_term_issuer(access_key_id)
        if not issuer_arn:
            output.error("Could not identify issuing principal in CloudTrail.")
            output.info("No usage events found for this access key. The key may not have been used yet, "
                        "or coverage gaps exist. Use CloudTrail Lake / Athena with "
                        "responseElements.credentials.accessKeyId match to find the issuance event manually.")
            return False

        click.echo(output.cyan(f"  Issuing principal: {issuer_arn}  ({issuer_kind})"))

        # Guard 1: SSO-managed roles cannot accept PutRolePolicy
        if issuer_kind == 'role' and (
            'aws-reserved/sso.amazonaws.com' in issuer_arn
            or issuer_name.startswith('AWSReservedSSO_')
        ):
            output.error("Issuer is an AWS SSO / Identity Center-managed role.")
            output.info(
                "AWS does not allow attaching inline policies directly to SSO-managed roles. "
                "Revoke at the right layer instead: disable / unassign the user in IAM Identity "
                "Center, edit the permission set's inline policy, or apply an SCP at the org level."
            )
            return False

        # Guard 2: self-revoke would lock the caller out of their own session
        self_revoke = self._issuer_matches_caller(issuer_arn, issuer_kind)
        if self_revoke:
            click.echo(output.red(
                "⚠️  Self-revoke detected: this issuer is the same principal you are authenticated as. "
                "Applying the deny will kill this bks session and any concurrent sessions using the "
                "same role/user."
            ))

        if dry_run:
            click.echo(output.yellow(
                f"\n[DRY-RUN] Would apply aws:TokenIssueTime deny on {issuer_kind} '{issuer_name}'"
            ))
            return True

        if self_revoke and not force:
            output.error("Refusing to self-revoke without --force.")
            output.info("Re-run with --force if you really want to deny your own current session.")
            return False

        if not force and not click.confirm(
            click.style(
                f"This will deny ALL actions for sessions issued before now on {issuer_kind} '{issuer_name}'. Continue?",
                fg="yellow",
            ),
            default=False,
        ):
            output.info("Revocation cancelled.")
            return False

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
            click.echo(f"\n{click.style('✓ Short-term token revocation complete', fg='green', bold=True)}")
            click.echo(output.cyan(f"All sessions issued by {issuer_arn} before {cutoff} are now denied.\n"))
            return True
        except ClientError as e:
            output.error(f"Failed to apply deny policy: {e}")
            return False

    def discover_trail_coverage(self) -> Dict[str, str]:
        """Map enabled AWS regions to the CloudTrail trail covering them.

        Returns {region: trail_name}. Multi-region or organization trails
        cover all enabled regions; single-region trails cover only their
        HomeRegion. Regions with no coverage are absent from the map.

        For full trail metadata (IsMultiRegionTrail, IsOrganizationTrail,
        HomeRegion, plus trails from other regions whose shadow lives here)
        we use cloudtrail:DescribeTrails. The API does not expose a
        paginator (no NextToken in the response shape), so list_trails +
        get_trail per ARN would be required to true-paginate. In practice
        an account rarely has more than a handful of trails and the AWS
        API returns the full list in a single response; we accept that
        contract here. If your org runs hundreds of trails per account,
        consider migrating to list_trails + get_trail.
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

    def generate_timeline(self, username: str, days: int = 7, all_regions: bool = False, max_events: int = 1000) -> None:
        """Generate CloudTrail timeline for phantom user activity.

        With all_regions=False (default), queries only the configured region.
        With all_regions=True, discovers CloudTrail coverage and iterates every
        region with an active trail, then merges results by EventTime. Useful
        for LLMjacking detection since Bedrock data-plane events are recorded
        in the region where InvokeModel was called.
        """
        click.echo(f"\n{output.bold('CloudTrail Timeline Analysis')}")
        click.echo(output.cyan(f"Username:   {username}"))
        click.echo(output.cyan(f"Time range: Last {days} days"))

        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        if all_regions:
            output.info("Discovering CloudTrail coverage...")
            coverage = self.discover_trail_coverage()
            if not coverage:
                output.warning("No CloudTrail trails found. Falling back to current region's 90-day event history.")
                regions = [self.region]
            else:
                regions = sorted(coverage.keys())
                trail_names = sorted(set(coverage.values()))
                click.echo(output.cyan(f"Regions:    {len(regions)} covered by trail(s) {', '.join(trail_names)}"))
        else:
            regions = [self.region]
            click.echo(output.cyan(f"Regions:    {self.region} (use --all-regions to fan out)"))
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
            click.echo(output.yellow(f"No CloudTrail events found for {username}") + "\n")
            return

        all_events.sort(key=lambda e: e['EventTime'])

        event_word = "event" if len(all_events) == 1 else "events"
        click.echo(f"{output.bold(f'Found {len(all_events)} {event_word}:')}\n")

        for event in all_events:
            event_data = json.loads(event['CloudTrailEvent'])
            event_time = event['EventTime'].strftime('%Y-%m-%d %H:%M:%S UTC')
            event_name = event['EventName']
            event_source = event_data.get('eventSource', 'unknown')
            source_ip = event_data.get('sourceIPAddress', 'unknown')
            error_code = event_data.get('errorCode', '')
            region = event.get('_Region', self.region)

            line = f"{event_time} | {region:14} | {event_name:36} | {event_source:30} | IP: {source_ip}"
            if error_code:
                click.echo(output.red(line))
                click.echo(output.red(f"    \u2514\u2500 Error: {error_code}"))
            elif 'Delete' in event_name or 'Create' in event_name:
                click.echo(output.yellow(line))
            else:
                click.echo(output.cyan(line))

        # Per-region tally \u2014 surfaces LLMjacking fan-out at a glance
        from collections import Counter
        region_tally = Counter(e.get('_Region', self.region) for e in all_events)
        if len(region_tally) > 1:
            click.echo(f"\n{output.bold('Region breakdown:')} {output.red('\u26a0 multi-region activity')}")
            for region, count in region_tally.most_common():
                click.echo(f"  {region:14} {count} events")

        output.success("Timeline generation complete")
        output.info("Review events above for suspicious activity\n")

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
        lines.append(f"{output.bold(output.cyan('  bks: Bedrock Keys Security'))}")
        lines.append(f"{output.bold('─' * 60)}")
        lines.append("")
        lines.append("  Scans AWS accounts for phantom IAM users")
        lines.append("  (BedrockAPIKey-*) created silently by Bedrock")
        lines.append("  API keys. They outlive the key and inherit")
        lines.append("  admin-level Bedrock + IAM/EC2/KMS permissions.")
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
            lines.append(output.red("These phantom users have IAM access keys (AKIA...) attached. Through the"))
            lines.append(output.red("AmazonBedrockLimitedAccess policy these keys inherit 47 bedrock: actions"))
            lines.append(output.red("(full Create/Delete/Update/Invoke lifecycle including DeleteGuardrail,"))
            lines.append(output.red("DeleteCustomModel, DeleteProvisionedModelThroughput) plus cross-service"))
            lines.append(output.red("reconnaissance: iam:ListRoles, ec2:DescribeVpcs, ec2:DescribeSubnets,"))
            lines.append(output.red("ec2:DescribeSecurityGroups, kms:DescribeKey. They persist even if the"))
            lines.append(output.red("API key is revoked. Investigate:"))
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
