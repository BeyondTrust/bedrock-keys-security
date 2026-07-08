"""Shared base for the per-service phantom user scanners.

Holds the methods that are identical or trivially parametrisable between
:class:`PhantomUserScanner` (Bedrock) and
:class:`ClaudePlatformPhantomScanner` (Claude Platform on AWS).

Subclasses parametrise the shared behaviour through class attributes:

============================================ =========================================
Attribute                                    Purpose
============================================ =========================================
``BACKING_USER_PREFIX``                      Filter for ``iam:ListUsers`` (e.g. ``BedrockAPIKey-``)
``SERVICE_SPECIFIC_CREDENTIAL_SERVICE``      Value passed to ``ServiceName=`` on the SSC IAM calls
``SERVICE_LABEL``                            Human label for log lines (e.g. ``Bedrock``)
``CREDENTIAL_COUNT_KEY``                     Output dict key for the total credential count
``ACTIVE_CREDENTIAL_COUNT_KEY``              Output dict key for the active credential count
``NOTABLE_MANAGED_POLICY_ARN``               Managed policy ARN to flag during ``check_policies`` (optional)
``NOTABLE_POLICY_FLAG_FIELD``                Output dict key for the boolean flag (optional)
============================================ =========================================

Genuinely service-specific behaviour stays on the subclasses:
``categorize_status``, ``generate_json_report``, ``generate_csv_report``,
``collect_incident_data`` and ``generate_incident_report`` (distinct output
schemas and narrative copy).

Revocation is shared here: ``revoke_key`` (long-term) is parametrised by
``REVOKE_DENY_ACTION`` / ``REVOKE_DENY_SID`` plus the ``_revoke_verify_hint``
hook, and ``revoke_short_term_key`` by the ``_decode_short_term`` and
``_short_term_issuer_not_found_hint`` hooks.

Scan / cleanup rendering is shared here and composed by the command layer:
``generate_timeline`` (anchors on a phantom username via ``Username=`` or on
the ``ASIA`` decoded from a short-term key via ``AccessKeyId=``, extracting the
calling identity and bearer-token signal generically), plus ``phantom_table``,
``summary_line``, ``summary_counts`` and ``section_label``. The combined
header, the per-service section and the AT RISK / ORPHANED remediation blocks
live once in ``commands/scan.py`` and are reused by ``cleanup``.
"""

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import click
from botocore.exceptions import ClientError
from tabulate import tabulate

from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.aws import AWSSession


# Per-user enrichment makes a handful of IAM API calls in parallel. Cap parallelism
# low enough to stay well under IAM throttling thresholds.
SCAN_MAX_WORKERS = 10


class BasePhantomScanner:
    """Shared surface for the Bedrock and Claude Platform phantom user scanners."""

    # Class attributes that subclasses override to parametrise the shared methods.
    BACKING_USER_PREFIX: str = ""
    SERVICE_SPECIFIC_CREDENTIAL_SERVICE: str = ""
    SERVICE_LABEL: str = ""
    CREDENTIAL_COUNT_KEY: str = "credentials"
    ACTIVE_CREDENTIAL_COUNT_KEY: str = "active_credentials"
    NOTABLE_MANAGED_POLICY_ARN: Optional[str] = None
    NOTABLE_POLICY_FLAG_FIELD: Optional[str] = None
    # Long-term revoke: the inline deny attached to the phantom user. Subclasses
    # set the service actions (e.g. ``["bedrock:*", "bedrock-mantle:*"]``) and the
    # statement Sid.
    REVOKE_DENY_ACTION: List[str] = []
    REVOKE_DENY_SID: str = ""
    # Status priority used by find_phantom_users for the result sort. Subclasses
    # can override (e.g. Claude Platform omits 'AT RISK').
    _STATUS_PRIORITY: Dict[str, int] = {'AT RISK': 0, 'ACTIVE': 1, 'ORPHANED': 2}

    def __init__(self, aws_session: AWSSession, verbose: bool = False):
        self.verbose = verbose
        self.aws_session = aws_session
        self.iam = aws_session.iam
        self.sts = aws_session.sts
        self.cloudtrail = aws_session.cloudtrail
        self.account_id = aws_session.account_id
        self.caller_arn = aws_session.caller_arn
        self.region = aws_session.region
        self.last_users_scanned = 0

    # ---- shared enumeration -------------------------------------------------

    def list_iam_users(self) -> List[Dict]:
        """Page through every IAM user once and return the raw account-wide list.

        Kept separate from :meth:`find_phantom_users` so a combined scan can
        enumerate ``iam:ListUsers`` a single time and hand the same list to both
        surface scanners (which differ only by ``BACKING_USER_PREFIX``), instead
        of paging the whole user directory once per surface.
        """
        users: List[Dict] = []
        paginator = self.iam.get_paginator('list_users')
        for page in paginator.paginate():
            users.extend(page['Users'])
        return users

    def find_phantom_users(self, users: Optional[List[Dict]] = None) -> List[Dict]:
        """List IAM users matching ``BACKING_USER_PREFIX`` and enrich each in parallel.

        ``users`` optionally supplies a pre-fetched account-wide IAM user list
        (from :meth:`list_iam_users`); when omitted the directory is paged here.
        A combined scan passes one shared list so ``iam:ListUsers`` runs once
        rather than once per surface scanner.
        """
        if self.verbose:
            output.info(f"Scanning for {self.SERVICE_LABEL} phantom IAM users...")

        if users is None:
            users = self.list_iam_users()
        self.last_users_scanned = len(users)

        bare_users: List[Dict] = []
        for user in users:
            username = user['UserName']
            if username.startswith(self.BACKING_USER_PREFIX):
                if self.verbose:
                    output.info(
                        f"Found {self.SERVICE_LABEL} phantom user: {username}"
                    )
                bare_users.append({
                    'username': username,
                    'user_id': user['UserId'],
                    'arn': user['Arn'],
                    'created': user['CreateDate'],
                    'path': user['Path'],
                })

        phantom_users: List[Dict] = []
        if bare_users:
            with ThreadPoolExecutor(max_workers=min(SCAN_MAX_WORKERS, len(bare_users))) as pool:
                futures = [pool.submit(self._enrich_user, u) for u in bare_users]
                for fut in as_completed(futures):
                    phantom_users.append(fut.result())

        phantom_users.sort(
            key=lambda u: (
                self._STATUS_PRIORITY.get(u.get('status'), 99),
                u['created'],
                u['username'],
            )
        )

        if self.verbose:
            output.success(
                f"Found {len(phantom_users)} {self.SERVICE_LABEL} phantom users"
            )

        return phantom_users

    def _enrich_user(self, user_data: Dict) -> Dict:
        """Run the per-user enrichment flow. Subclasses can override."""
        username = user_data['username']
        user_data.update(self.check_credentials(username))
        user_data.update(self.check_access_keys(username))
        user_data.update(self.check_policies(username))
        user_data['status'] = self.categorize_status(user_data)
        return user_data

    def categorize_status(self, user_data: Dict) -> str:
        """Subclasses implement the per-service categorization rules."""
        raise NotImplementedError

    # ---- shared IAM checks -------------------------------------------------

    def check_credentials(self, username: str) -> Dict:
        """List the service-specific credentials of the configured service.

        The output keys are parametrised so each scanner keeps its
        service-named fields (``bedrock_credentials`` vs
        ``claude_platform_credentials`` etc.).
        """
        try:
            response = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName=self.SERVICE_SPECIFIC_CREDENTIAL_SERVICE,
            )

            credentials = response.get('ServiceSpecificCredentials', [])
            active_creds = [c for c in credentials if c['Status'] == 'Active']

            if self.verbose and active_creds:
                key_word = "key" if len(active_creds) == 1 else "keys"
                output.warning(
                    f"{username}: {len(active_creds)} active {self.SERVICE_LABEL} API {key_word}"
                )

            return {
                self.CREDENTIAL_COUNT_KEY: len(credentials),
                self.ACTIVE_CREDENTIAL_COUNT_KEY: len(active_creds),
                'credential_details': active_creds,
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return {
                    self.CREDENTIAL_COUNT_KEY: 0,
                    self.ACTIVE_CREDENTIAL_COUNT_KEY: 0,
                    'credential_details': [],
                }
            output.warning(f"Could not check credentials for {username}: {e}")
            return {
                self.CREDENTIAL_COUNT_KEY: 0,
                self.ACTIVE_CREDENTIAL_COUNT_KEY: 0,
                'credential_details': [],
            }

    def check_access_keys(self, username: str) -> Dict:
        """Check for ``AKIA*`` IAM access keys. Identical signal on either service."""
        try:
            response = self.iam.list_access_keys(UserName=username)
            access_keys = response.get('AccessKeyMetadata', [])
            active_keys = [k for k in access_keys if k['Status'] == 'Active']

            if active_keys and self.verbose:
                key_word = "key" if len(active_keys) == 1 else "keys"
                output.high_risk(
                    f"{username}: {len(active_keys)} IAM access {key_word} found"
                )

            return {
                'access_keys': len(access_keys),
                'active_access_keys': len(active_keys),
                'access_key_ids': [k['AccessKeyId'] for k in active_keys],
            }

        except ClientError as e:
            output.warning(f"Could not check access keys for {username}: {e}")
            return {
                'access_keys': 0,
                'active_access_keys': 0,
                'access_key_ids': [],
            }

    def check_policies(self, username: str) -> Dict:
        """List attached and inline policies, optionally flagging a notable managed ARN."""
        try:
            attached = self.iam.list_attached_user_policies(UserName=username)
            attached_policies = attached.get('AttachedPolicies', [])

            inline = self.iam.list_user_policies(UserName=username)
            inline_policies = inline.get('PolicyNames', [])

            if self.verbose:
                policy_names = [p['PolicyName'] for p in attached_policies] + inline_policies
                if policy_names:
                    output.info(f"  [POLICY] {username}: {', '.join(policy_names)}")

            result: Dict = {
                'attached_policies': [p['PolicyName'] for p in attached_policies],
                'inline_policies': inline_policies,
                'total_policies': len(attached_policies) + len(inline_policies),
            }
            if self.NOTABLE_MANAGED_POLICY_ARN and self.NOTABLE_POLICY_FLAG_FIELD:
                attached_arns = {p['PolicyArn'] for p in attached_policies}
                result[self.NOTABLE_POLICY_FLAG_FIELD] = (
                    self.NOTABLE_MANAGED_POLICY_ARN in attached_arns
                )
            return result

        except ClientError as e:
            output.warning(f"Could not check policies for {username}: {e}")
            result = {
                'attached_policies': [],
                'inline_policies': [],
                'total_policies': 0,
            }
            if self.NOTABLE_MANAGED_POLICY_ARN and self.NOTABLE_POLICY_FLAG_FIELD:
                result[self.NOTABLE_POLICY_FLAG_FIELD] = False
            return result

    # ---- shared lifecycle (delete / cleanup) -------------------------------

    def delete_phantom_user(self, username: str, dry_run: bool = False) -> bool:
        """Delete a phantom IAM user and all associated resources.

        Parametrised by ``SERVICE_SPECIFIC_CREDENTIAL_SERVICE`` and
        ``SERVICE_LABEL`` so each scanner emits its own log lines while the
        deletion sequence stays shared.
        """
        try:
            if dry_run:
                click.echo(output.yellow(f"[DRY-RUN] Would delete user: {username}"))

                access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                if access_keys:
                    word = 'key' if len(access_keys) == 1 else 'keys'
                    click.echo(output.yellow(
                        f"  - Would delete {len(access_keys)} access {word}"
                    ))

                service_creds = self.iam.list_service_specific_credentials(
                    UserName=username,
                    ServiceName=self.SERVICE_SPECIFIC_CREDENTIAL_SERVICE,
                )['ServiceSpecificCredentials']
                if service_creds:
                    word = 'key' if len(service_creds) == 1 else 'keys'
                    click.echo(output.yellow(
                        f"  - Would delete {len(service_creds)} {self.SERVICE_LABEL} API {word}"
                    ))

                attached = self.iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
                if attached:
                    word = 'policy' if len(attached) == 1 else 'policies'
                    click.echo(output.yellow(
                        f"  - Would detach {len(attached)} managed {word}"
                    ))

                inline = self.iam.list_user_policies(UserName=username)['PolicyNames']
                if inline:
                    click.echo(output.yellow(
                        f"  - Would delete {len(inline)} inline polic(y/ies)"
                    ))

                return True

            if self.verbose:
                output.info(f"Deleting {self.SERVICE_LABEL} phantom user: {username}")

            access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                if self.verbose:
                    output.info(f"  Deleting access key: {key['AccessKeyId']}")
                self.iam.delete_access_key(UserName=username, AccessKeyId=key['AccessKeyId'])

            service_creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName=self.SERVICE_SPECIFIC_CREDENTIAL_SERVICE,
            )['ServiceSpecificCredentials']
            for cred in service_creds:
                if self.verbose:
                    output.info(
                        f"  Deleting {self.SERVICE_LABEL} API key: {cred['ServiceSpecificCredentialId']}"
                    )
                self.iam.delete_service_specific_credential(
                    UserName=username,
                    ServiceSpecificCredentialId=cred['ServiceSpecificCredentialId'],
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

            output.success(f"Deleted {self.SERVICE_LABEL} phantom user: {username}")
            return True

        except ClientError as e:
            output.error(f"Failed to delete {username}: {e}")
            return False

    def cleanup_orphaned_users(self, phantoms: List[Dict],
                                dry_run: bool = False, force: bool = False) -> Dict:
        """Clean up orphaned phantom users (no active credentials).

        Parametrised by ``SERVICE_LABEL`` and ``service`` tag. Subclasses
        that need different result-dict keys can post-process the result
        before returning to a caller.
        """
        orphaned_users = [u for u in phantoms if u['status'] == 'ORPHANED']
        unsafe_users = [u for u in phantoms if u['status'] in ('ACTIVE', 'AT RISK')]

        result: Dict = {
            "service": self._service_tag(),
            "dry_run": dry_run,
            "total_orphaned": len(orphaned_users),
            "deleted_users": [],
            "failed_users": [],
            "skipped_users": [u['username'] for u in unsafe_users],
        }

        if not orphaned_users:
            if not output._quiet_mode:
                click.echo(
                    f"\n{output.green(f'No orphaned {self.SERVICE_LABEL} phantom users found. Nothing to clean up.')}\n"
                )
            result.update({'total': 0, 'deleted': 0, 'failed': 0})
            return result

        n_orphaned = len(orphaned_users)
        if not output._quiet_mode:
            orphaned_word = "User" if n_orphaned == 1 else "Users"
            click.echo(
                f"\n{output.bold(f'Orphaned {self.SERVICE_LABEL} Phantom {orphaned_word} Found: {n_orphaned}')}"
            )
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
                click.echo(output.red(
                    f"⚠ Found {n_unsafe} {unsafe_word} with active credentials."
                ))
                click.echo(output.red("These will NOT be deleted for safety:"))
                for user in unsafe_users:
                    click.echo(f"  • {user['username']} ({user['status']})")
                click.echo()

        if not dry_run and not force:
            prompt = click.style(
                f"Delete {len(orphaned_users)} orphaned phantom "
                f"{'user' if len(orphaned_users) == 1 else 'users'}?",
                fg="yellow",
            )
            if not click.confirm(prompt, default=False):
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

    def _service_tag(self) -> str:
        """Service identifier used in JSON output. Subclasses override."""
        return self.SERVICE_LABEL.lower().replace(' ', '-')

    # ---- shared scan rendering helpers ------------------------------------

    def section_label(self) -> str:
        """Header for this service's block in a scan, e.g. ``Bedrock phantom users  (BedrockAPIKey-*)``."""
        return f"{self.SERVICE_LABEL} phantom users  ({self.BACKING_USER_PREFIX}*)"

    def summary_counts(self, phantoms: List[Dict]) -> Dict[str, int]:
        """Tally phantom statuses for the summary line."""
        return {
            'total': len(phantoms),
            'active': sum(1 for u in phantoms if u.get('status') == 'ACTIVE'),
            'orphaned': sum(1 for u in phantoms if u.get('status') == 'ORPHANED'),
            'at_risk': sum(1 for u in phantoms if u.get('status') == 'AT RISK'),
        }

    def summary_line(self, phantoms: List[Dict]) -> str:
        """One-line tally: ``11 phantom users  ·  2 at risk  ·  3 active  ·  6 orphaned``.

        ``at risk`` is omitted when zero (Claude Platform never emits it).
        """
        c = self.summary_counts(phantoms)
        n = c['total']
        parts = [f"{n} phantom user{'' if n == 1 else 's'}"]
        if c['at_risk']:
            parts.append(f"{c['at_risk']} at risk")
        parts.append(f"{c['active']} active")
        parts.append(f"{c['orphaned']} orphaned")
        return '  ·  '.join(parts)

    def phantom_table(self, phantoms: List[Dict]) -> str:
        """Render the phantom-user grid only (no summary). Shared across services.

        The ``Active API Keys`` column reads the per-service credential count
        (``ACTIVE_CREDENTIAL_COUNT_KEY``); every other column is identical on
        both surfaces.
        """
        if not phantoms:
            return f"\n{output.green(f'No {self.SERVICE_LABEL} phantom users found in this account.')}\n"

        table_data = []
        for user in phantoms:
            created_date = user['created'].strftime('%Y-%m-%d')
            table_data.append([
                user['username'],
                created_date,
                user.get(self.ACTIVE_CREDENTIAL_COUNT_KEY, 0),
                user.get('active_access_keys', 0),
                output.style_status(user['status']),
            ])
        headers = ['Username', 'Created', 'Active API Keys', 'Access Keys', 'Status']
        return tabulate(table_data, headers=headers, tablefmt='grid')

    # ---- shared CloudTrail timeline ---------------------------------------

    def generate_timeline(self, username: Optional[str] = None, days: int = 7,
                          all_regions: bool = False, max_events: int = 1000,
                          access_key_id: Optional[str] = None,
                          region_hint: Optional[str] = None) -> Dict:
        """Generate a CloudTrail timeline for a phantom user or a short-term key's ASIA.

        Two anchoring modes, symmetric across Bedrock and Claude Platform:

        - ``username`` (a phantom user, or the user decoded from a long-term
          key): ``Username=`` lookup. Picks up long-term API key use, IAM
          lifecycle events and, on Claude Platform, the
          ``sts:GetWebIdentityToken`` side channel.
        - ``access_key_id`` (the ``ASIA`` decoded offline from a short-term
          key): ``AccessKeyId=`` lookup. The ASIA is created server-side by AWS
          and that creation step is invisible in customer CloudTrail, but every
          *use* of the key lands as a default-logged management event
          (``InvokeModel`` / ``Converse`` on Bedrock; ``ListWorkspaces`` /
          ``GetWorkspace`` on Claude Platform) whose ``userIdentity`` is the
          operator that wielded the key.

        Each event row carries the calling identity (``actor``) plus the
        bearer-token signal (``call_with_bearer_token`` / ``bearer_token_type``)
        wherever CloudTrail records it. Single-region by default;
        ``all_regions=True`` searches every region with trail coverage.
        ``region_hint`` (the region a short-term key is signed for) targets the
        single-region lookup at that region instead of the configured one.
        """
        if not username and not access_key_id:
            raise ValueError(
                "generate_timeline requires either username or access_key_id"
            )

        if access_key_id:
            lookup_key, lookup_value = 'AccessKeyId', access_key_id
            subject_label, subject = 'Access key', access_key_id
        else:
            lookup_key, lookup_value = 'Username', username
            subject_label, subject = 'Username', username

        result: Dict = {
            "service": self._service_tag(),
            "username": username,
            "access_key_id": access_key_id,
            "lookup_attribute": lookup_key,
            "days": days,
            "all_regions": all_regions,
            "regions_searched": [],
            "trail_coverage": {},
            "events": [],
            "total_events": 0,
            "regions_with_activity": [],
        }

        if not output._quiet_mode:
            click.echo(f"\n{output.bold(f'CloudTrail Timeline Analysis ({self.SERVICE_LABEL})')}")
            click.echo(output.cyan(f"{subject_label + ':':<11} {subject}"))
            click.echo(output.cyan(f"{'Time range:':<11} Last {days} days"))

        start_time = datetime.now(timezone.utc) - timedelta(days=days)

        if all_regions:
            output.info("Discovering CloudTrail coverage...")
            coverage = self.discover_trail_coverage()
            result["trail_coverage"] = coverage
            if not coverage:
                output.warning(
                    "No CloudTrail trails found. Falling back to current region's 90-day event history."
                )
                regions = [region_hint or self.region]
            else:
                regions = sorted(coverage.keys())
                trail_names = sorted(set(coverage.values()))
                if not output._quiet_mode:
                    click.echo(output.cyan(
                        f"{'Regions:':<11} {len(regions)} covered by trail(s) {', '.join(trail_names)}"
                    ))
        else:
            regions = [region_hint or self.region]
            if not output._quiet_mode:
                click.echo(output.cyan(f"{'Regions:':<11} {regions[0]} (use --all-regions to search every region)"))

        result["regions_searched"] = regions

        if not output._quiet_mode:
            click.echo()
        output.info(
            f"Querying CloudTrail across {len(regions)} region(s) (this may take a moment)...\n"
        )

        all_events: List[Dict] = []
        if len(regions) == 1:
            all_events = self._lookup_events_in_region(
                regions[0], lookup_value, start_time, max_events, lookup_key=lookup_key
            )
        else:
            with ThreadPoolExecutor(max_workers=min(SCAN_MAX_WORKERS, len(regions))) as pool:
                futures = {
                    pool.submit(
                        self._lookup_events_in_region, r, lookup_value, start_time,
                        max_events, lookup_key,
                    ): r
                    for r in regions
                }
                for fut in as_completed(futures):
                    all_events.extend(fut.result())

        if not all_events:
            if not output._quiet_mode:
                click.echo(output.yellow(f"No CloudTrail events found for {subject}") + "\n")
            return result

        all_events.sort(key=lambda e: e['EventTime'])
        result["total_events"] = len(all_events)

        if not output._quiet_mode:
            event_word = "event" if len(all_events) == 1 else "events"
            n_events = len(all_events)
            click.echo(f"{output.bold(f'Found {n_events} {event_word}:')}\n")

        for event in all_events:
            event_data = json.loads(event['CloudTrailEvent'])
            event_time = event['EventTime'].astimezone(timezone.utc)
            event_name = event['EventName']
            event_source = event_data.get('eventSource', 'unknown')
            source_ip = event_data.get('sourceIPAddress', 'unknown')
            error_code = event_data.get('errorCode', '')
            region = event.get('_Region', self.region)
            user_agent = event_data.get('userAgent')

            req_params = event_data.get('requestParameters')
            add_data = event_data.get('additionalEventData')
            # callWithBearerToken lives under requestParameters on Claude Platform
            # and under additionalEventData on Bedrock; read both for symmetry.
            cwbt = None
            if isinstance(req_params, dict) and 'callWithBearerToken' in req_params:
                cwbt = req_params.get('callWithBearerToken')
            elif isinstance(add_data, dict) and 'callWithBearerToken' in add_data:
                cwbt = add_data.get('callWithBearerToken')
            key_type = req_params.get('bearerTokenType') if isinstance(req_params, dict) else None
            actor = self._extract_actor(event_data)

            result["events"].append({
                "event_time": event_time.isoformat(),
                "event_name": event_name,
                "event_source": event_source,
                "source_ip": source_ip,
                "error_code": error_code or None,
                "region": region,
                "user_agent": user_agent,
                "call_with_bearer_token": cwbt,
                "bearer_token_type": key_type,
                "actor": actor,
            })

            if not output._quiet_mode:
                event_time_str = event_time.strftime('%Y-%m-%d %H:%M:%S UTC')
                extra = ''
                if cwbt:
                    extra = '  bearer=true'
                    if key_type:
                        extra += f' type={key_type}'
                line = (
                    f"{event_time_str} | {region:14} | {event_name:32} | "
                    f"{event_source:38} | IP: {source_ip}{extra}"
                )
                if error_code:
                    click.echo(output.red(line))
                    click.echo(output.red(f"    Error: {error_code}"))
                elif 'Delete' in event_name or 'Create' in event_name:
                    click.echo(output.yellow(line))
                else:
                    click.echo(output.cyan(line))
                actor_arn = actor.get('arn')
                if actor_arn:
                    click.echo(f"    actor: {actor_arn}")

        region_tally = Counter(e.get('_Region', self.region) for e in all_events)
        result["regions_with_activity"] = sorted(region_tally.keys())

        if not output._quiet_mode and len(region_tally) > 1:
            click.echo(f"\n{output.bold('Region breakdown:')} {output.red('multi-region activity')}")
            for region, count in region_tally.most_common():
                click.echo(f"  {region:14} {count} events")

        output.success("Timeline generation complete")
        output.info("Review events above for suspicious activity\n")
        return result

    # ---- shared long-term revoke ------------------------------------------

    def _revoke_verify_hint(self) -> str:
        """Post-revocation verification hint. Subclasses override per service."""
        return (
            f"Verify with: bks scan should report {self.BACKING_USER_PREFIX}* "
            f"as ORPHANED.\n"
        )

    def revoke_key(self, username: str, dry_run: bool = False, force: bool = False) -> Dict:
        """Emergency long-term revocation of a phantom user's API key.

        Attaches an inline deny on ``REVOKE_DENY_ACTION``, deletes the
        service-specific credentials under ``SERVICE_SPECIFIC_CREDENTIAL_SERVICE``
        and disables any ``AKIA*`` access keys. The inline deny is defense in
        depth on top of deleting the credentials: it blocks any further service
        call even if a new credential were created on the same user before the
        operator can react.

        Shared across surfaces; only the deny action/Sid, the credential service
        and the per-service copy differ (the latter via ``SERVICE_LABEL`` and the
        ``_revoke_verify_hint`` hook). Returns a structured Dict:

            {
                "username": str, "service": str, "key_kind": "long-term",
                "dry_run": bool, "actions": [{"action": str, ..., "success": bool}],
                "success": bool, "cancelled"?: bool, "error"?: str,
            }
        """
        result: Dict = {
            "username": username,
            "service": self._service_tag(),
            "key_kind": "long-term",
            "dry_run": dry_run,
            "actions": [],
            "success": False,
        }

        if not output._quiet_mode:
            click.echo(
                f"\n{click.style(f'EMERGENCY KEY REVOCATION ({self.SERVICE_LABEL})', fg='red', bold=True)}"
            )
            click.echo(f"{output.yellow(f'Username: {username}')}\n")

        if dry_run:
            if not output._quiet_mode:
                click.echo(output.yellow(
                    f"[DRY-RUN] Would deny {', '.join(self.REVOKE_DENY_ACTION)}, delete {self.SERVICE_LABEL} "
                    f"service-specific credentials and disable IAM access keys for: {username}"
                ))
            result["success"] = True
            return result

        if not force and not click.confirm(
            click.style(
                f"This will immediately deny {', '.join(self.REVOKE_DENY_ACTION)}, delete {self.SERVICE_LABEL} "
                f"credentials and disable IAM access keys. Continue?",
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
                    "Sid": self.REVOKE_DENY_SID,
                    "Effect": "Deny",
                    "Action": self.REVOKE_DENY_ACTION,
                    "Resource": "*",
                }],
            }
            self.iam.put_user_policy(
                UserName=username,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
            )
            output.success(f"Deny policy applied: {policy_name}")
            result["actions"].append({
                "action": "deny_policy",
                "policy_name": policy_name,
                "success": True,
            })

            output.info(f"Deleting {self.SERVICE_LABEL} API credentials...")
            creds = self.iam.list_service_specific_credentials(
                UserName=username,
                ServiceName=self.SERVICE_SPECIFIC_CREDENTIAL_SERVICE,
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
                output.info(f"No active {self.SERVICE_LABEL} credentials found")

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
                click.echo(f"\n{click.style('Key revocation complete', fg='green', bold=True)}")
                output.info(self._revoke_verify_hint())
            result["success"] = True
            return result

        except ClientError as e:
            output.error(f"Revocation failed: {e}")
            result["error"] = str(e)
            return result

    # ---- shared short-term revoke -----------------------------------------

    def _decode_short_term(self, key: str) -> Dict:
        """Subclasses return the decoded short-term key dict (or {'error': ...})."""
        raise NotImplementedError

    def _short_term_issuer_not_found_hint(self) -> str:
        """Subclasses return the hint text emitted when CloudTrail finds no issuer."""
        return (
            "No CloudTrail events found for this access key. A short-term key's "
            "use is logged as management events keyed by this ASIA, so an empty "
            "result usually means it has not been used in this window. If the "
            "only use was an agent, knowledge base, flow or async call, those "
            "are CloudTrail data events and need a selector on the trail. Also "
            "try --all-regions or a longer --days window, and confirm the trail "
            "covers the key's signed region."
        )

    def _short_term_revoke_banner(self) -> str:
        """Subclasses can customise the header. Default uses ``SERVICE_LABEL``."""
        return f"EMERGENCY TOKEN REVOCATION ({self.SERVICE_LABEL} short-term)"

    def _echo_actor_identity(self, actor: Optional[Dict], issuer_arn: Optional[str] = None) -> None:
        """Print WHO used the key: the operator identity behind the bearer call.

        For an assumed-role session ``actor['arn']`` differs from ``issuer_arn``
        (the role) and carries the human session name, so it is the more useful
        attribution; for a plain IAM user the two coincide and the redundant
        line is suppressed.
        """
        if not actor:
            return
        arn = actor.get('arn')
        if arn and arn != issuer_arn:
            click.echo(output.cyan(f"  Key used by:       {arn}"))
        origin = []
        if actor.get('source_ip'):
            origin.append(f"IP {actor['source_ip']}")
        if actor.get('user_agent'):
            origin.append(f"UA {actor['user_agent']}")
        if origin:
            click.echo(output.cyan(f"  Call origin:       {'  '.join(origin)}"))
        if actor.get('on_behalf_of_user_id'):
            click.echo(output.cyan(f"  Identity Center:   user {actor['on_behalf_of_user_id']}"))

    def revoke_short_term_key(self, key: str, dry_run: bool = False,
                                force: bool = False) -> Dict:
        """Apply ``aws:TokenIssueTime`` deny on the principal that issued an STS short-term API key.

        Algorithm is identical across services; subclasses parametrise the
        decoder used to extract the embedded ASIA (``_decode_short_term``)
        and the hint emitted when CloudTrail returns no issuer
        (``_short_term_issuer_not_found_hint``).
        """
        result: Dict = {
            "service": self._service_tag(),
            "key_kind": "short-term",
            "dry_run": dry_run,
            "actions": [],
            "success": False,
        }

        if not output._quiet_mode:
            click.echo(
                f"\n{click.style(self._short_term_revoke_banner(), fg='red', bold=True)}"
            )

        decoded = self._decode_short_term(key)
        if 'error' in decoded:
            output.error(f"Could not decode key: {decoded['error']}")
            result["error"] = decoded['error']
            return result

        access_key_id = decoded.get('access_key_id', 'Unknown')
        account_id = decoded.get('account_id', 'Unknown')
        region = decoded.get('region', 'Unknown')
        result["access_key_id"] = access_key_id

        if not output._quiet_mode:
            click.echo(output.cyan(
                f"  Access key: {access_key_id}  account: {account_id}  region: {region}"
            ))

        if not access_key_id.startswith('ASIA'):
            output.error("Decoded access key isn't an STS temporary credential (expected ASIA*).")
            result["error"] = "not an STS temporary credential"
            return result

        output.info("Looking up the principal that used this key via CloudTrail...")
        issuer_arn, issuer_name, issuer_kind, actor = self._find_short_term_issuer(access_key_id)
        if not issuer_arn:
            output.error("Could not identify the principal that used this key in CloudTrail.")
            output.info(self._short_term_issuer_not_found_hint())
            result["error"] = "issuing principal not found in CloudTrail"
            return result

        result["issuer_arn"] = issuer_arn
        result["issuer_name"] = issuer_name
        result["issuer_kind"] = issuer_kind
        result["actor"] = actor

        if not output._quiet_mode:
            click.echo(output.cyan(
                f"  Issuing principal: {issuer_arn}  ({issuer_kind})"
            ))
            self._echo_actor_identity(actor, issuer_arn)

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

        if issuer_kind == 'root':
            output.error("This short-term key was used under the AWS account root identity.")
            output.info(
                "Root cannot be constrained with an IAM user or role policy. Rotate the root "
                "credentials, lock down root with MFA, or apply an SCP at the org level."
            )
            result["error"] = "root principal; not revocable via IAM policy"
            return result

        self_revoke = self._issuer_matches_caller(issuer_arn, issuer_kind)
        result["self_revoke"] = self_revoke
        if self_revoke and not output._quiet_mode:
            click.echo(output.red(
                "Self-revoke detected: this issuer is the same principal you are authenticated as. "
                "Applying the deny will kill this bks session and any concurrent sessions using the "
                "same role/user."
            ))

        if self_revoke and not force:
            output.error("Refusing to self-revoke without --force.")
            output.info("Re-run with --force if you really want to deny your own current session.")
            result["error"] = "self-revoke blocked without --force"
            return result

        if dry_run:
            if not output._quiet_mode:
                click.echo(output.yellow(
                    f"\n[DRY-RUN] Would apply aws:TokenIssueTime deny on {issuer_kind} '{issuer_name}'"
                ))
            result["success"] = True
            return result

        if not force and not click.confirm(
            click.style(
                f"This will deny ALL actions for sessions issued before now on "
                f"{issuer_kind} '{issuer_name}'. Continue?",
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
            output.success(
                f"Applied TokenIssueTime deny on {issuer_kind} '{issuer_name}': {policy_name}"
            )
            result["actions"].append({
                "action": "token_issue_time_deny",
                "policy_name": policy_name,
                "cutoff": cutoff,
                "success": True,
            })
            if not output._quiet_mode:
                click.echo(
                    f"\n{click.style('Short-term token revocation complete', fg='green', bold=True)}"
                )
                click.echo(output.cyan(
                    f"All sessions issued by {issuer_arn} before {cutoff} are now denied.\n"
                ))
            result["success"] = True
            return result
        except ClientError as e:
            output.error(f"Failed to apply deny policy: {e}")
            result["error"] = str(e)
            return result

    # ---- shared CloudTrail helpers (unchanged) -----------------------------

    def discover_trail_coverage(self) -> Dict[str, str]:
        """Map enabled AWS regions to the CloudTrail trail covering them."""
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

    def _lookup_events_in_region(self, region: str, lookup_value: str,
                                  start_time: datetime, max_events: int,
                                  lookup_key: str = 'Username') -> List[Dict]:
        """Page through CloudTrail ``lookup_events`` in one region, capped at ``max_events``.

        ``lookup_key`` selects the CloudTrail lookup attribute: ``Username`` (the
        default, anchors on a phantom user) or ``AccessKeyId`` (anchors on the
        ``ASIA`` decoded offline from a short-term key, to follow its use).
        """
        client = self.aws_session.session.client('cloudtrail', region_name=region)
        events: List[Dict] = []
        try:
            paginator = client.get_paginator('lookup_events')
            for page in paginator.paginate(
                LookupAttributes=[{'AttributeKey': lookup_key, 'AttributeValue': lookup_value}],
                StartTime=start_time,
                PaginationConfig={'MaxItems': max_events},
            ):
                for ev in page.get('Events', []):
                    ev['_Region'] = region
                    events.append(ev)
        except ClientError as e:
            output.warning(f"[{region}] CloudTrail lookup failed: {e}")
        return events

    @staticmethod
    def _extract_actor(event_data: Dict) -> Dict:
        """Pull the calling identity out of a CloudTrail event.

        Surfaces WHO made the call. For an SSO / Identity Center session the
        ``arn`` carries the human session name (e.g.
        ``...:assumed-role/AWSReservedSSO_.../user@corp.com``); ``session_issuer_arn``
        is the role that issued the session and ``on_behalf_of_user_id`` is the
        IAM Identity Center user behind it. On a short-term key's use event
        ``access_key_id`` is the same ``ASIA`` the key decodes to.
        """
        ui = event_data.get('userIdentity') or {}
        issuer = (ui.get('sessionContext') or {}).get('sessionIssuer') or {}
        on_behalf_of = ui.get('onBehalfOf') or {}
        return {
            'arn': ui.get('arn'),
            'type': ui.get('type'),
            'principal_id': ui.get('principalId'),
            'account_id': ui.get('accountId'),
            'access_key_id': ui.get('accessKeyId'),
            'session_issuer_arn': issuer.get('arn'),
            'on_behalf_of_user_id': on_behalf_of.get('userId'),
        }

    def _issuer_matches_caller(self, issuer_arn: str, issuer_kind: str) -> bool:
        """Return True when the issuer principal is the caller principal."""
        caller = self.caller_arn or ''
        issuer_leaf = issuer_arn.rsplit('/', 1)[-1]
        if issuer_kind == 'role' and ':assumed-role/' in caller:
            caller_role = caller.split(':assumed-role/', 1)[1].split('/', 1)[0]
            return caller_role == issuer_leaf
        if issuer_kind == 'user' and ':user/' in caller:
            caller_user = caller.rsplit('/', 1)[-1]
            return caller_user == issuer_leaf
        return False

    def _find_short_term_issuer(self, access_key_id: str) -> Tuple[
        Optional[str], Optional[str], Optional[str], Optional[Dict]
    ]:
        """Look up the principal behind an STS short-term key via its use events.

        Anchors on ``AccessKeyId=<ASIA>``. The ASIA is created server-side by
        AWS and that creation step is invisible, but its *use* surfaces as
        default-logged management events whose ``userIdentity.accessKeyId`` is
        this ASIA. Reads the ``sessionIssuer`` (the role that issued the
        session) or, when the caller was a plain IAM user, the user itself.

        Returns ``(arn, name, kind, actor)`` or ``(None, None, None, None)``
        when no usage events are found. ``actor`` is the full calling identity
        (the operator that wielded the key), augmented with the source IP and
        user agent of the event seen.
        """
        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            for page in paginator.paginate(
                LookupAttributes=[{'AttributeKey': 'AccessKeyId', 'AttributeValue': access_key_id}],
                PaginationConfig={'MaxItems': 5},
            ):
                for ev in page.get('Events', []):
                    ct = json.loads(ev['CloudTrailEvent'])
                    ui = ct.get('userIdentity', {}) or {}
                    actor = self._extract_actor(ct)
                    actor['source_ip'] = ct.get('sourceIPAddress')
                    actor['user_agent'] = ct.get('userAgent')

                    issuer = (ui.get('sessionContext', {}) or {}).get('sessionIssuer', {}) or {}
                    issuer_arn = issuer.get('arn')
                    if issuer_arn:
                        name = issuer.get('userName') or issuer_arn.rsplit('/', 1)[-1]
                        kind = 'role' if ':role/' in issuer_arn else 'user'
                        return issuer_arn, name, kind, actor

                    # No sessionIssuer: a plain IAM user (or root) used the key directly.
                    ui_arn = ui.get('arn')
                    if ui.get('type') == 'IAMUser' and ui_arn and ':user/' in ui_arn:
                        name = ui.get('userName') or ui_arn.rsplit('/', 1)[-1]
                        return ui_arn, name, 'user', actor

                    # Root used the key directly. Not revocable via an IAM
                    # user/role policy, but the operator must still see who it
                    # was instead of a misleading "issuer not found". Some root
                    # events omit userIdentity.arn, so fall back to the
                    # account-derived root ARN.
                    if ui.get('type') == 'Root':
                        root_arn = ui_arn or (
                            f"arn:aws:iam::{ui.get('accountId')}:root"
                            if ui.get('accountId') else None
                        )
                        if root_arn:
                            return root_arn, 'root', 'root', actor
        except ClientError as e:
            output.warning(f"CloudTrail lookup failed: {e}")
        return None, None, None, None
