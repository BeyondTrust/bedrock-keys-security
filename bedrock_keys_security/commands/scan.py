"""Scan command - discover phantom IAM users"""

import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import click
from botocore.exceptions import ClientError

from bedrock_keys_security.core.org import (
    DEFAULT_ORG_ROLE,
    OrgScanError,
    OrgScanner,
    format_org_table_report,
    org_csv_report,
    org_json_report,
)
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, apply_quiet_override, quiet_option


OUTPUT_DIR = Path("output")
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ACCOUNT_LIST_RE = re.compile(r"^\d{12}(,\d{12})*$")
_ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")


def build_output_path(command: str, account_id: str, ext: str, output_dir: Path = OUTPUT_DIR) -> Path:
    """Return output/bks-<command>-<account>-<UTC ts µs>.<ext>; create dir if missing.

    Non-12-digit `account_id` (e.g. path-traversal payload from a crafted ABSK
    key) collapses to `unknown` so the filename can't escape `output_dir`.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_account = account_id if _ACCOUNT_ID_RE.match(str(account_id)) else "unknown"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return output_dir / f"bks-{command}-{safe_account}-{ts}.{ext}"


def write_secure(path: Path, content: str) -> None:
    """Write text and chmod 0600 so JSON/CSV outputs aren't world-readable on shared hosts."""
    path.write_text(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _parse_account_list(value: Optional[str], flag_name: str) -> Optional[List[str]]:
    """Validate a comma-separated 12-digit account-id list. Empty → None."""
    if not value:
        return None
    if not _ACCOUNT_LIST_RE.match(value):
        raise click.BadParameter(
            f"{flag_name} must be a comma-separated list of 12-digit account IDs",
            param_hint=flag_name,
        )
    return value.split(",")


def _validate_role_name(value: Optional[str], flag_name: str) -> Optional[str]:
    """Validate an IAM role name against AWS spec. Empty → None."""
    if not value:
        return None
    if not _ROLE_NAME_RE.match(value):
        raise click.BadParameter(
            f"{flag_name} must be 1-64 chars from [A-Za-z0-9_+=,.@-]",
            param_hint=flag_name,
        )
    return value


@click.command()
@aws_options
@click.option('--json', 'output_json', is_flag=True,
              help='Save scan results as JSON to output/ directory')
@click.option('--csv', 'output_csv', is_flag=True,
              help='Save scan results as CSV to output/ directory')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose log output during scan')
@click.option('--org', 'org_mode', is_flag=True,
              help='Org-wide scan: AssumeRole into every active member account and aggregate. '
                   'Caller must run from the management account or a delegated admin.')
@click.option('--org-role', 'org_role', default=None, metavar='NAME',
              help=f'Cross-account role name to assume when --org is set '
                   f'(default: {DEFAULT_ORG_ROLE}).')
@click.option('--org-accounts', 'org_accounts', default=None, metavar='IDS',
              help='Comma-separated 12-digit account IDs. When set, --org scans only these.')
@click.option('--org-skip', 'org_skip', default=None, metavar='IDS',
              help='Comma-separated 12-digit account IDs to exclude from --org scan.')
@quiet_option
@click.pass_context
def scan(ctx, profile, region, output_json, output_csv, verbose,
         org_mode, org_role, org_accounts, org_skip, quiet_flag):
    """Scan for phantom IAM users (default command).

    Single-account by default. Pass --org to fan out across every ACTIVE
    member account in the organization via sts:AssumeRole.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    if verbose:
        ctx.obj.verbose = True

    if org_mode:
        _run_org_scan(
            ctx,
            org_role=_validate_role_name(org_role, "--org-role") or DEFAULT_ORG_ROLE,
            accounts_filter=_parse_account_list(org_accounts, "--org-accounts"),
            skip_accounts=_parse_account_list(org_skip, "--org-skip"),
            output_json=output_json,
            output_csv=output_csv,
        )
        return

    if org_role or org_accounts or org_skip:
        raise click.UsageError("--org-role / --org-accounts / --org-skip require --org")

    scanner = ctx.obj.scanner
    quiet = ctx.obj.quiet

    if not quiet:
        click.echo(scanner.report_header())

    start = time.monotonic()
    try:
        with output.spinner():
            phantoms = scanner.find_phantom_users()
    except ClientError as e:
        output.error(f"Failed to list IAM users: {e}")
        sys.exit(1)

    if not quiet:
        click.echo(scanner.generate_table_report(phantoms))

    saved = []
    if output_json:
        path = build_output_path("scan", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, scanner.generate_json_report(phantoms))
        saved.append(("JSON", path))

    if output_csv:
        path = build_output_path("scan", scanner.account_id, "csv", output_dir=ctx.obj.output_dir)
        scanner.generate_csv_report(phantoms, str(path))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        saved.append(("CSV", path))

    if not quiet:
        elapsed = time.monotonic() - start
        total_users = getattr(scanner, 'last_users_scanned', None)
        n_phantoms = len(phantoms)
        if total_users is not None:
            click.echo(
                f"\n{output.bold('Scan complete')}  "
                f"{total_users} IAM users  ·  {n_phantoms} phantom"
                f"{'s' if n_phantoms != 1 else ''}  ·  {elapsed:.1f}s"
            )

    for label, path in saved:
        click.echo(f"{label} saved: {path}")


def _run_org_scan(ctx, org_role, accounts_filter, skip_accounts, output_json, output_csv):
    """Fan out the scan across the organization and render the aggregate."""
    quiet = ctx.obj.quiet
    base_session = ctx.obj.scanner.aws_session
    org_scanner = OrgScanner(
        base_session=base_session,
        role_name=org_role,
        verbose=ctx.obj.verbose,
    )

    if not quiet:
        click.echo(
            f"\n{output.bold(output.cyan('bks org scan'))}  "
            f"BedrockAPIKey-* phantom users across the organization\n"
            f"Management account: {output.cyan(base_session.account_id)}  "
            f"Region: {base_session.region}\n"
        )

    start = time.monotonic()
    try:
        with output.spinner(label="Scanning org"):
            result = org_scanner.scan_all(
                accounts_filter=accounts_filter,
                skip_accounts=skip_accounts,
            )
    except OrgScanError as e:
        output.error(str(e))
        sys.exit(1)

    if not quiet:
        click.echo(format_org_table_report(result))

    saved = []
    if output_json:
        path = build_output_path("scan-org", base_session.account_id, "json",
                                 output_dir=ctx.obj.output_dir)
        write_secure(path, org_json_report(result))
        saved.append(("JSON", path))

    if output_csv:
        path = build_output_path("scan-org", base_session.account_id, "csv",
                                 output_dir=ctx.obj.output_dir)
        org_csv_report(result, str(path))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        saved.append(("CSV", path))

    if not quiet:
        elapsed = time.monotonic() - start
        meta = result["scan_metadata"]
        click.echo(
            f"\n{output.bold('Org scan complete')}  "
            f"{meta['accounts_scanned']}/{meta['accounts_total']} accounts  ·  "
            f"{result['summary']['total']} phantom"
            f"{'s' if result['summary']['total'] != 1 else ''}  ·  {elapsed:.1f}s"
        )

    for label, path in saved:
        click.echo(f"{label} saved: {path}")
