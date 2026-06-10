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
from bedrock_keys_security.core.scanner import PhantomUserScanner
from bedrock_keys_security.core.scanner_claude_platform import (
    ClaudePlatformPhantomScanner,
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


SERVICE_CHOICES = ('bedrock', 'claude-platform', 'all')


def _resolve_services(ctx, service: str, base_tag: str):
    """Ordered ``[(scanner, command_tag)]`` for a ``--service`` value.

    Single-service Bedrock uses the bare ``base_tag`` (e.g. ``scan``,
    ``cleanup``) to keep the original single-file output name; the combined run and Claude Platform disambiguate with a
    per-surface suffix. Shared by ``scan`` and ``cleanup`` so the two commands
    stay in lockstep.
    """
    services = []
    if service in ('bedrock', 'all'):
        services.append(
            (ctx.obj.scanner, base_tag if service == 'bedrock' else f'{base_tag}-bedrock')
        )
    if service in ('claude-platform', 'all'):
        services.append((ctx.obj.claude_platform_scanner, f'{base_tag}-claude-platform'))
    return services


def _combined_header(scanners, verb: str) -> None:
    """Emit one shared header naming every scanned surface.

    e.g. ``bks v1.3.0  phantom user scan: Bedrock + Claude Platform`` over a single
    ``Account: <id>  Region: <r>`` line, instead of one banner per service.
    """
    from bedrock_keys_security import __version__

    title = " + ".join(scanner.SERVICE_LABEL for scanner in scanners)
    first = scanners[0]
    click.echo(f"\n{output.bold(output.cyan(f'bks v{__version__}'))}  phantom user {verb}: {title}")
    click.echo(f"Account: {output.cyan(first.account_id)}  Region: {first.region}")


def _service_section(scanner, phantoms) -> None:
    """Emit one service's block: section label, grid, one-line summary."""
    click.echo(f"\n{output.bold(scanner.section_label())}")
    click.echo(scanner.phantom_table(phantoms))
    if phantoms:
        click.echo("  " + scanner.summary_line(phantoms))


def _render_combined_scan(ctx, services, output_json: bool, output_csv: bool) -> int:
    """Render a single-account scan over one or more services with shared chrome.

    ``services`` is an ordered list of ``(scanner, command_tag)``. Emits one
    header, then a per-service section (label + grid + one-line summary), then a
    single combined block of remediation hints, then one footer, so scanning
    both surfaces no longer repeats the banner, the IAM-user count or the
    "Scan complete" line. ``command_tag`` is the filename segment for JSON / CSV
    outputs so per-service files do not collide.

    The account-wide IAM user list is paged once and shared across surfaces
    (they differ only by prefix), and a per-surface failure is isolated
    (reported, that surface skipped) so one surface erroring does not discard
    the other's results or abort the whole run.

    Returns the total count of phantom users found across the services.
    """
    quiet = ctx.obj.quiet

    if not quiet:
        _combined_header([s for s, _ in services], "scan")

    start = time.monotonic()
    runs = []          # list of (scanner, phantoms)
    saved = []
    failed = []

    # One iam:ListUsers pass shared across surfaces, fetched up front.
    try:
        with output.spinner():
            shared_users = services[0][0].list_iam_users() if services else []
    except ClientError as e:
        output.error(f"Failed to list IAM users: {e}")
        sys.exit(1)
    total_users = len(shared_users)

    for scanner, command_tag in services:
        try:
            with output.spinner():
                phantoms = scanner.find_phantom_users(users=shared_users)
        except ClientError as e:
            output.error(f"[{scanner.SERVICE_LABEL}] scan failed: {e}")
            failed.append(scanner.SERVICE_LABEL)
            continue
        runs.append((scanner, phantoms))

        if not quiet:
            _service_section(scanner, phantoms)

        if output_json:
            path = build_output_path(command_tag, scanner.account_id, "json",
                                     output_dir=ctx.obj.output_dir)
            write_secure(path, scanner.generate_json_report(phantoms))
            saved.append(("JSON", path))

        if output_csv:
            path = build_output_path(command_tag, scanner.account_id, "csv",
                                     output_dir=ctx.obj.output_dir)
            scanner.generate_csv_report(phantoms, str(path))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            saved.append(("CSV", path))

    total_phantoms = sum(len(p) for _, p in runs)

    if not quiet:
        _echo_combined_actions(runs)
        elapsed = time.monotonic() - start
        if runs:
            phantom_word = "phantom user" if total_phantoms == 1 else "phantom users"
            click.echo(
                f"\n{output.bold('Scan complete')}  ·  "
                f"{total_users} IAM users  ·  {total_phantoms} {phantom_word}  ·  "
                f"{elapsed:.1f}s"
            )
        if failed:
            click.echo(output.red(
                f"{len(failed)} surface(s) failed to scan: {', '.join(failed)}"
            ))

    for label, path in saved:
        click.echo(f"{label} saved: {path}")

    if failed:
        sys.exit(1)
    return total_phantoms


def _echo_combined_actions(runs) -> None:
    """Emit the combined AT RISK / ORPHANED remediation blocks across services.

    AT RISK is a Bedrock-only status (persistent IAM access keys on a phantom);
    ORPHANED is tallied across every scanned service since ``bks cleanup``
    covers both surfaces by default. Both blocks use the same bullets and arrows
    so the two services read consistently.
    """
    at_risk_users = [u for _, phantoms in runs for u in phantoms if u.get('status') == 'AT RISK']
    orphaned_total = sum(1 for _, phantoms in runs for u in phantoms if u.get('status') == 'ORPHANED')

    if at_risk_users:
        n = len(at_risk_users)
        word = "user" if n == 1 else "users"
        click.echo(
            f"\n{click.style(f'⚠ AT RISK · {n} phantom {word} with persistent IAM credentials', fg='red', bold=True)}"
        )
        for u in at_risk_users:
            k = u.get('active_access_keys', 0)
            key_word = "key" if k == 1 else "keys"
            click.echo(output.red(f"   - {u['username']}  ({k} access {key_word})"))
        click.echo(output.red("   These inherit Bedrock admin + IAM/VPC/KMS reconnaissance from"))
        click.echo(output.red("   AmazonBedrockLimitedAccess, and persist after Bedrock API key revocation."))
        click.echo()
        click.echo(f"   {output.cyan('→')} bks revoke-key <username>   emergency containment")
        click.echo(f"   {output.cyan('→')} bks report     <username>   forensic report")

    if orphaned_total:
        word = "user" if orphaned_total == 1 else "users"
        click.echo(
            f"\n{click.style(f'▸ ORPHANED · {orphaned_total} phantom {word} with no active credentials', fg='yellow', bold=True)}"
        )
        click.echo(output.yellow("   These accumulate over time as privilege-escalation pivots. Cleanup"))
        click.echo(output.yellow("   shrinks the attack surface, and removing them breaks nothing."))
        click.echo()
        click.echo(f"   {output.cyan('→')} bks cleanup --dry-run   preview deletions")
        click.echo(f"   {output.cyan('→')} bks cleanup             delete with confirmation")


@click.command()
@aws_options
@click.option('--service', type=click.Choice(SERVICE_CHOICES), default=None,
              help='Which API key surface to scan. Default is "all" '
                   '(both scanners). Pass "bedrock" or "claude-platform" to '
                   'scope to a single surface. Honoured for both '
                   'single-account and --org scans.')
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
def scan(ctx, profile, region, service, output_json, output_csv, verbose,
         org_mode, org_role, org_accounts, org_skip, quiet_flag):
    """Scan for phantom IAM users (default command)."""
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    if verbose:
        ctx.obj.verbose = True

    if org_mode:
        resolved_org_service = service if service is not None else 'all'
        _run_org_scans(
            ctx,
            org_role=_validate_role_name(org_role, "--org-role") or DEFAULT_ORG_ROLE,
            accounts_filter=_parse_account_list(org_accounts, "--org-accounts"),
            skip_accounts=_parse_account_list(org_skip, "--org-skip"),
            output_json=output_json,
            output_csv=output_csv,
            service_choices=_org_services_to_run(resolved_org_service),
            combined_run=resolved_org_service == 'all',
        )
        return

    if org_role or org_accounts or org_skip:
        raise click.UsageError("--org-role / --org-accounts / --org-skip require --org")

    if service is None:
        service = 'all'

    services = _resolve_services(ctx, service, 'scan')
    _render_combined_scan(ctx, services, output_json=output_json, output_csv=output_csv)


def _org_services_to_run(service: str) -> List[str]:
    """Translate the --service flag into the ordered list of org scans to run."""
    if service == 'all':
        return ['bedrock', 'claude-platform']
    return [service]


_ORG_SCANNER_CLASSES = {
    'bedrock': PhantomUserScanner,
    'claude-platform': ClaudePlatformPhantomScanner,
}

def _run_org_scans(ctx, org_role, accounts_filter, skip_accounts, output_json, output_csv,
                   service_choices, combined_run: bool = False):
    """Fan the org scan across one or more surfaces with shared chrome.

    Prints one banner naming the surfaces and one management-account line, then
    a per-surface aggregate table (each carrying its own ``Org scan (<surface>)``
    heading from ``format_org_table_report``), then one footer, instead of
    repeating the banner and footer once per surface. ``combined_run`` keeps the
    per-surface output-file names distinct (``scan-org-bedrock`` /
    ``scan-org-claude-platform``) so they do not collide.
    """
    from bedrock_keys_security import __version__

    quiet = ctx.obj.quiet
    base_session = ctx.obj.scanner.aws_session

    if not quiet:
        title = " + ".join(_ORG_SCANNER_CLASSES[s].SERVICE_LABEL for s in service_choices)
        click.echo(
            f"\n{output.bold(output.cyan(f'bks v{__version__}'))}  "
            f"org scan: {title}  (across the organization)\n"
            f"Management account: {output.cyan(base_session.account_id)}  "
            f"Region: {base_session.region}"
        )

    start = time.monotonic()
    results = []
    saved = []
    failed = []
    for service_choice in service_choices:
        result, service_saved = _run_org_scan_service(
            ctx, org_role, accounts_filter, skip_accounts,
            output_json, output_csv, service_choice, combined_run,
        )
        if result is None:
            failed.append(service_choice)
            continue
        results.append(result)
        saved.extend(service_saved)

    if not quiet and results:
        elapsed = time.monotonic() - start
        meta = results[0]["scan_metadata"]   # account counts are identical per surface
        total_phantoms = sum(r["summary"]["total"] for r in results)
        phantom_word = "phantom user" if total_phantoms == 1 else "phantom users"
        click.echo(
            f"\n{output.bold('Org scan complete')}  "
            f"{meta['accounts_scanned']}/{meta['accounts_total']} accounts  ·  "
            f"{total_phantoms} {phantom_word}  ·  {elapsed:.1f}s"
        )

    for label, path in saved:
        click.echo(f"{label} saved: {path}")

    if failed:
        sys.exit(1)


def _run_org_scan_service(ctx, org_role, accounts_filter, skip_accounts, output_json,
                          output_csv, service_choice: str, combined_run: bool):
    """Run the org scan for one surface: scan_all, render its table, save files.

    Returns ``(result, saved)`` where ``saved`` is a list of ``(label, path)``
    for the orchestrator to echo after the shared footer. Does not print the
    outer banner or footer; ``_run_org_scans`` owns those.
    """
    quiet = ctx.obj.quiet
    base_session = ctx.obj.scanner.aws_session
    scanner_class = _ORG_SCANNER_CLASSES[service_choice]
    org_scanner = OrgScanner(
        base_session=base_session,
        role_name=org_role,
        verbose=ctx.obj.verbose,
        scanner_class=scanner_class,
    )

    try:
        with output.spinner(label=f"Scanning org ({scanner_class.SERVICE_LABEL})"):
            result = org_scanner.scan_all(
                accounts_filter=accounts_filter,
                skip_accounts=skip_accounts,
            )
    except OrgScanError as e:
        output.error(f"[{scanner_class.SERVICE_LABEL}] org scan failed: {e}")
        return None, []

    if not quiet:
        click.echo("\n" + format_org_table_report(result, scanner_class=scanner_class))

    if combined_run or service_choice != 'bedrock':
        command_tag = f"scan-org-{service_choice}"
    else:
        command_tag = "scan-org"  # bare name for the single org output file

    saved = []
    if output_json:
        path = build_output_path(command_tag, base_session.account_id, "json",
                                 output_dir=ctx.obj.output_dir)
        write_secure(path, org_json_report(result))
        saved.append(("JSON", path))

    if output_csv:
        path = build_output_path(command_tag, base_session.account_id, "csv",
                                 output_dir=ctx.obj.output_dir)
        org_csv_report(result, str(path), scanner_class=scanner_class)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        saved.append(("CSV", path))

    return result, saved
