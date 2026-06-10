"""Cleanup command - delete orphaned phantom users"""

import json
import sys
import click
from botocore.exceptions import ClientError

from bedrock_keys_security.commands.scan import (
    SERVICE_CHOICES,
    _combined_header,
    _resolve_services,
    _service_section,
    build_output_path,
    write_secure,
)
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, apply_quiet_override, quiet_option


def _render_combined_cleanup(ctx, services, dry_run: bool, force: bool, output_json: bool) -> int:
    """Run cleanup over one or more services with the same shared chrome as scan.

    Emits one header, then per service a section (label, grid, one-line summary)
    followed by the interactive orphan deletion, then any saved-file paths,
    instead of repeating the banner and full table block per service. Returns
    the total count of failed deletions (plus any surface whose scan failed)
    across the services.

    The account-wide IAM user list is paged once up front and shared across
    surfaces, so the (destructive) per-surface deletion never runs between two
    separate iam:ListUsers calls. A per-surface scan failure is caught and
    reported rather than crashing after an earlier surface already deleted users.
    """
    quiet = ctx.obj.quiet

    if not quiet:
        _combined_header([s for s, _ in services], "cleanup")

    # One iam:ListUsers pass, fetched before any (destructive) deletion runs.
    try:
        with output.spinner():
            shared_users = services[0][0].list_iam_users() if services else []
    except ClientError as e:
        output.error(f"Failed to list IAM users: {e}")
        sys.exit(1)

    failed_total = 0
    saved = []
    for scanner, command_tag in services:
        try:
            with output.spinner():
                phantoms = scanner.find_phantom_users(users=shared_users)
        except ClientError as e:
            output.error(
                f"[{scanner.SERVICE_LABEL}] cleanup scan failed; skipping this surface: {e}"
            )
            failed_total += 1
            continue

        if not quiet:
            _service_section(scanner, phantoms)

        result = scanner.cleanup_orphaned_users(phantoms, dry_run=dry_run, force=force)
        failed_total += result['failed']

        if output_json:
            path = build_output_path(command_tag, scanner.account_id, "json",
                                     output_dir=ctx.obj.output_dir)
            write_secure(path, json.dumps(result, indent=2, default=str))
            saved.append(("JSON", path))

    for label, path in saved:
        click.echo(f"{label} saved: {path}")

    return failed_total


@click.command()
@aws_options
@click.option('--service', type=click.Choice(SERVICE_CHOICES), default=None,
              help='Which API key surface to clean. Default is "all" '
                   '(both scanners). Pass "bedrock" or "claude-platform" to '
                   'scope to a single surface.')
@click.option('--dry-run', is_flag=True, help='Simulate cleanup without deleting')
@click.option('--force', is_flag=True, help='Skip confirmation prompts (DANGEROUS)')
@click.option('--json', 'output_json', is_flag=True,
              help='Save cleanup result as JSON to output/ directory')
@quiet_option
@click.pass_context
def cleanup(ctx, profile, region, service, dry_run, force, output_json, quiet_flag):
    """Delete orphaned phantom IAM users (no active credentials).
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)

    if service is None:
        service = 'all'

    services = _resolve_services(ctx, service, 'cleanup')
    failed_total = _render_combined_cleanup(ctx, services, dry_run, force, output_json)

    sys.exit(0 if failed_total == 0 else 1)
