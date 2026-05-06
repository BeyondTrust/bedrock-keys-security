"""Cleanup command - delete orphaned phantom users"""

import json
import sys
import click

from bedrock_keys_security.commands.scan import build_output_path, write_secure
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, apply_quiet_override, quiet_option


@click.command()
@aws_options
@click.option('--dry-run', is_flag=True, help='Simulate cleanup without deleting')
@click.option('--force', is_flag=True, help='Skip confirmation prompts (DANGEROUS)')
@click.option('--json', 'output_json', is_flag=True,
              help='Save cleanup result as JSON to output/ directory')
@quiet_option
@click.pass_context
def cleanup(ctx, profile, region, dry_run, force, output_json, quiet_flag):
    """Delete orphaned phantom users"""
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    scanner = ctx.obj.scanner
    quiet = ctx.obj.quiet

    if not quiet:
        click.echo(scanner.report_header())
    with output.spinner():
        phantoms = scanner.find_phantom_users()
    if not quiet:
        click.echo(scanner.generate_table_report(phantoms))

    result = scanner.cleanup_orphaned_users(phantoms, dry_run=dry_run, force=force)

    if output_json:
        path = build_output_path("cleanup", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, json.dumps(result, indent=2, default=str))
        click.echo(f"JSON saved: {path}")

    sys.exit(0 if result['failed'] == 0 else 1)
