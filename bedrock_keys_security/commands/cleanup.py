"""Cleanup command - delete orphaned phantom users"""

import sys
import click

from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides


@click.command()
@aws_options
@click.option('--dry-run', is_flag=True, help='Simulate cleanup without deleting')
@click.option('--force', is_flag=True, help='Skip confirmation prompts (DANGEROUS)')
@click.pass_context
def cleanup(ctx, profile, region, dry_run, force):
    """Delete orphaned phantom users"""
    apply_aws_overrides(ctx, profile, region)
    scanner = ctx.obj.scanner

    click.echo(scanner.report_header())
    with output.spinner():
        phantoms = scanner.find_phantom_users()
    click.echo(scanner.generate_table_report(phantoms))

    stats = scanner.cleanup_orphaned_users(phantoms, dry_run=dry_run, force=force)
    sys.exit(0 if stats['failed'] == 0 else 1)
