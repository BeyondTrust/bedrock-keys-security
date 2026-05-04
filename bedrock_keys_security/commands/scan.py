"""Scan command - discover phantom IAM users"""

import time

import click

from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides


@click.command()
@aws_options
@click.option('--json', 'output_json', is_flag=True, help='Output results as JSON')
@click.option('--csv', 'csv_file', default=None, metavar='FILE', help='Export results to CSV file')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose log output during scan')
@click.pass_context
def scan(ctx, profile, region, output_json, csv_file, verbose):
    """Scan for phantom IAM users (default command)"""
    apply_aws_overrides(ctx, profile, region)
    if verbose:
        ctx.obj.verbose = True

    scanner = ctx.obj.scanner

    if not output_json:
        click.echo(scanner.report_header())

    start = time.monotonic()
    if output_json:
        phantoms = scanner.find_phantom_users()
        click.echo(scanner.generate_json_report(phantoms))
        return

    with output.spinner():
        phantoms = scanner.find_phantom_users()
    click.echo(scanner.generate_table_report(phantoms))
    if csv_file:
        scanner.generate_csv_report(phantoms, csv_file)

    elapsed = time.monotonic() - start
    total_users = getattr(scanner, 'last_users_scanned', None)
    n_phantoms = len(phantoms)
    if total_users is not None:
        click.echo(
            f"\n{output.bold('Scan complete')}  "
            f"{total_users} IAM users  ·  {n_phantoms} phantom"
            f"{'s' if n_phantoms != 1 else ''}  ·  {elapsed:.1f}s"
        )
