"""Report command - incident report generation"""

import click

from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides


@click.command()
@aws_options
@click.argument('username')
@click.option('--output', 'output_file', default=None, metavar='FILE', help='Save report to file')
@click.pass_context
def report(ctx, profile, region, username, output_file):
    """Generate incident report for phantom user"""
    apply_aws_overrides(ctx, profile, region)
    ctx.obj.scanner.generate_incident_report(username, output_file=output_file)
