"""Timeline command - CloudTrail timeline generation"""

import click

from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides


@click.command()
@aws_options
@click.argument('username')
@click.option('--days', type=int, default=7, help='Days to look back (default: 7)')
@click.pass_context
def timeline(ctx, profile, region, username, days):
    """Generate CloudTrail timeline for phantom user"""
    apply_aws_overrides(ctx, profile, region)
    ctx.obj.scanner.generate_timeline(username, days=days)
