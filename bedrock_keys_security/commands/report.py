"""Report command - incident report generation"""

import click

from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, resolve_username


@click.command()
@aws_options
@click.argument('username_or_key')
@click.option('--output', 'output_file', default=None, metavar='FILE', help='Save report to file')
@click.pass_context
def report(ctx, profile, region, username_or_key, output_file):
    """Generate incident report for phantom user.

    Accepts either a phantom IAM username (BedrockAPIKey-xxxx) or a
    long-term ABSK key string.
    """
    apply_aws_overrides(ctx, profile, region)
    username = resolve_username(username_or_key)
    ctx.obj.scanner.generate_incident_report(username, output_file=output_file)
