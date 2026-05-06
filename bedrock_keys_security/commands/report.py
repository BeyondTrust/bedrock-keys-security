"""Report command - incident report generation"""

import click

from bedrock_keys_security.utils.cli import (
    apply_aws_overrides,
    apply_quiet_override,
    aws_options,
    quiet_option,
    resolve_username,
)


@click.command()
@aws_options
@click.argument('username_or_key')
@click.option('--output', 'output_file', default=None, metavar='FILE', help='Save report to file')
@quiet_option
@click.pass_context
def report(ctx, profile, region, username_or_key, output_file, quiet_flag):
    """Generate incident report for phantom user.

    Accepts either a phantom IAM username (BedrockAPIKey-xxxx) or a
    long-term ABSK key string.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    username = resolve_username(username_or_key)
    ctx.obj.scanner.generate_incident_report(username, output_file=output_file)
