"""Report command - incident report generation"""

import json
import click

from bedrock_keys_security.commands.scan import build_output_path, write_secure
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
@click.option('--output', 'output_file', default=None, metavar='FILE',
              help='Save text report to FILE')
@click.option('--json', 'output_json', is_flag=True,
              help='Save report data as JSON to output/ directory')
@quiet_option
@click.pass_context
def report(ctx, profile, region, username_or_key, output_file, output_json, quiet_flag):
    """Generate incident report for phantom user.

    Accepts either a phantom IAM username (BedrockAPIKey-xxxx) or a
    long-term ABSK key string.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    username = resolve_username(username_or_key)
    scanner = ctx.obj.scanner

    if output_json:
        data = scanner.collect_incident_data(username)
        path = build_output_path("report", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, json.dumps(data, indent=2, default=str))
        click.echo(f"JSON saved: {path}")
        if output_file:
            scanner.generate_incident_report(username, output_file=output_file)
    else:
        scanner.generate_incident_report(username, output_file=output_file)
