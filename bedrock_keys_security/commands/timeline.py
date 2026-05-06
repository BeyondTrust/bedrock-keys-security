"""Timeline command - CloudTrail timeline generation"""

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
@click.option('--days', type=int, default=7, help='Days to look back (default: 7)')
@click.option('--all-regions', is_flag=True,
              help='Fan out across every region with CloudTrail coverage. Recommended for Bedrock '
                   'data-plane events, which are recorded in the region where InvokeModel was called.')
@click.option('--max-events', type=int, default=1000,
              help='Cap total events returned per region (default: 1000)')
@quiet_option
@click.pass_context
def timeline(ctx, profile, region, username_or_key, days, all_regions, max_events, quiet_flag):
    """Generate CloudTrail timeline for phantom user.

    Accepts either a phantom IAM username (BedrockAPIKey-xxxx) or a
    long-term ABSK key string.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    username = resolve_username(username_or_key)
    ctx.obj.scanner.generate_timeline(
        username,
        days=days,
        all_regions=all_regions,
        max_events=max_events,
    )
