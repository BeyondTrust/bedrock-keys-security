"""Timeline command - CloudTrail timeline generation"""

import json
import click

from bedrock_keys_security.commands.scan import build_output_path, write_secure
from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.core.decoder_claude_platform import (
    ClaudePlatformKeyDecoder,
)
from bedrock_keys_security.utils.cli import (
    apply_aws_overrides,
    apply_quiet_override,
    aws_options,
    quiet_option,
    resolve_username,
    select_scanner,
)


def _decode_short_term_asia(decoder, key, label):
    """Decode a short-term key offline to its embedded ASIA and signed region.

    Returns ``(access_key_id, region_or_None)``; raises ClickException on a bad
    decode or when the key does not yield an STS access key.
    """
    decoded = decoder.decode_short_term_key(key)
    if 'error' in decoded:
        raise click.ClickException(
            f"Could not decode {label} short-term key: {decoded['error']}"
        )
    asia = decoded.get('access_key_id')
    if not asia or not asia.startswith('ASIA'):
        raise click.ClickException(
            f"Decoded {label} short-term key did not yield an STS access key (ASIA*)."
        )
    region = decoded.get('region')
    return asia, (region if region and region != 'Unknown' else None)


@click.command()
@aws_options
@click.argument('username_or_key')
@click.option('--days', type=int, default=7, help='Days to look back (default: 7)')
@click.option('--all-regions', is_flag=True,
              help='Search every region with CloudTrail coverage. Recommended for '
                   'short-term keys and Bedrock data-plane events, which are recorded in the '
                   'region where the call ran, not the home region.')
@click.option('--max-events', type=int, default=1000,
              help='Cap total events returned per region (default: 1000)')
@click.option('--json', 'output_json', is_flag=True,
              help='Save timeline result as JSON to output/ directory')
@quiet_option
@click.pass_context
def timeline(ctx, profile, region, username_or_key, days, all_regions, max_events, output_json, quiet_flag):
    """Generate a CloudTrail timeline for a phantom user or an API key.

    Accepts a phantom IAM username, a long-term key or a short-term key. A
    username or long-term key tracks the phantom user's activity; a short-term
    key is decoded to the STS key inside it, and the timeline shows who used it.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)

    if username_or_key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
        asia, key_region = _decode_short_term_asia(BedrockKeyDecoder, username_or_key, "Bedrock")
        scanner = ctx.obj.scanner
        result = scanner.generate_timeline(
            access_key_id=asia, days=days, all_regions=all_regions,
            max_events=max_events, region_hint=key_region,
        )
    elif username_or_key.startswith(ClaudePlatformKeyDecoder.SHORT_TERM_PREFIX):
        asia, key_region = _decode_short_term_asia(
            ClaudePlatformKeyDecoder, username_or_key, "Claude Platform"
        )
        scanner = ctx.obj.claude_platform_scanner
        result = scanner.generate_timeline(
            access_key_id=asia, days=days, all_regions=all_regions,
            max_events=max_events, region_hint=key_region,
        )
    else:
        username = resolve_username(username_or_key)
        scanner = select_scanner(ctx, username)
        result = scanner.generate_timeline(
            username, days=days, all_regions=all_regions, max_events=max_events,
        )

    if output_json:
        path = build_output_path("timeline", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, json.dumps(result, indent=2, default=str))
        click.echo(f"JSON saved: {path}")
