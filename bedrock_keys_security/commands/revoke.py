"""Revoke-key command - emergency key revocation"""

import json
import sys
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


@click.command('revoke-key')
@aws_options
@click.argument('username_or_key')
@click.option('--dry-run', is_flag=True, help='Simulate revocation without executing')
@click.option('--force', is_flag=True, help='Skip confirmation prompt (DANGEROUS)')
@click.option('--json', 'output_json', is_flag=True,
              help='Save revocation result as JSON to output/ directory')
@quiet_option
@click.pass_context
def revoke_key(ctx, profile, region, username_or_key, dry_run, force, output_json, quiet_flag):
    """Emergency revocation of a Bedrock or Claude Platform API key.

    Accepts a phantom IAM username, a long-term key or a short-term key.
    A username or long-term key revokes the phantom user's keys; short-term
    keys are traced through CloudTrail to deny the principal that used them.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)

    if username_or_key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
        scanner = ctx.obj.scanner
        result = scanner.revoke_short_term_key(username_or_key, dry_run=dry_run, force=force)
    elif username_or_key.startswith(ClaudePlatformKeyDecoder.SHORT_TERM_PREFIX):
        scanner = ctx.obj.claude_platform_scanner
        result = scanner.revoke_short_term_key(username_or_key, dry_run=dry_run, force=force)
    else:
        username = resolve_username(username_or_key)
        scanner = select_scanner(ctx, username)
        result = scanner.revoke_key(username, dry_run=dry_run, force=force)

    if output_json:
        path = build_output_path("revoke", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, json.dumps(result, indent=2, default=str))
        click.echo(f"JSON saved: {path}")

    sys.exit(0 if result['success'] else 1)
