"""Revoke-key command - emergency key revocation"""

import json
import sys
import click

from bedrock_keys_security.commands.scan import build_output_path, write_secure
from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.utils.cli import (
    apply_aws_overrides,
    apply_quiet_override,
    aws_options,
    quiet_option,
    resolve_username,
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
    """Emergency revocation of Bedrock API key.

    Accepts:
    - A phantom IAM username (BedrockAPIKey-xxxx): runs the long-term flow
      (deny policy + delete SSCs + disable AKIAs).
    - A long-term ABSK key string: decoded offline to its phantom username,
      then the same long-term flow.
    - A short-term bedrock-api-key-* string: decodes the embedded STS access
      key, finds the issuing principal in CloudTrail, applies an
      aws:TokenIssueTime deny on that principal.
    """
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)

    scanner = ctx.obj.scanner

    if username_or_key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
        result = scanner.revoke_short_term_key(username_or_key, dry_run=dry_run, force=force)
    else:
        username = resolve_username(username_or_key)
        result = scanner.revoke_key(username, dry_run=dry_run, force=force)

    if output_json:
        path = build_output_path("revoke", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, json.dumps(result, indent=2, default=str))
        click.echo(f"JSON saved: {path}")

    sys.exit(0 if result['success'] else 1)
