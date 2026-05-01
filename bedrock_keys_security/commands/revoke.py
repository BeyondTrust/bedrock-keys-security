"""Revoke-key command - emergency key revocation"""

import sys
import click

from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, resolve_username


@click.command('revoke-key')
@aws_options
@click.argument('username_or_key')
@click.option('--dry-run', is_flag=True, help='Simulate revocation without executing')
@click.option('--force', is_flag=True, help='Skip confirmation prompt (DANGEROUS)')
@click.pass_context
def revoke_key(ctx, profile, region, username_or_key, dry_run, force):
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

    if username_or_key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
        success = ctx.obj.scanner.revoke_short_term_key(username_or_key, dry_run=dry_run, force=force)
    else:
        username = resolve_username(username_or_key)
        success = ctx.obj.scanner.revoke_key(username, dry_run=dry_run, force=force)

    sys.exit(0 if success else 1)
