"""Revoke-key command - emergency key revocation"""

import sys
import click

from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, resolve_username


@click.command('revoke-key')
@aws_options
@click.argument('username_or_key')
@click.option('--dry-run', is_flag=True, help='Simulate revocation without executing')
@click.option('--force', is_flag=True, help='Skip confirmation prompt (DANGEROUS)')
@click.pass_context
def revoke_key(ctx, profile, region, username_or_key, dry_run, force):
    """Emergency revocation of Bedrock API key.

    Accepts either a phantom IAM username (BedrockAPIKey-xxxx) or a
    long-term ABSK key string (decoded offline to find the underlying
    phantom user).
    """
    apply_aws_overrides(ctx, profile, region)
    username = resolve_username(username_or_key)
    success = ctx.obj.scanner.revoke_key(username, dry_run=dry_run, force=force)
    sys.exit(0 if success else 1)
