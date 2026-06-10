"""Shared Click option decorators for subcommands"""

import click

from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.core.decoder_claude_platform import (
    ClaudePlatformKeyDecoder,
)


def aws_options(f):
    """Add --profile and --region to a subcommand. Subcommand-level wins over group-level."""
    f = click.option('--region', default=None, help='AWS region (overrides group-level)')(f)
    f = click.option('--profile', default=None, help='AWS profile (overrides group-level)')(f)
    return f


def apply_aws_overrides(ctx, profile, region):
    """Apply subcommand-level --profile/--region to the shared Context"""
    if profile is not None:
        ctx.obj.profile = profile
    if region is not None:
        ctx.obj.region = region


def quiet_option(f):
    """Add --quiet/-q to a subcommand. Same flag exists at the group level; this allows
    `bks <cmd> --quiet` and `bks --quiet <cmd>` to be equivalent."""
    return click.option('--quiet', '-q', 'quiet_flag', is_flag=True,
                        help='Suppress info logs (same as global --quiet)')(f)


def apply_quiet_override(ctx, quiet_flag):
    """Apply subcommand-level --quiet to the shared Context. Idempotent if global already set it."""
    if quiet_flag:
        from bedrock_keys_security.utils import output
        ctx.obj.quiet = True
        output.set_quiet(True)


def resolve_username(value: str) -> str:
    """Accept an IAM username or any supported long-term API key.

    Long-term API key formats are decoded offline to recover the backing
    phantom username:

    - ``ABSK`` (Bedrock long-term)
    - ``AEAA`` (Claude Platform long-term)

    Short-term formats have no IAM phantom user to act on directly; the
    function raises a ClickException pointing at the appropriate
    incident-response path for each service.
    """
    if value.startswith(BedrockKeyDecoder.LONG_TERM_PREFIX):
        result = BedrockKeyDecoder.decode_long_term_key(value)
        if 'error' in result:
            raise click.ClickException(
                f"Input looks like an ABSK key but could not be decoded: {result['error']}"
            )
        return result['username']
    if value.startswith(ClaudePlatformKeyDecoder.LONG_TERM_PREFIX):
        result = ClaudePlatformKeyDecoder.decode_long_term_key(value)
        if 'error' in result:
            raise click.ClickException(
                f"Input looks like an AEAA Claude Platform key but could not be decoded: {result['error']}"
            )
        return result['username']
    if value.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
        raise click.ClickException(
            "Short-term Bedrock keys (bedrock-api-key-*) have no phantom IAM user to build "
            "an incident report on. Use `bks timeline <bedrock-api-key-...>` to see who used "
            "the key, or `bks revoke-key <bedrock-api-key-...>` to deny the issuing principal."
        )
    if value.startswith(ClaudePlatformKeyDecoder.SHORT_TERM_PREFIX):
        raise click.ClickException(
            "Short-term Claude Platform keys (aws-external-anthropic-api-key-*) have no phantom "
            "IAM user to build an incident report on. Use "
            "`bks timeline <aws-external-anthropic-api-key-...>` to see who used the key, or "
            "`bks revoke-key <aws-external-anthropic-api-key-...>` to act on the issuing principal."
        )
    return value


def select_scanner(ctx, username: str):
    """Return the scanner that owns a phantom username by prefix.

    - ``AeaApiKey-*`` routes to the Claude Platform scanner.
    - ``BedrockAPIKey-*`` (and everything else) routes to the Bedrock scanner.
    """
    if username.startswith("AeaApiKey-"):
        return ctx.obj.claude_platform_scanner
    return ctx.obj.scanner
