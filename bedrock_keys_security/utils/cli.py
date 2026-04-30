"""Shared Click option decorators for subcommands"""

import click

from bedrock_keys_security.core.decoder import BedrockKeyDecoder


def aws_options(f):
    """Add --profile and --region to a subcommand and merge with group context.

    Group-level options (bks --profile X scan) and subcommand-level options
    (bks scan --profile X) both work; subcommand wins when both are set.
    """
    f = click.option('--region', default=None, help='AWS region (overrides group-level)')(f)
    f = click.option('--profile', default=None, help='AWS profile (overrides group-level)')(f)
    return f


def apply_aws_overrides(ctx, profile, region):
    """Apply subcommand-level --profile/--region to the shared Context"""
    if profile is not None:
        ctx.obj.profile = profile
    if region is not None:
        ctx.obj.region = region


def resolve_username(value: str) -> str:
    """Accept either an IAM username or a Bedrock API key.

    Long-term ABSK keys are decoded offline and the underlying
    BedrockAPIKey-<id> phantom username is returned. Short-term keys have
    no phantom user, so the function errors out with a pointer to the
    aws:TokenIssueTime IR procedure. Plain usernames pass through unchanged.

    Lets the IR flow read naturally: `bks revoke-key <leaked-ABSK-key>`
    works without forcing the responder to manually decode first.
    """
    if value.startswith(BedrockKeyDecoder.LONG_TERM_PREFIX):
        result = BedrockKeyDecoder.decode_long_term_key(value)
        if 'error' in result:
            raise click.ClickException(
                f"Input looks like an ABSK key but could not be decoded: {result['error']}"
            )
        return result['username']
    if value.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
        raise click.ClickException(
            "Short-term keys (bedrock-api-key-*) have no phantom user to act on. "
            "Apply an aws:TokenIssueTime deny policy on the issuing principal instead "
            "(see the incident response runbook in README)."
        )
    return value
