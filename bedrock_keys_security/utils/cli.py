"""Shared Click option decorators for subcommands"""

import click

from bedrock_keys_security.core.decoder import BedrockKeyDecoder


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
    """Accept an IAM username or a Bedrock API key; ABSK keys are decoded to their phantom username.

    Short-term keys raise a ClickException pointing at the aws:TokenIssueTime IR path.
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
