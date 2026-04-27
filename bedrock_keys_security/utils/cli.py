"""Shared Click option decorators for subcommands"""

import click


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
