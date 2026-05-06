"""Click CLI entry point for bks (Bedrock Keys Security)"""

from pathlib import Path
from typing import Optional

import click

from bedrock_keys_security import __version__
from bedrock_keys_security._version import get_commit
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.aws import AWSSession
from bedrock_keys_security.core.scanner import PhantomUserScanner

_commit = get_commit()
_version_string = f"{__version__} (commit {_commit})" if _commit else __version__


class Context:
    """Shared CLI context passed to all subcommands"""

    def __init__(self):
        self.profile: Optional[str] = None
        self.region: str = "us-east-1"
        self.verbose: bool = False
        self.quiet: bool = False
        self.output_dir: Path = Path("output")
        self._scanner: Optional[PhantomUserScanner] = None

    @property
    def scanner(self) -> PhantomUserScanner:
        """Lazy-initialize PhantomUserScanner (avoids AWS calls for decode-key)"""
        if self._scanner is None:
            aws = AWSSession(profile=self.profile, region=self.region, verbose=self.verbose)
            self._scanner = PhantomUserScanner(aws_session=aws, verbose=self.verbose)
        return self._scanner


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option('--profile', default=None, help='AWS profile name')
@click.option('--region', default='us-east-1', help='AWS region (default: us-east-1)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--quiet', '-q', is_flag=True,
              help='Suppress info / success / warning logs and the scan banner / table / summary. '
                   'Errors still go to stderr; saved-file paths still print to stdout. Useful for SOAR pipelines.')
@click.option('--output-dir', 'output_dir', default='output', metavar='DIR',
              help='Directory for JSON / CSV reports (default: ./output). '
                   'Created if missing. Useful for SOAR pipelines that store reports under /var/log/bks or similar.')
@click.version_option(_version_string, prog_name='bks')
@click.pass_context
def cli(ctx, profile, region, verbose, quiet, output_dir):
    """Bedrock API Keys Security Toolkit (BKS).

    The AWS Bedrock API keys security toolkit. Includes a phantom user
    scanner (BedrockAPIKey-* IAM users silently provisioned by Console
    long-term keys), an offline key decoder for ABSK and short-term keys,
    incident response commands and a report generator.

    Subcommands: scan, decode-key, timeline, revoke-key, report, cleanup.
    """
    ctx.ensure_object(Context)
    ctx.obj.profile = profile
    ctx.obj.region = region
    ctx.obj.verbose = verbose
    ctx.obj.quiet = quiet
    ctx.obj.output_dir = Path(output_dir)
    if quiet:
        output.set_quiet(True)

    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


from bedrock_keys_security.commands.scan import scan  # noqa: E402
from bedrock_keys_security.commands.cleanup import cleanup  # noqa: E402
from bedrock_keys_security.commands.revoke import revoke_key  # noqa: E402
from bedrock_keys_security.commands.timeline import timeline  # noqa: E402
from bedrock_keys_security.commands.report import report  # noqa: E402
from bedrock_keys_security.commands.decode import decode_key  # noqa: E402

cli.add_command(scan)
cli.add_command(cleanup)
cli.add_command(revoke_key)
cli.add_command(timeline)
cli.add_command(report)
cli.add_command(decode_key)
