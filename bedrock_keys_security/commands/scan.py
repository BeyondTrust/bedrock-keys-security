"""Scan command - discover phantom IAM users"""

import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import click

from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.cli import aws_options, apply_aws_overrides, apply_quiet_override, quiet_option


OUTPUT_DIR = Path("output")
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


def build_output_path(command: str, account_id: str, ext: str, output_dir: Path = OUTPUT_DIR) -> Path:
    """Return output/bks-<command>-<account>-<UTC ts µs>.<ext>; create dir if missing.

    Non-12-digit `account_id` (e.g. path-traversal payload from a crafted ABSK
    key) collapses to `unknown` so the filename can't escape `output_dir`.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_account = account_id if _ACCOUNT_ID_RE.match(str(account_id)) else "unknown"
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return output_dir / f"bks-{command}-{safe_account}-{ts}.{ext}"


def write_secure(path: Path, content: str) -> None:
    """Write text and chmod 0600 so JSON/CSV outputs aren't world-readable on shared hosts."""
    path.write_text(content)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


@click.command()
@aws_options
@click.option('--json', 'output_json', is_flag=True,
              help='Save scan results as JSON to output/ directory')
@click.option('--csv', 'output_csv', is_flag=True,
              help='Save scan results as CSV to output/ directory')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose log output during scan')
@quiet_option
@click.pass_context
def scan(ctx, profile, region, output_json, output_csv, verbose, quiet_flag):
    """Scan for phantom IAM users (default command)"""
    apply_aws_overrides(ctx, profile, region)
    apply_quiet_override(ctx, quiet_flag)
    if verbose:
        ctx.obj.verbose = True

    scanner = ctx.obj.scanner
    quiet = ctx.obj.quiet

    if not quiet:
        click.echo(scanner.report_header())

    start = time.monotonic()
    with output.spinner():
        phantoms = scanner.find_phantom_users()

    if not quiet:
        click.echo(scanner.generate_table_report(phantoms))

    saved = []
    if output_json:
        path = build_output_path("scan", scanner.account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, scanner.generate_json_report(phantoms))
        saved.append(("JSON", path))

    if output_csv:
        path = build_output_path("scan", scanner.account_id, "csv", output_dir=ctx.obj.output_dir)
        scanner.generate_csv_report(phantoms, str(path))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        saved.append(("CSV", path))

    if not quiet:
        elapsed = time.monotonic() - start
        total_users = getattr(scanner, 'last_users_scanned', None)
        n_phantoms = len(phantoms)
        if total_users is not None:
            click.echo(
                f"\n{output.bold('Scan complete')}  "
                f"{total_users} IAM users  ·  {n_phantoms} phantom"
                f"{'s' if n_phantoms != 1 else ''}  ·  {elapsed:.1f}s"
            )

    for label, path in saved:
        click.echo(f"{label} saved: {path}")
