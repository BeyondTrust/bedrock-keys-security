"""Decode-key command - offline forensics for any supported API key format"""

import json
import sys

import click

from bedrock_keys_security.commands.scan import build_output_path, write_secure
from bedrock_keys_security.core.multi_decoder import decode_any_key, redact_for_display
from bedrock_keys_security.utils.output import format_decode_table_output


@click.command('decode-key')
@click.argument('key')
@click.option('--json', 'output_json', is_flag=True,
              help='Save decoded analysis as JSON to output/ directory')
@click.pass_context
def decode_key(ctx, key, output_json):
    """Decode a Bedrock or Claude Platform API key (no AWS credentials needed).

    Supports both Bedrock (ABSK, bedrock-api-key-) and Claude Platform
    on AWS (AEAA, aws-external-anthropic-api-key-) formats; the service is
    detected automatically from the API key prefix.
    """
    raw = decode_any_key(key)
    result = redact_for_display(raw)

    if output_json:
        account_id = raw.get('account_id') or 'unknown'
        path = build_output_path("decode", account_id, "json", output_dir=ctx.obj.output_dir)
        write_secure(path, json.dumps(result, indent=2))
        click.echo(f"JSON saved: {path}")
    else:
        click.echo(format_decode_table_output(result))

    sys.exit(0 if 'error' not in result else 1)
