"""Decode-key command - offline Bedrock API key forensics"""

import json
import sys
import click

from bedrock_keys_security.core.decoder import BedrockKeyDecoder, redact_for_display
from bedrock_keys_security.utils.output import format_decode_table_output


@click.command('decode-key')
@click.argument('key')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
def decode_key(key, output_json):
    """Decode Bedrock API key (no AWS credentials needed)"""
    raw = BedrockKeyDecoder.decode_key(key)
    result = redact_for_display(raw)

    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(format_decode_table_output(result))

    sys.exit(0 if 'error' not in result else 1)
