"""Offline forensic decoder for AWS Bedrock API keys"""

import base64
import hashlib
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


class BedrockKeyDecoder:
    """Decoder for AWS Bedrock API keys"""

    LONG_TERM_PREFIX = "ABSK"
    SHORT_TERM_PREFIX = "bedrock-api-key-"

    @staticmethod
    def detect_key_type(key: str) -> Optional[str]:
        """
        Detect the type of Bedrock API key

        Returns:
            'long-term', 'short-term', or None
        """
        if key.startswith(BedrockKeyDecoder.LONG_TERM_PREFIX):
            return 'long-term'
        elif key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX):
            return 'short-term'
        else:
            return None

    @staticmethod
    def decode_long_term_key(key: str) -> Dict:
        """
        Decode ABSK (long-term) Bedrock API key

        Format: ABSK + base64(BedrockAPIKey-{id}-at-{account_id}:{secret})
        """
        try:
            encoded_part = key[len(BedrockKeyDecoder.LONG_TERM_PREFIX):]
            encoded_part += '=' * (-len(encoded_part) % 4)
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_str = decoded_bytes.decode('utf-8')

            if '-at-' not in decoded_str:
                return {
                    'error': 'Invalid format: missing -at- separator',
                    'decoded_string': decoded_str,
                }

            parts = decoded_str.split('-at-')
            username_raw = parts[0]

            if ':' not in parts[1]:
                return {
                    'error': 'Invalid format: missing : separator',
                    'decoded_string': decoded_str,
                }

            account_id, secret = parts[1].split(':', 1)
            secret_preview = (secret[:8] + '...') if len(secret) > 8 else secret
            secret_fingerprint = hashlib.sha256(secret.encode('utf-8')).hexdigest()[:16]

            # AWS allows two ABSK credentials per phantom user. The second key's
            # decoded payload includes a +N marker (typically +1) appended to the
            # IAM username. The marker is NOT part of the actual IAM username,
            # so strip it before constructing user-facing identifiers.
            if '+' in username_raw:
                username, index_marker = username_raw.split('+', 1)
                key_position = 'secondary'
                key_index_marker = f'+{index_marker}'
            else:
                username = username_raw
                key_position = 'primary'
                key_index_marker = None

            user_suffix = username[len('BedrockAPIKey-'):] if username.startswith('BedrockAPIKey-') else username

            security_notes = [
                'AWS Account ID disclosed (enables reconnaissance)',
                'IAM username disclosed (enables targeted attacks)',
                'ABSK prefix enables automated secret scanning',
                'Credential persists until explicitly revoked',
            ]
            if key_position == 'secondary':
                security_notes.append(
                    'Secondary key (+N marker present): phantom user has at least 2 active ABSK credentials'
                )

            return {
                'type': 'long-term',
                'format': 'ABSK + base64(username-at-accountid:secret)',
                'username': username,
                'username_suffix': user_suffix,
                'username_raw': username_raw,
                'key_position': key_position,
                'key_index_marker': key_index_marker,
                'is_secondary': key_position == 'secondary',
                'account_id': account_id,
                'iam_user_arn': f'arn:aws:iam::{account_id}:user/{username}',
                'secret_preview': secret_preview,
                'secret_length': len(secret),
                'secret_sha256_16': secret_fingerprint,
                'full_decoded': decoded_str,
                'security_notes': security_notes,
            }

        except Exception as e:
            return {
                'error': f'Decoding failed: {str(e)}',
                'type': 'long-term',
            }

    @staticmethod
    def decode_short_term_key(key: str) -> Dict:
        """
        Decode short-term Bedrock API key

        Format: bedrock-api-key- + base64(SigV4 presigned URL)
        """
        try:
            encoded_part = key[len(BedrockKeyDecoder.SHORT_TERM_PREFIX):]
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_url = decoded_bytes.decode('utf-8')

            # The decoded payload starts with `bedrock.amazonaws.com/?...` (no scheme),
            # so prepend https:// to make urlparse extract netloc correctly.
            parse_target = decoded_url if '://' in decoded_url else 'https://' + decoded_url
            parsed = urllib.parse.urlparse(parse_target)
            params = urllib.parse.parse_qs(parsed.query)

            def first(k, default='Unknown'):
                return params.get(k, [default])[0]

            credential = first('X-Amz-Credential')
            cred_parts = credential.split('/') if credential != 'Unknown' else []
            access_key_id = cred_parts[0] if len(cred_parts) >= 1 else 'Unknown'
            cred_date = cred_parts[1] if len(cred_parts) >= 2 else 'Unknown'
            region = cred_parts[2] if len(cred_parts) >= 3 else 'Unknown'
            service = cred_parts[3] if len(cred_parts) >= 4 else 'Unknown'

            date = first('X-Amz-Date')
            expires_str = first('X-Amz-Expires')

            issued_at = expires_at = 'Unknown'
            try:
                issued_dt = datetime.strptime(date, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
                issued_at = issued_dt.isoformat()
                expires_seconds = int(expires_str)
                expires_at = (issued_dt + timedelta(seconds=expires_seconds)).isoformat()
            except (ValueError, TypeError):
                pass

            # Account ID extraction: STS session tokens contain the 12-digit account
            # ID as ASCII plaintext within the unencrypted session metadata header.
            account_id = 'Unknown'
            security_token = first('X-Amz-Security-Token', '')
            if security_token:
                try:
                    token_decoded = base64.b64decode(security_token + '==').decode('utf-8', errors='ignore')
                    account_match = re.search(r'(\d{12})', token_decoded)
                    if account_match:
                        account_id = account_match.group(1)
                except Exception:
                    pass

            signature = first('X-Amz-Signature')
            signature_preview = (
                signature[:16] + '...' + signature[-8:]
                if signature != 'Unknown' and len(signature) > 24
                else signature
            )

            return {
                'type': 'short-term',
                'format': 'bedrock-api-key- + base64(presigned_url)',
                'presigned_url': decoded_url,
                'hostname': parsed.netloc,
                'action': first('Action'),
                'api_version': first('Version'),
                'access_key_id': access_key_id,
                'service': service,
                'region': region,
                'account_id': account_id,
                'date': date,
                'issued_at': issued_at,
                'expires_in_seconds': expires_str,
                'expires_at': expires_at,
                'algorithm': first('X-Amz-Algorithm'),
                'signed_headers': first('X-Amz-SignedHeaders'),
                'signature_preview': signature_preview,
                'credential_hint': (
                    credential[:30] + '...' if len(credential) > 30 else credential
                ),
                'security_notes': [
                    'Temporary credential with time-limited validity',
                    'Revocable via aws:TokenIssueTime deny policy on the issuing principal '
                    '(see incident response runbook in README)',
                    'Presigned URL contains AWS credentials',
                    f'Expires {expires_at}' if expires_at != 'Unknown'
                    else 'Expiry: unknown (could not parse presigned URL)',
                ],
            }

        except Exception as e:
            return {
                'error': f'Decoding failed: {str(e)}',
                'type': 'short-term',
            }

    @staticmethod
    def decode_key(key: str) -> Dict:
        """Auto-detect and decode any Bedrock API key"""
        key_type = BedrockKeyDecoder.detect_key_type(key)

        if key_type == 'long-term':
            return BedrockKeyDecoder.decode_long_term_key(key)
        elif key_type == 'short-term':
            return BedrockKeyDecoder.decode_short_term_key(key)
        else:
            return {
                'error': 'Unknown key format',
                'expected_formats': [
                    'ABSK... (long-term key)',
                    'bedrock-api-key-... (short-term key)',
                ],
            }


# Fields the decoder may emit that should not appear in CLI / report output.
# Centralised here so adding a new sensitive field cannot leak silently
# through every consumer that builds its own redaction list.
_FIELDS_TO_REMOVE = ('full_decoded', 'presigned_url')
_FIELDS_TO_REDACT = ('secret_preview', 'credential_hint')


def redact_for_display(result: Dict) -> Dict:
    """Return a copy of a decoder result safe to display or persist.

    Removes plaintext payload fields (full decoded string, presigned URL)
    and replaces preview-style fields with '[REDACTED]'. The original
    result dict is not mutated, so library callers that intentionally
    want the raw output can keep using BedrockKeyDecoder.decode_key().
    """
    safe = dict(result)
    for field in _FIELDS_TO_REMOVE:
        safe.pop(field, None)
    for field in _FIELDS_TO_REDACT:
        if field in safe:
            safe[field] = '[REDACTED]'
    return safe
