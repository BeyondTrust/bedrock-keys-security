"""Offline forensic decoder for the Claude Platform on AWS API keys.

Mirrors the BedrockKeyDecoder API for the AWS Bedrock surface.
The Claude Platform service (`aws-external-anthropic.amazonaws.com`) ships
its own pair of key formats:

- Long-term : ``AEAA`` prefix + base64(``\\x00@\\x00`` framing + ``AeaApiKey-<id>-at-<account>:<secret>``)
- Short-term: ``aws-external-anthropic-api-key-`` prefix + base64(SigV4 presigned URL)

Both are reversible with stdlib base64 and expose the AWS account ID and the
backing IAM user ARN. The backing IAM user is auto-provisioned by AWS when
the long-term key is created in the Claude Platform console and follows the
``AeaApiKey-*`` naming convention.
"""

import base64
import hashlib
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional


class ClaudePlatformKeyDecoder:
    """Decoder for the Claude Platform on AWS API keys"""

    LONG_TERM_PREFIX = "AEAA"
    SHORT_TERM_PREFIX = "aws-external-anthropic-api-key-"
    BACKING_USER_PREFIX = "AeaApiKey-"
    SERVICE_PRINCIPAL = "aws-external-anthropic.amazonaws.com"

    @staticmethod
    def detect_key_type(key: str) -> Optional[str]:
        """Return 'long-term', 'short-term' or None."""
        if key.startswith(ClaudePlatformKeyDecoder.LONG_TERM_PREFIX):
            return 'long-term'
        if key.startswith(ClaudePlatformKeyDecoder.SHORT_TERM_PREFIX):
            return 'short-term'
        return None

    @staticmethod
    def decode_long_term_key(key: str) -> Dict:
        """Decode AEAA long-term API key.

        Format: ``AEAA`` + base64(``\\x00@\\x00`` framing + ``AeaApiKey-<id>-at-<account>:<secret>``).
        ``AEAA`` itself decodes to the framing bytes, so stripping the prefix
        and base64-decoding the rest yields the bare ASCII payload.
        """
        try:
            encoded_part = key[len(ClaudePlatformKeyDecoder.LONG_TERM_PREFIX):]
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

            # AWS allows up to 2 service-specific credentials per phantom; the
            # secondary key's decoded payload appends a +N marker that is not
            # part of the IAM username (same pattern as Bedrock ABSK keys).
            if '+' in username_raw:
                username, index_marker = username_raw.split('+', 1)
                key_position = 'secondary'
                key_index_marker = f'+{index_marker}'
            else:
                username = username_raw
                key_position = 'primary'
                key_index_marker = None

            user_suffix = (
                username[len(ClaudePlatformKeyDecoder.BACKING_USER_PREFIX):]
                if username.startswith(ClaudePlatformKeyDecoder.BACKING_USER_PREFIX)
                else username
            )

            security_notes = [
                'API key is HTTP-Basic-style credentials wrapping the IAM phantom user',
                'Account ID is recoverable in cleartext from the API key',
                'API key is held on the IAM user as a service-specific credential '
                'under ServiceName=aws-external-anthropic.amazonaws.com and can be '
                'revoked per-key via iam:DeleteServiceSpecificCredential',
            ]
            if key_position == 'secondary':
                security_notes.append(
                    'Secondary key (+N marker present): phantom user has at least '
                    '2 active service-specific credentials'
                )

            return {
                'bks_service': 'claude-platform',
                'type': 'long-term',
                'format': 'AEAA + base64(framing + AeaApiKey-<id>-at-<account>:<secret>)',
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
                'bks_service': 'claude-platform',
                'type': 'long-term',
            }

    @staticmethod
    def decode_short_term_key(key: str) -> Dict:
        """Decode short-term API key.

        Format: ``aws-external-anthropic-api-key-`` + base64(SigV4 presigned URL).
        The URL targets ``aws-external-anthropic.amazonaws.com/?Action=CallWithBearerToken``
        and embeds an STS temporary credential (``ASIA*``) in ``X-Amz-Credential``.
        """
        try:
            encoded_part = key[len(ClaudePlatformKeyDecoder.SHORT_TERM_PREFIX):]
            encoded_part += '=' * (-len(encoded_part) % 4)
            decoded_bytes = base64.b64decode(encoded_part)
            decoded_url = decoded_bytes.decode('utf-8')

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
                'bks_service': 'claude-platform',
                'type': 'short-term',
                'format': 'aws-external-anthropic-api-key- + base64(presigned_url)',
                'presigned_url': decoded_url,
                'hostname': parsed.netloc,
                'action': first('Action'),
                'api_version': first('Version'),
                'access_key_id': access_key_id,
                'sigv4_service': service,
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
                    'STS temporary credential with X-Amz-Expires validity window',
                    'Effective TTL is bounded by the underlying STS session, '
                    'which has been observed shorter than X-Amz-Expires in practice',
                    'Pre-signed URL is region-locked to the credential scope',
                    f'Expires {expires_at}' if expires_at != 'Unknown'
                    else 'Expiry: unknown (could not parse presigned URL)',
                ],
            }

        except Exception as e:
            return {
                'error': f'Decoding failed: {str(e)}',
                'bks_service': 'claude-platform',
                'type': 'short-term',
            }

    @staticmethod
    def decode_key(key: str) -> Dict:
        """Auto-detect and decode any Claude Platform API key"""
        key_type = ClaudePlatformKeyDecoder.detect_key_type(key)

        if key_type == 'long-term':
            return ClaudePlatformKeyDecoder.decode_long_term_key(key)
        if key_type == 'short-term':
            return ClaudePlatformKeyDecoder.decode_short_term_key(key)
        return {
            'error': 'Unknown key format',
            'expected_formats': [
                'AEAA... (long-term key)',
                'aws-external-anthropic-api-key-... (short-term key)',
            ],
        }


_FIELDS_TO_REMOVE = ('full_decoded', 'presigned_url')
_FIELDS_TO_REDACT = ('secret_preview', 'credential_hint')


def redact_for_display(result: Dict) -> Dict:
    """Return a copy of a decoder result safe to display or persist.

    Mirrors the redaction helper from the Bedrock decoder so callers can
    operate uniformly on either service's output.
    """
    safe = dict(result)
    for field in _FIELDS_TO_REMOVE:
        safe.pop(field, None)
    for field in _FIELDS_TO_REDACT:
        if field in safe:
            safe[field] = '[REDACTED]'
    return safe
