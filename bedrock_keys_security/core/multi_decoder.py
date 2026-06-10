"""Service-agnostic dispatcher for the per-service offline key decoders.

Detects which surface (Bedrock or Claude Platform) an API key belongs to by prefix and routes
to the matching decoder. Used by ``bks decode-key`` so callers do not need
to know in advance whether they hold a Bedrock or a Claude
Platform key.

Prefix routing table:

============================================ =================================
Prefix                                       Decoder
============================================ =================================
``ABSK``                                     BedrockKeyDecoder.long-term
``bedrock-api-key-``                         BedrockKeyDecoder.short-term
``AEAA``                                     ClaudePlatformKeyDecoder.long-term
``aws-external-anthropic-api-key-``          ClaudePlatformKeyDecoder.short-term
============================================ =================================
"""

from typing import Dict, Optional

from bedrock_keys_security.core.decoder import BedrockKeyDecoder
from bedrock_keys_security.core.decoder_claude_platform import ClaudePlatformKeyDecoder


def detect_service(key: str) -> Optional[str]:
    """Return 'bedrock', 'claude-platform' or None for an unknown prefix."""
    if (
        key.startswith(BedrockKeyDecoder.LONG_TERM_PREFIX)
        or key.startswith(BedrockKeyDecoder.SHORT_TERM_PREFIX)
    ):
        return 'bedrock'
    if (
        key.startswith(ClaudePlatformKeyDecoder.LONG_TERM_PREFIX)
        or key.startswith(ClaudePlatformKeyDecoder.SHORT_TERM_PREFIX)
    ):
        return 'claude-platform'
    return None


def decode_any_key(key: str) -> Dict:
    """Dispatch to the matching decoder and return its result.

    Falls back to a structured error result when no prefix matches so
    callers can serialize the response uniformly.
    """
    service = detect_service(key)
    if service == 'bedrock':
        return BedrockKeyDecoder.decode_key(key)
    if service == 'claude-platform':
        return ClaudePlatformKeyDecoder.decode_key(key)
    return {
        'error': 'Unknown key format',
        'expected_formats': [
            'ABSK... (Bedrock long-term)',
            'bedrock-api-key-... (Bedrock short-term)',
            'AEAA... (Claude Platform long-term)',
            'aws-external-anthropic-api-key-... (Claude Platform short-term)',
        ],
    }


def redact_for_display(result: Dict) -> Dict:
    """Redact a multi-decoder result by routing to the matching service helper."""
    if result.get('bks_service') == 'claude-platform':
        from bedrock_keys_security.core.decoder_claude_platform import (
            redact_for_display as redact_claude,
        )
        return redact_claude(result)
    from bedrock_keys_security.core.decoder import redact_for_display as redact_bedrock
    return redact_bedrock(result)
