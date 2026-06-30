"""Offline tests for ClaudePlatformKeyDecoder.

Mirrors tests/test_decoder.py for the Bedrock surface but covers
the AEAA long-term and aws-external-anthropic-api-key- short-term formats
introduced by the Claude Platform on AWS service. All tests run offline.
"""

import base64
from urllib.parse import urlencode

import pytest

from bedrock_keys_security.core.decoder_claude_platform import (
    ClaudePlatformKeyDecoder,
    redact_for_display,
)


def _build_long_term_key(payload: bytes) -> str:
    """Wrap an ASCII payload with the AEAA prefix.

    AEAA decodes to three framing bytes (\\x00\\x40\\x00), so callers pass
    the bare AeaApiKey-... payload and the helper handles the framing.
    """
    framed = b'\x00\x40\x00' + payload
    return base64.b64encode(framed).decode()


def _build_short_term_key(params: dict) -> str:
    url = "aws-external-anthropic.amazonaws.com/?" + urlencode(params)
    return "aws-external-anthropic-api-key-" + base64.b64encode(url.encode()).decode()


class TestDetectKeyType:
    def test_long_term_prefix(self):
        assert ClaudePlatformKeyDecoder.detect_key_type("AEAAabc123") == "long-term"

    def test_short_term_prefix(self):
        assert (
            ClaudePlatformKeyDecoder.detect_key_type(
                "aws-external-anthropic-api-key-abc"
            )
            == "short-term"
        )

    def test_unknown_prefix_returns_none(self):
        assert ClaudePlatformKeyDecoder.detect_key_type("AKIAIOSFODNN7EXAMPLE") is None

    def test_bedrock_prefix_returns_none(self):
        """ABSK and bedrock-api-key- belong to the Bedrock decoder."""
        assert ClaudePlatformKeyDecoder.detect_key_type("ABSKabc123") is None
        assert ClaudePlatformKeyDecoder.detect_key_type("bedrock-api-key-abc") is None


class TestDecodeLongTerm:
    def test_decoded_fields(self):
        key = _build_long_term_key(
            b"AeaApiKey-h42z-at-123456789012:thisisasecretsecret123456"
        )
        result = ClaudePlatformKeyDecoder.decode_long_term_key(key)

        assert "error" not in result
        assert result["bks_service"] == "claude-platform"
        assert result["type"] == "long-term"
        assert result["username"] == "AeaApiKey-h42z"
        assert result["username_suffix"] == "h42z"
        assert result["account_id"] == "123456789012"
        assert result["iam_user_arn"] == (
            "arn:aws:iam::123456789012:user/AeaApiKey-h42z"
        )
        assert "managed_policy_arn" not in result
        assert result["secret_length"] == len("thisisasecretsecret123456")
        assert result["key_position"] == "primary"
        assert result["is_secondary"] is False
        assert result["key_index_marker"] is None
        assert len(result["security_notes"]) == 3

    def test_secondary_key_strips_plus_marker(self):
        """On Claude Platform the ServiceCredentialAlias on the secondary
        credential is ``AeaApiKey-<id>+1-at-<account>``, mirroring the Bedrock
        ABSK +N pattern."""
        key = _build_long_term_key(
            b"AeaApiKey-h42z+1-at-123456789012:secondsecretvalue123456"
        )
        result = ClaudePlatformKeyDecoder.decode_long_term_key(key)

        assert "error" not in result
        assert result["username"] == "AeaApiKey-h42z"
        assert result["username_raw"] == "AeaApiKey-h42z+1"
        assert result["key_position"] == "secondary"
        assert result["is_secondary"] is True
        assert result["key_index_marker"] == "+1"
        assert any("Secondary key" in n for n in result["security_notes"])

    def test_long_term_key_decodes_account_and_username(self):
        """Synthetic AEAA key mirroring a real provisioning event's shape."""
        api_key = _build_long_term_key(
            b"AeaApiKey-abcd1234-at-123456789012:c3ludGhldGljLXNlY3JldA=="
        )
        result = ClaudePlatformKeyDecoder.decode_long_term_key(api_key)

        assert result["account_id"] == "123456789012"
        assert result["username"] == "AeaApiKey-abcd1234"
        assert result["username_suffix"] == "abcd1234"

    def test_missing_at_separator_returns_error(self):
        key = _build_long_term_key(b"AeaApiKey-h42z-no-separator-here")
        result = ClaudePlatformKeyDecoder.decode_long_term_key(key)

        assert "missing -at- separator" in result["error"]

    def test_missing_colon_separator_returns_error(self):
        key = _build_long_term_key(b"AeaApiKey-h42z-at-123456789012-no-colon")
        result = ClaudePlatformKeyDecoder.decode_long_term_key(key)

        assert "missing : separator" in result["error"]

    def test_malformed_base64_returns_error(self):
        result = ClaudePlatformKeyDecoder.decode_long_term_key("AEAA!!!not-base64!!!")

        assert "error" in result
        assert result["bks_service"] == "claude-platform"
        assert result["type"] == "long-term"


class TestDecodeShortTerm:
    @pytest.fixture
    def base_params(self):
        return {
            "Action": "CallWithBearerToken",
            "Version": "1",
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": (
                "ASIATESTEXAMPLE/20260511/us-east-1/aws-external-anthropic/aws4_request"
            ),
            "X-Amz-Date": "20260511T184706Z",
            "X-Amz-Expires": "43200",
            "X-Amz-SignedHeaders": "host",
            "X-Amz-Signature": "eadc6442f6f616e6" * 4,
        }

    def test_extracts_credential_components(self, base_params):
        params = dict(base_params)
        params["X-Amz-Security-Token"] = base64.b64encode(
            b"sessionmeta-123456789012-extra"
        ).decode()
        key = _build_short_term_key(params)

        result = ClaudePlatformKeyDecoder.decode_short_term_key(key)

        assert "error" not in result
        assert result["bks_service"] == "claude-platform"
        assert result["type"] == "short-term"
        assert result["access_key_id"] == "ASIATESTEXAMPLE"
        assert result["region"] == "us-east-1"
        assert result["sigv4_service"] == "aws-external-anthropic"
        assert result["hostname"] == "aws-external-anthropic.amazonaws.com"
        assert result["account_id"] == "123456789012"
        assert result["action"] == "CallWithBearerToken"
        assert result["issued_at"] == "2026-05-11T18:47:06+00:00"
        assert result["expires_at"] == "2026-05-12T06:47:06+00:00"

    def test_short_term_key_decodes_credential_components(self):
        """Synthetic short-term key mirroring a real console-issued key's shape."""
        params = {
            "Action": "CallWithBearerToken",
            "Version": "1",
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": (
                "ASIAEXAMPLE0000000001/20260511/us-east-1/aws-external-anthropic/aws4_request"
            ),
            "X-Amz-Date": "20260511T184706Z",
            "X-Amz-Expires": "43200",
            "X-Amz-SignedHeaders": "host",
            "X-Amz-Signature": "eadc6442f6f616e6" * 4,
            "X-Amz-Security-Token": base64.b64encode(
                b"sessionmeta-123456789012-synthetic"
            ).decode(),
        }
        result = ClaudePlatformKeyDecoder.decode_short_term_key(_build_short_term_key(params))

        assert result["access_key_id"] == "ASIAEXAMPLE0000000001"
        assert result["region"] == "us-east-1"
        assert result["sigv4_service"] == "aws-external-anthropic"
        assert result["account_id"] == "123456789012"

    def test_without_security_token_account_id_is_unknown(self, base_params):
        key = _build_short_term_key(base_params)

        result = ClaudePlatformKeyDecoder.decode_short_term_key(key)

        assert "error" not in result
        assert result["account_id"] == "Unknown"


class TestDecodeKeyDispatcher:
    def test_unknown_prefix_returns_error(self):
        result = ClaudePlatformKeyDecoder.decode_key("AKIAIOSFODNN7EXAMPLE")

        assert result["error"] == "Unknown key format"
        assert "expected_formats" in result


class TestRedactForDisplay:
    def test_removes_plaintext_and_redacts_previews_without_mutation(self):
        original = {
            "type": "long-term",
            "bks_service": "claude-platform",
            "username": "AeaApiKey-h42z",
            "secret_preview": "abc12345...",
            "credential_hint": "ASIATESTEXAMPLE/20260511/...",
            "full_decoded": "AeaApiKey-h42z-at-123456789012:plaintextsecret",
            "presigned_url": "aws-external-anthropic.amazonaws.com/?Action=...",
        }
        original_snapshot = dict(original)

        safe = redact_for_display(original)

        assert "full_decoded" not in safe
        assert "presigned_url" not in safe
        assert safe["secret_preview"] == "[REDACTED]"
        assert safe["credential_hint"] == "[REDACTED]"
        assert safe["username"] == "AeaApiKey-h42z"

        assert original == original_snapshot
