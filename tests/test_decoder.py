"""Offline tests for BedrockKeyDecoder.

Covers the public surface used by `bks decode-key` and library callers:
key-type detection, ABSK primary/secondary decoding, malformed input
handling, short-term presigned-URL parsing and the display-redaction
helper. The decoder has no AWS dependencies, so these run fully offline.
"""

import base64
from urllib.parse import urlencode

import pytest

from bedrock_keys_security.core.decoder import (
    BedrockKeyDecoder,
    redact_for_display,
)


def _build_long_term_key(payload: bytes) -> str:
    return "ABSK" + base64.b64encode(payload).decode()


def _build_short_term_key(params: dict) -> str:
    url = "bedrock.amazonaws.com/?" + urlencode(params)
    return "bedrock-api-key-" + base64.b64encode(url.encode()).decode()


class TestDetectKeyType:
    def test_long_term_prefix(self):
        assert BedrockKeyDecoder.detect_key_type("ABSKabc123") == "long-term"

    def test_short_term_prefix(self):
        assert BedrockKeyDecoder.detect_key_type("bedrock-api-key-abc") == "short-term"

    def test_unknown_prefix_returns_none(self):
        assert BedrockKeyDecoder.detect_key_type("AKIAIOSFODNN7EXAMPLE") is None


class TestDecodeLongTerm:
    def test_primary_key(self):
        key = _build_long_term_key(
            b"BedrockAPIKey-h42z-at-123456789012:thisisasecretsecret123456"
        )
        result = BedrockKeyDecoder.decode_long_term_key(key)

        assert "error" not in result
        assert result["type"] == "long-term"
        assert result["username"] == "BedrockAPIKey-h42z"
        assert result["username_suffix"] == "h42z"
        assert result["account_id"] == "123456789012"
        assert result["key_position"] == "primary"
        assert result["is_secondary"] is False
        assert result["key_index_marker"] is None
        assert result["iam_user_arn"] == (
            "arn:aws:iam::123456789012:user/BedrockAPIKey-h42z"
        )
        assert result["secret_length"] == len("thisisasecretsecret123456")
        assert result["security_notes"] == []

    def test_secondary_key_strips_plus_marker(self):
        key = _build_long_term_key(
            b"BedrockAPIKey-h42z+1-at-123456789012:secondsecretvalue123456"
        )
        result = BedrockKeyDecoder.decode_long_term_key(key)

        assert "error" not in result
        assert result["username"] == "BedrockAPIKey-h42z"
        assert result["username_raw"] == "BedrockAPIKey-h42z+1"
        assert result["key_position"] == "secondary"
        assert result["is_secondary"] is True
        assert result["key_index_marker"] == "+1"
        assert len(result["security_notes"]) == 1
        assert "Secondary key" in result["security_notes"][0]

    def test_missing_at_separator_returns_error(self):
        key = _build_long_term_key(b"BedrockAPIKey-h42z-no-separator-here")
        result = BedrockKeyDecoder.decode_long_term_key(key)

        assert "missing -at- separator" in result["error"]

    def test_missing_colon_separator_returns_error(self):
        key = _build_long_term_key(b"BedrockAPIKey-h42z-at-123456789012-no-colon")
        result = BedrockKeyDecoder.decode_long_term_key(key)

        assert "missing : separator" in result["error"]

    def test_malformed_base64_returns_error(self):
        result = BedrockKeyDecoder.decode_long_term_key("ABSK!!!not-base64!!!")

        assert "error" in result
        assert result["type"] == "long-term"


class TestDecodeShortTerm:
    @pytest.fixture
    def base_params(self):
        return {
            "Action": "CallWithBearerToken",
            "Version": "2023-09-30",
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": (
                "ASIATESTEXAMPLE/20260504/us-east-1/bedrock/aws4_request"
            ),
            "X-Amz-Date": "20260504T120000Z",
            "X-Amz-Expires": "43200",
            "X-Amz-SignedHeaders": "host",
            "X-Amz-Signature": "abc123def456" * 5,
        }

    def test_extracts_credential_components(self, base_params):
        params = dict(base_params)
        params["X-Amz-Security-Token"] = base64.b64encode(
            b"sessionmeta-123456789012-extra"
        ).decode()
        key = _build_short_term_key(params)

        result = BedrockKeyDecoder.decode_short_term_key(key)

        assert "error" not in result
        assert result["type"] == "short-term"
        assert result["access_key_id"] == "ASIATESTEXAMPLE"
        assert result["region"] == "us-east-1"
        assert result["service"] == "bedrock"
        assert result["account_id"] == "123456789012"
        assert result["action"] == "CallWithBearerToken"
        assert result["issued_at"] == "2026-05-04T12:00:00+00:00"
        assert result["expires_at"] == "2026-05-05T00:00:00+00:00"

    def test_without_security_token_account_id_is_unknown(self, base_params):
        key = _build_short_term_key(base_params)

        result = BedrockKeyDecoder.decode_short_term_key(key)

        assert "error" not in result
        assert result["account_id"] == "Unknown"


class TestDecodeKeyDispatcher:
    def test_unknown_prefix_returns_error(self):
        result = BedrockKeyDecoder.decode_key("AKIAIOSFODNN7EXAMPLE")

        assert result["error"] == "Unknown key format"
        assert "expected_formats" in result


class TestRedactForDisplay:
    def test_removes_plaintext_and_redacts_previews_without_mutation(self):
        original = {
            "type": "long-term",
            "username": "BedrockAPIKey-h42z",
            "secret_preview": "abc12345...",
            "credential_hint": "ASIATESTEXAMPLE/20260504/...",
            "full_decoded": "BedrockAPIKey-h42z-at-123456789012:plaintextsecret",
            "presigned_url": "bedrock.amazonaws.com/?Action=...",
        }
        original_snapshot = dict(original)

        safe = redact_for_display(original)

        assert "full_decoded" not in safe
        assert "presigned_url" not in safe
        assert safe["secret_preview"] == "[REDACTED]"
        assert safe["credential_hint"] == "[REDACTED]"
        assert safe["username"] == "BedrockAPIKey-h42z"

        assert original == original_snapshot
