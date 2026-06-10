"""Tests for the timeline command's key-routing glue.

Covers the short-term path that is new in this change: a short-term key is
decoded offline to its embedded ASIA and the timeline is anchored on
``AccessKeyId=`` against the matching service scanner. Long-term keys and
phantom usernames keep routing through resolve_username/select_scanner.
"""

import base64
from unittest.mock import MagicMock

import click
import pytest
from click.testing import CliRunner

from bedrock_keys_security.cli import Context, cli
from bedrock_keys_security.commands.timeline import _decode_short_term_asia
from bedrock_keys_security.core.decoder_claude_platform import ClaudePlatformKeyDecoder


def _claude_short_term_key(asia="ASIAROUTINGTEST", region="us-east-1"):
    url = (
        "aws-external-anthropic.amazonaws.com/?Action=CallWithBearerToken"
        f"&X-Amz-Credential={asia}/20260529/{region}/aws-external-anthropic/aws4_request"
        "&X-Amz-Date=20260529T000000Z&X-Amz-Expires=43200"
        "&X-Amz-Signature=deadbeef&X-Amz-SignedHeaders=host&Version=1"
    )
    return "aws-external-anthropic-api-key-" + base64.b64encode(url.encode()).decode()


def _bedrock_short_term_key(asia="ASIABEDROCKTEST", region="us-west-2"):
    url = (
        "bedrock.amazonaws.com/?Action=CallWithBearerToken"
        f"&X-Amz-Credential={asia}/20260529/{region}/bedrock/aws4_request"
        "&X-Amz-Date=20260529T000000Z&X-Amz-Expires=43200"
        "&X-Amz-Signature=deadbeef&X-Amz-SignedHeaders=host&Version=1"
    )
    return "bedrock-api-key-" + base64.b64encode(url.encode()).decode()


class TestDecodeShortTermAsia:
    def test_returns_asia_and_region(self):
        key = _claude_short_term_key("ASIAEXAMPLE123", "eu-west-1")
        asia, region = _decode_short_term_asia(ClaudePlatformKeyDecoder, key, "Claude Platform")
        assert asia == "ASIAEXAMPLE123"
        assert region == "eu-west-1"

    def test_rejects_garbage(self):
        with pytest.raises(click.ClickException):
            _decode_short_term_asia(
                ClaudePlatformKeyDecoder,
                "aws-external-anthropic-api-key-!!!notb64!!!",
                "Claude Platform",
            )


def _runner_obj():
    """A real CLI Context with both lazy scanners pre-set to mocks.

    Must be a genuine ``Context`` instance: the group callback calls
    ``ctx.ensure_object(Context)``, which discards an injected object that is
    not a ``Context`` and builds a real one (triggering AWS init). Pre-seeding
    the private ``_scanner`` / ``_claude_platform_scanner`` makes the lazy
    properties return the mocks without ever touching AWS.
    """
    obj = Context()
    obj._scanner = MagicMock()
    obj._claude_platform_scanner = MagicMock()
    obj._scanner.generate_timeline.return_value = {}
    obj._claude_platform_scanner.generate_timeline.return_value = {}
    return obj


class TestTimelineRouting:
    def test_claude_short_term_anchors_on_access_key(self):
        obj = _runner_obj()
        key = _claude_short_term_key("ASIACLAUDE999", "us-east-1")

        result = CliRunner().invoke(cli, ["timeline", key], obj=obj)

        assert result.exit_code == 0, result.output
        obj.claude_platform_scanner.generate_timeline.assert_called_once()
        _, kwargs = obj.claude_platform_scanner.generate_timeline.call_args
        assert kwargs["access_key_id"] == "ASIACLAUDE999"
        assert kwargs["region_hint"] == "us-east-1"
        obj.scanner.generate_timeline.assert_not_called()

    def test_bedrock_short_term_routes_to_bedrock_scanner(self):
        obj = _runner_obj()
        key = _bedrock_short_term_key("ASIABEDROCK111", "us-west-2")

        result = CliRunner().invoke(cli, ["timeline", key], obj=obj)

        assert result.exit_code == 0, result.output
        obj.scanner.generate_timeline.assert_called_once()
        _, kwargs = obj.scanner.generate_timeline.call_args
        assert kwargs["access_key_id"] == "ASIABEDROCK111"
        assert kwargs["region_hint"] == "us-west-2"
        obj.claude_platform_scanner.generate_timeline.assert_not_called()
