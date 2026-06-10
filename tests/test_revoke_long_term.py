"""Tests for the shared long-term ``revoke_key`` flow.

``revoke_key`` lives once on ``BasePhantomScanner`` and is parametrised per
surface by ``REVOKE_DENY_ACTION`` / ``REVOKE_DENY_SID`` and the
``_revoke_verify_hint`` hook. These tests pin, for each surface, that the
correct deny lands and that the shared steps (delete service-specific
credentials, disable AKIAs, dry-run, cancel) behave identically. The IAM
client is mocked so the suite runs offline.
"""

import json
from unittest.mock import MagicMock

import click
import pytest

from bedrock_keys_security.core.scanner import PhantomUserScanner
from bedrock_keys_security.core.scanner_claude_platform import (
    ClaudePlatformPhantomScanner,
)


def _session(account_id="123456789012", region="us-east-1"):
    s = MagicMock()
    s.session = MagicMock()
    s.iam = MagicMock()
    s.sts = MagicMock()
    s.cloudtrail = MagicMock()
    s.account_id = account_id
    s.caller_arn = f"arn:aws:iam::{account_id}:user/admin"
    s.region = region
    return s


def _scanner(cls):
    """Scanner whose phantom has one service-specific credential and one active AKIA."""
    s = _session()
    s.iam.list_service_specific_credentials.return_value = {
        "ServiceSpecificCredentials": [{"ServiceSpecificCredentialId": "ACCA1EXAMPLE"}]
    }
    s.iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [{"AccessKeyId": "AKIA1EXAMPLE", "Status": "Active"}]
    }
    return cls(aws_session=s)


_SURFACES = [
    pytest.param(PhantomUserScanner, "bedrock:*", "DenyBedrockAPIKeyUsage",
                 "bedrock", "bedrock.amazonaws.com", id="bedrock"),
    pytest.param(ClaudePlatformPhantomScanner, "aws-external-anthropic:*",
                 "DenyClaudePlatformUsage", "claude-platform",
                 "aws-external-anthropic.amazonaws.com", id="claude-platform"),
]


class TestRevokeKeyPerSurface:
    @pytest.mark.parametrize("cls,action,sid,service,ssc_service", _SURFACES)
    def test_applies_correct_deny_and_cleans_up(self, cls, action, sid, service, ssc_service):
        scanner = _scanner(cls)
        result = scanner.revoke_key("phantom-user", force=True)

        # The inline deny carries the surface's own action and Sid.
        scanner.iam.put_user_policy.assert_called_once()
        doc = json.loads(scanner.iam.put_user_policy.call_args.kwargs["PolicyDocument"])
        stmt = doc["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Action"] == action
        assert stmt["Sid"] == sid

        # Service-specific credentials are listed for the right service and deleted.
        scanner.iam.list_service_specific_credentials.assert_called_with(
            UserName="phantom-user", ServiceName=ssc_service
        )
        scanner.iam.delete_service_specific_credential.assert_called_once_with(
            UserName="phantom-user", ServiceSpecificCredentialId="ACCA1EXAMPLE"
        )

        # Active AKIA is disabled, not deleted.
        scanner.iam.update_access_key.assert_called_once_with(
            UserName="phantom-user", AccessKeyId="AKIA1EXAMPLE", Status="Inactive"
        )

        assert result["success"] is True
        assert result["service"] == service
        assert result["key_kind"] == "long-term"
        actions = {a["action"] for a in result["actions"]}
        assert actions == {"deny_policy", "delete_ssc", "disable_access_key"}

    @pytest.mark.parametrize("cls,action,sid,service,ssc_service", _SURFACES)
    def test_dry_run_makes_no_iam_writes(self, cls, action, sid, service, ssc_service):
        scanner = _scanner(cls)
        result = scanner.revoke_key("phantom-user", dry_run=True)

        assert result["success"] is True
        assert result["dry_run"] is True
        scanner.iam.put_user_policy.assert_not_called()
        scanner.iam.delete_service_specific_credential.assert_not_called()
        scanner.iam.update_access_key.assert_not_called()

    @pytest.mark.parametrize("cls,action,sid,service,ssc_service", _SURFACES)
    def test_cancel_without_force_makes_no_iam_writes(self, cls, action, sid, service,
                                                      ssc_service, monkeypatch):
        monkeypatch.setattr(click, "confirm", lambda *a, **k: False)
        scanner = _scanner(cls)
        result = scanner.revoke_key("phantom-user", force=False)

        assert result.get("cancelled") is True
        assert result["success"] is False
        scanner.iam.put_user_policy.assert_not_called()
