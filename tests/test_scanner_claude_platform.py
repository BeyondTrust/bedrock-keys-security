"""Tests for the Claude Platform on AWS phantom user scanner.

Mocks the IAM client so the test suite runs offline. Mirrors the mocking
style used in tests/test_org_scan.py for the Bedrock scanner.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from bedrock_keys_security.core.scanner_claude_platform import (
    MANAGED_POLICY_ARN,
    ClaudePlatformPhantomScanner,
)


class _StubSession:
    """Minimal AWSSession surface needed by ClaudePlatformPhantomScanner."""

    def __init__(self, account_id="222222222222", region="us-east-1"):
        self.session = MagicMock()
        self.iam = MagicMock()
        self.sts = MagicMock()
        self.cloudtrail = MagicMock()
        self.account_id = account_id
        self.caller_arn = f"arn:aws:iam::{account_id}:user/admin"
        self.region = region


def _list_users_paginator(users):
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Users": users}])
    return paginator


def _aea_user(suffix="aaa1234"):
    name = f"AeaApiKey-{suffix}"
    return {
        "UserName": name,
        "UserId": f"AID{suffix.upper()}",
        "Arn": f"arn:aws:iam::222222222222:user/{name}",
        "CreateDate": datetime(2026, 5, 11, tzinfo=timezone.utc),
        "Path": "/",
    }


def _empty_iam(iam: MagicMock) -> None:
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_user_policies.return_value = {"PolicyNames": []}


def _with_anthropic_policy(iam: MagicMock) -> None:
    iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {"PolicyName": "AnthropicLimitedAccess", "PolicyArn": MANAGED_POLICY_ARN}
        ]
    }


def _with_active_credential(iam: MagicMock) -> None:
    iam.list_service_specific_credentials.return_value = {
        "ServiceSpecificCredentials": [
            {
                "UserName": "AeaApiKey-aaa",
                "Status": "Active",
                "ServiceCredentialAlias": "AeaApiKey-aaa-at-222222222222",
                "CreateDate": datetime(2026, 5, 11, tzinfo=timezone.utc),
                "ExpirationDate": datetime(2027, 5, 11, tzinfo=timezone.utc),
                "ServiceSpecificCredentialId": "ACCAEXAMPLE",
                "ServiceName": "aws-external-anthropic.amazonaws.com",
            }
        ]
    }


class TestFindPhantomUsers:
    def test_filters_to_aea_prefix(self):
        session = _StubSession()
        session.iam.get_paginator.return_value = _list_users_paginator([
            _aea_user("aaa"),
            {
                "UserName": "regular-user",
                "UserId": "AIDREGULAR",
                "Arn": "arn:aws:iam::222222222222:user/regular-user",
                "CreateDate": datetime(2026, 5, 11, tzinfo=timezone.utc),
                "Path": "/",
            },
            _aea_user("bbb"),
            {
                "UserName": "BedrockAPIKey-zzz",
                "UserId": "AIDBEDROCK",
                "Arn": "arn:aws:iam::222222222222:user/BedrockAPIKey-zzz",
                "CreateDate": datetime(2026, 5, 11, tzinfo=timezone.utc),
                "Path": "/",
            },
        ])
        _empty_iam(session.iam)

        scanner = ClaudePlatformPhantomScanner(session)
        phantoms = scanner.find_phantom_users()

        assert {p["username"] for p in phantoms} == {"AeaApiKey-aaa", "AeaApiKey-bbb"}
        assert scanner.last_users_scanned == 4

    def test_active_when_live_service_specific_credential(self):
        session = _StubSession()
        session.iam.get_paginator.return_value = _list_users_paginator([_aea_user("aaa")])
        _empty_iam(session.iam)
        _with_anthropic_policy(session.iam)
        _with_active_credential(session.iam)

        phantoms = ClaudePlatformPhantomScanner(session).find_phantom_users()

        assert len(phantoms) == 1
        assert phantoms[0]["status"] == "ACTIVE"
        assert phantoms[0]["active_claude_platform_credentials"] == 1
        assert phantoms[0]["has_anthropic_policy"] is True

    def test_orphaned_when_no_service_specific_credentials(self):
        session = _StubSession()
        session.iam.get_paginator.return_value = _list_users_paginator([_aea_user("aaa")])
        _empty_iam(session.iam)
        _with_anthropic_policy(session.iam)
        # Default _empty_iam leaves no service-specific credentials.

        phantoms = ClaudePlatformPhantomScanner(session).find_phantom_users()

        assert len(phantoms) == 1
        assert phantoms[0]["status"] == "ORPHANED"
        assert phantoms[0]["active_claude_platform_credentials"] == 0

    def test_akia_present_stays_active_not_at_risk(self):
        """An AKIA on an AeaApiKey-* user inherits AnthropicLimitedAccess which
        is workspace-scoped, so the credential does not expand the API key's
        blast radius. The scanner reports the AKIA via the access_keys column
        but does not escalate to AT RISK."""
        session = _StubSession()
        session.iam.get_paginator.return_value = _list_users_paginator([_aea_user("aaa")])
        _with_anthropic_policy(session.iam)
        _with_active_credential(session.iam)
        session.iam.list_user_policies.return_value = {"PolicyNames": []}
        session.iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAFAKEEXAMPLE", "Status": "Active"}
            ]
        }

        phantoms = ClaudePlatformPhantomScanner(session).find_phantom_users()

        assert phantoms[0]["status"] == "ACTIVE"
        assert phantoms[0]["access_key_ids"] == ["AKIAFAKEEXAMPLE"]
        assert phantoms[0]["active_access_keys"] == 1


class TestCategorizeStatus:
    def setup_method(self):
        self.scanner = ClaudePlatformPhantomScanner(_StubSession())

    def test_active_when_akia_only(self):
        """AKIA-only users are ACTIVE; the AKIA inherits AnthropicLimitedAccess
        which is workspace-scoped, so there is no escalation pivot to flag."""
        result = self.scanner.categorize_status({
            "active_access_keys": 1,
            "active_claude_platform_credentials": 0,
        })
        assert result == "ACTIVE"

    def test_active_when_live_credential(self):
        result = self.scanner.categorize_status({
            "active_access_keys": 0,
            "active_claude_platform_credentials": 1,
        })
        assert result == "ACTIVE"

    def test_active_when_both_credential_types(self):
        result = self.scanner.categorize_status({
            "active_access_keys": 1,
            "active_claude_platform_credentials": 1,
        })
        assert result == "ACTIVE"

    def test_orphaned_when_no_credentials(self):
        result = self.scanner.categorize_status({
            "active_access_keys": 0,
            "active_claude_platform_credentials": 0,
        })
        assert result == "ORPHANED"


class TestReports:
    def _scanner_with_one_active(self) -> ClaudePlatformPhantomScanner:
        session = _StubSession()
        session.iam.get_paginator.return_value = _list_users_paginator([_aea_user("aaa")])
        _empty_iam(session.iam)
        _with_anthropic_policy(session.iam)
        _with_active_credential(session.iam)
        return ClaudePlatformPhantomScanner(session)

    def test_table_report_contains_username_and_status(self):
        scanner = self._scanner_with_one_active()
        phantoms = scanner.find_phantom_users()
        report = scanner.phantom_table(phantoms)

        assert "AeaApiKey-aaa" in report
        assert "ACTIVE" in report

    def test_table_report_empty(self):
        scanner = ClaudePlatformPhantomScanner(_StubSession())
        scanner.iam.get_paginator.return_value = _list_users_paginator([])
        phantoms = scanner.find_phantom_users()

        report = scanner.phantom_table(phantoms)

        assert "No Claude Platform phantom users found" in report

    def test_json_report_is_valid_and_tags_service(self):
        scanner = self._scanner_with_one_active()
        phantoms = scanner.find_phantom_users()
        payload = json.loads(scanner.generate_json_report(phantoms))

        assert payload["scan_metadata"]["service"] == "claude-platform"
        assert payload["scan_metadata"]["account_id"] == "222222222222"
        assert payload["summary"]["total"] == 1
        assert payload["summary"]["active"] == 1
        assert payload["phantom_users"][0]["username"] == "AeaApiKey-aaa"


class TestCleanupOrphanedUsers:
    def test_no_orphans_short_circuits(self):
        scanner = ClaudePlatformPhantomScanner(_StubSession())
        result = scanner.cleanup_orphaned_users([], dry_run=True, force=True)

        assert result["service"] == "claude-platform"
        assert result["total_orphaned"] == 0
        assert result["deleted"] == 0

    def test_dry_run_does_not_call_delete(self):
        session = _StubSession()
        session.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
        session.iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
        session.iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        session.iam.list_user_policies.return_value = {"PolicyNames": []}

        scanner = ClaudePlatformPhantomScanner(session)

        phantoms = [{
            "username": "AeaApiKey-aaa",
            "created": datetime(2026, 5, 11, tzinfo=timezone.utc),
            "status": "ORPHANED",
            "active_access_keys": 0,
            "active_claude_platform_credentials": 0,
            "has_anthropic_policy": False,
        }]

        result = scanner.cleanup_orphaned_users(phantoms, dry_run=True, force=True)

        assert result["deleted"] == 1
        session.iam.delete_user.assert_not_called()
        session.iam.delete_service_specific_credential.assert_not_called()


# A ListWorkspaces management event for a SHORT_TERM Claude Platform key, modeled
# on a real 2026-05-29 capture with every identifier replaced by synthetic values
# (account 123456789012). Default-logged, no data-event selector: it carries the
# operator that wielded the key (an SSO session) plus the bearer-token signal.
# This is the event timeline/revoke now lean on.
_SHORT_TERM_ASIA = "ASIAEXAMPLE0000000002"
_SSO_SESSION_ARN = (
    "arn:aws:sts::123456789012:assumed-role/"
    "AWSReservedSSO_AdminAccess_1234567890abcdef/alice@example.com"
)
_SSO_ROLE_ARN = (
    "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/"
    "AWSReservedSSO_AdminAccess_1234567890abcdef"
)
_LISTWORKSPACES_EVENT = {
    "eventVersion": "1.11",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAEXAMPLE0000000001:alice@example.com",
        "arn": _SSO_SESSION_ARN,
        "accountId": "123456789012",
        "accessKeyId": _SHORT_TERM_ASIA,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "AROAEXAMPLE0000000001",
                "arn": _SSO_ROLE_ARN,
                "accountId": "123456789012",
                "userName": "AWSReservedSSO_AdminAccess_1234567890abcdef",
            },
            "attributes": {"creationDate": "2026-05-29T14:01:13Z", "mfaAuthenticated": "false"},
        },
        "onBehalfOf": {
            "userId": "00000000-0000-0000-0000-000000000001",
            "identityStoreArn": "arn:aws:identitystore::123456789012:identitystore/d-1234567890",
        },
    },
    "eventTime": "2026-05-29T16:12:21Z",
    "eventSource": "aws-external-anthropic.amazonaws.com",
    "eventName": "ListWorkspaces",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.10",
    "userAgent": "python-httpx/0.28.1",
    "requestParameters": {"bearerTokenType": "SHORT_TERM", "callWithBearerToken": True},
    "managementEvent": True,
    "eventCategory": "Management",
}


def _lookup_page(events):
    """Build a one-page lookup_events paginator mock yielding the given events."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Events": events}])
    return paginator


def _ct_event(cloudtrail_event):
    return {
        "EventId": "e9a5ecee-8798-486a-be47-9641c7fdf216",
        "EventName": cloudtrail_event["eventName"],
        "EventTime": datetime(2026, 5, 29, 16, 12, 21, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps(cloudtrail_event),
    }


class TestExtractActor:
    def test_pulls_identity_from_sso_event(self):
        actor = ClaudePlatformPhantomScanner._extract_actor(_LISTWORKSPACES_EVENT)
        assert actor["arn"] == _SSO_SESSION_ARN
        assert actor["type"] == "AssumedRole"
        assert actor["access_key_id"] == _SHORT_TERM_ASIA
        assert actor["session_issuer_arn"] == _SSO_ROLE_ARN
        assert actor["on_behalf_of_user_id"] == "00000000-0000-0000-0000-000000000001"

    def test_empty_identity_is_safe(self):
        actor = ClaudePlatformPhantomScanner._extract_actor({})
        assert actor["arn"] is None
        assert actor["session_issuer_arn"] is None


class TestTimelineByAccessKey:
    def test_short_term_key_timeline_surfaces_operator_and_bearer(self):
        session = _StubSession()
        session.session.client.return_value.get_paginator.return_value = _lookup_page(
            [_ct_event(_LISTWORKSPACES_EVENT)]
        )

        scanner = ClaudePlatformPhantomScanner(session)
        result = scanner.generate_timeline(access_key_id=_SHORT_TERM_ASIA, days=7)

        # Anchored on the ASIA, not a phantom username.
        assert result["lookup_attribute"] == "AccessKeyId"
        assert result["access_key_id"] == _SHORT_TERM_ASIA
        assert result["service"] == "claude-platform"
        assert result["total_events"] == 1

        ev = result["events"][0]
        assert ev["event_name"] == "ListWorkspaces"
        assert ev["call_with_bearer_token"] is True
        assert ev["bearer_token_type"] == "SHORT_TERM"
        assert ev["source_ip"] == "203.0.113.10"
        assert ev["user_agent"] == "python-httpx/0.28.1"
        # WHO used the key.
        assert ev["actor"]["arn"] == _SSO_SESSION_ARN
        assert ev["actor"]["session_issuer_arn"] == _SSO_ROLE_ARN

    def test_uses_access_key_lookup_attribute(self):
        session = _StubSession()
        paginator = _lookup_page([_ct_event(_LISTWORKSPACES_EVENT)])
        session.session.client.return_value.get_paginator.return_value = paginator

        ClaudePlatformPhantomScanner(session).generate_timeline(
            access_key_id=_SHORT_TERM_ASIA, days=7
        )

        _, kwargs = paginator.paginate.call_args
        assert kwargs["LookupAttributes"] == [
            {"AttributeKey": "AccessKeyId", "AttributeValue": _SHORT_TERM_ASIA}
        ]


class TestShortTermRevokeSurfacesOperator:
    def test_finds_sso_operator_and_refuses_overbroad_deny(self):
        session = _StubSession()
        session.cloudtrail.get_paginator.return_value = _lookup_page(
            [_ct_event(_LISTWORKSPACES_EVENT)]
        )

        scanner = ClaudePlatformPhantomScanner(session)
        # Decoding is offline and covered elsewhere; stub it to the embedded ASIA.
        scanner._decode_short_term = MagicMock(return_value={
            "access_key_id": _SHORT_TERM_ASIA,
            "account_id": "123456789012",
            "region": "us-east-1",
        })

        result = scanner.revoke_short_term_key("aws-external-anthropic-api-key-xxx", force=False)

        # The operator behind the key is recovered even though the deny is refused.
        assert result["access_key_id"] == _SHORT_TERM_ASIA
        assert result["issuer_arn"] == _SSO_ROLE_ARN
        assert result["actor"]["arn"] == _SSO_SESSION_ARN
        assert result["actor"]["source_ip"] == "203.0.113.10"
        # SSO-managed role: inline deny not allowed, so it refuses cleanly.
        assert result["success"] is False
        assert "SSO-managed role" in result["error"]
        session.iam.put_role_policy.assert_not_called()

    def test_no_usage_events_returns_simple_hint(self):
        session = _StubSession()
        session.cloudtrail.get_paginator.return_value = _lookup_page([])

        scanner = ClaudePlatformPhantomScanner(session)
        scanner._decode_short_term = MagicMock(return_value={
            "access_key_id": _SHORT_TERM_ASIA,
            "account_id": "123456789012",
            "region": "us-east-1",
        })

        result = scanner.revoke_short_term_key("aws-external-anthropic-api-key-xxx", force=False)

        assert result["success"] is False
        assert result["error"] == "issuing principal not found in CloudTrail"
