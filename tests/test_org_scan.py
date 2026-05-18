"""Tests for the org-wide phantom user scanner.

OrgScanner is exercised with mocked organizations / sts / iam clients.
We don't want network or real AWS credentials in unit tests.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import json

import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from bedrock_keys_security.cli import cli
from bedrock_keys_security.core.org import (
    DEFAULT_ORG_ROLE,
    OrgScanError,
    OrgScanner,
    format_org_table_report,
    org_csv_report,
    org_csv_rows,
    org_json_report,
)
from bedrock_keys_security.utils import output


class _BaseStubSession:
    """Minimal AWSSession surface needed by OrgScanner.

    OrgScanner pulls organizations/sts off the base session, then for any
    account different from base.account_id calls AWSSession.from_credentials
    via _assume_role. We monkeypatch from_credentials in tests so we don't
    actually create boto3 sessions for member accounts.
    """

    def __init__(self, account_id="111111111111", region="us-east-1"):
        self.session = MagicMock()
        self.iam = MagicMock()
        self.sts = MagicMock()
        self.cloudtrail = MagicMock()
        self.account_id = account_id
        self.caller_arn = f"arn:aws:iam::{account_id}:user/admin"
        self.region = region

        self.organizations = MagicMock()
        self.session.client = MagicMock(
            side_effect=lambda name, region_name=None: {
                "organizations": self.organizations,
                "iam": self.iam,
                "sts": self.sts,
                "cloudtrail": self.cloudtrail,
            }[name]
        )


def _empty_iam(iam: MagicMock) -> None:
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_user_policies.return_value = {"PolicyNames": []}


def _list_users_paginator(users):
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{"Users": users}])
    return paginator


def _phantom_user(name="BedrockAPIKey-aaa"):
    return {
        "UserName": name,
        "UserId": f"AID{name[-3:]}",
        "Arn": f"arn:aws:iam::222222222222:user/{name}",
        "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "Path": "/",
    }


def _list_accounts_response(accounts):
    paginator = MagicMock()
    paginator.paginate.return_value = iter([{
        "Accounts": [
            {"Id": a["id"], "Name": a.get("name", ""), "Email": a.get("email", "x@y"),
             "Status": a.get("status", "ACTIVE")}
            for a in accounts
        ]
    }])
    return paginator


@pytest.fixture(autouse=True)
def _reset_quiet_mode():
    yield
    output.set_quiet(False)


@pytest.fixture
def patched_from_credentials(monkeypatch):
    """Replace AWSSession.from_credentials with a factory that returns
    pre-built stubs keyed by account_id, so _assume_role hands back our
    iam mocks instead of building real boto3 sessions.
    """
    member_sessions = {}

    def fake_factory(access_key, secret_key, session_token, region,
                     account_id, caller_arn, verbose=False):
        if account_id not in member_sessions:
            raise AssertionError(f"unexpected AssumeRole into {account_id}")
        return member_sessions[account_id]

    from bedrock_keys_security.utils import aws as aws_mod
    monkeypatch.setattr(aws_mod.AWSSession, "from_credentials", staticmethod(fake_factory))
    return member_sessions


class TestListAccounts:
    def test_filters_to_active_only(self):
        base = _BaseStubSession()
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt", "status": "ACTIVE"},
            {"id": "222222222222", "name": "prod", "status": "ACTIVE"},
            {"id": "333333333333", "name": "closed", "status": "SUSPENDED"},
        ])
        scanner = OrgScanner(base_session=base)
        accounts = scanner.list_accounts()
        assert [a["account_id"] for a in accounts] == ["111111111111", "222222222222"]

    def test_access_denied_raises_org_scan_error(self):
        base = _BaseStubSession()
        err = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListAccounts",
        )
        paginator = MagicMock()
        paginator.paginate.side_effect = err
        base.organizations.get_paginator.return_value = paginator

        scanner = OrgScanner(base_session=base)
        with pytest.raises(OrgScanError) as exc:
            scanner.list_accounts()
        assert "AccessDeniedException" in str(exc.value)
        assert "delegated admin" in str(exc.value)


class TestScanAll:
    def test_aggregates_across_accounts(self, patched_from_credentials):
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
            {"id": "222222222222", "name": "prod"},
        ])
        # Management account: 1 orphan phantom directly via base.iam.
        _empty_iam(base.iam)
        base.iam.get_paginator.return_value = _list_users_paginator([
            _phantom_user("BedrockAPIKey-mgmt1"),
        ])

        # Member account: 1 AT RISK phantom via the patched session.
        member = _BaseStubSession(account_id="222222222222")
        _empty_iam(member.iam)
        member.iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIATEST", "Status": "Active",
                 "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc)},
            ]
        }
        member.iam.get_paginator.return_value = _list_users_paginator([
            _phantom_user("BedrockAPIKey-prod1"),
        ])
        patched_from_credentials["222222222222"] = member

        base.sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA",
                "SecretAccessKey": "x",
                "SessionToken": "t",
                "Expiration": datetime(2099, 1, 1, tzinfo=timezone.utc),
            },
            "AssumedRoleUser": {
                "Arn": "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/bks",
                "AssumedRoleId": "AROA:bks",
            },
        }

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all()

        assert result["scan_metadata"]["mode"] == "org"
        assert result["scan_metadata"]["management_account_id"] == "111111111111"
        assert result["scan_metadata"]["accounts_total"] == 2
        assert result["scan_metadata"]["accounts_scanned"] == 2
        assert result["scan_metadata"]["accounts_failed"] == 0

        assert result["summary"] == {"total": 2, "active": 0, "orphaned": 1, "at_risk": 1}

        accounts_by_id = {a["account_id"]: a for a in result["accounts"]}
        assert accounts_by_id["111111111111"]["status"] == "ok"
        assert accounts_by_id["111111111111"]["summary"]["orphaned"] == 1
        assert accounts_by_id["222222222222"]["status"] == "ok"
        assert accounts_by_id["222222222222"]["summary"]["at_risk"] == 1

        # Management account scan should NOT trigger AssumeRole.
        assert base.sts.assume_role.call_count == 1

    def test_assume_role_failure_marks_account_error_does_not_abort(self, patched_from_credentials):
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
            {"id": "222222222222", "name": "denied"},
        ])
        _empty_iam(base.iam)
        base.iam.get_paginator.return_value = _list_users_paginator([])

        base.sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no role"}},
            "AssumeRole",
        )

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all()

        assert result["scan_metadata"]["accounts_scanned"] == 1
        assert result["scan_metadata"]["accounts_failed"] == 1

        denied = next(a for a in result["accounts"] if a["account_id"] == "222222222222")
        assert denied["status"] == "error"
        assert "AccessDenied" in denied["error"]

        ok = next(a for a in result["accounts"] if a["account_id"] == "111111111111")
        assert ok["status"] == "ok"

    def test_iam_failure_inside_member_account_does_not_abort(self, patched_from_credentials):
        """A ClientError inside scanner.find_phantom_users (e.g. ListUsers throttled,
        AccessDenied) for one member account must be captured as status=error in the
        result, never abort the org-wide run via sys.exit / SystemExit.
        """
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
            {"id": "222222222222", "name": "throttled"},
        ])
        # Management account scans clean.
        _empty_iam(base.iam)
        base.iam.get_paginator.return_value = _list_users_paginator([])

        # Member account: iam.list_users paginator raises ThrottlingException.
        member = _BaseStubSession(account_id="222222222222")
        _empty_iam(member.iam)
        throttled_paginator = MagicMock()
        throttled_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
            "ListUsers",
        )
        member.iam.get_paginator.return_value = throttled_paginator
        patched_from_credentials["222222222222"] = member

        base.sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA",
                "SecretAccessKey": "x",
                "SessionToken": "t",
                "Expiration": datetime(2099, 1, 1, tzinfo=timezone.utc),
            },
            "AssumedRoleUser": {
                "Arn": "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/bks",
                "AssumedRoleId": "AROA:bks",
            },
        }

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all()

        assert result["scan_metadata"]["accounts_scanned"] == 1
        assert result["scan_metadata"]["accounts_failed"] == 1
        throttled = next(a for a in result["accounts"] if a["account_id"] == "222222222222")
        assert throttled["status"] == "error"
        assert "ThrottlingException" in throttled["error"]
        ok = next(a for a in result["accounts"] if a["account_id"] == "111111111111")
        assert ok["status"] == "ok"

    def test_unexpected_exception_in_scanner_does_not_abort(self, patched_from_credentials):
        """A non-AWS exception (KeyError, AttributeError, etc.) inside scanner
        must be captured as status=error in the result, never abort the org-wide
        run. Catches all-Exception defense-in-depth path.
        """
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
            {"id": "222222222222", "name": "broken"},
        ])
        _empty_iam(base.iam)
        base.iam.get_paginator.return_value = _list_users_paginator([])

        member = _BaseStubSession(account_id="222222222222")
        _empty_iam(member.iam)
        member.iam.get_paginator.side_effect = KeyError("unexpected boto3 shape")
        patched_from_credentials["222222222222"] = member

        base.sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA",
                "SecretAccessKey": "x",
                "SessionToken": "t",
                "Expiration": datetime(2099, 1, 1, tzinfo=timezone.utc),
            },
            "AssumedRoleUser": {
                "Arn": "arn:aws:sts::222222222222:assumed-role/OrganizationAccountAccessRole/bks",
                "AssumedRoleId": "AROA:bks",
            },
        }

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all()

        assert result["scan_metadata"]["accounts_scanned"] == 1
        assert result["scan_metadata"]["accounts_failed"] == 1
        broken = next(a for a in result["accounts"] if a["account_id"] == "222222222222")
        assert broken["status"] == "error"
        assert "unexpected" in broken["error"]
        assert "KeyError" in broken["error"]

    def test_accounts_filter_scopes_run(self, patched_from_credentials):
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
            {"id": "222222222222", "name": "prod"},
            {"id": "333333333333", "name": "sandbox"},
        ])
        _empty_iam(base.iam)
        base.iam.get_paginator.return_value = _list_users_paginator([])

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all(accounts_filter=["111111111111"])

        assert result["scan_metadata"]["accounts_total"] == 1
        assert [a["account_id"] for a in result["accounts"]] == ["111111111111"]
        # No AssumeRole because only management account is in filter.
        assert base.sts.assume_role.call_count == 0

    def test_filter_matching_nothing_returns_empty_result(self, patched_from_credentials):
        """When --org-accounts filter matches zero accounts in the org, scan_all
        short-circuits with an empty result. No AssumeRole should be attempted.
        """
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
        ])

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all(accounts_filter=["999999999999"])

        assert result["scan_metadata"]["accounts_total"] == 0
        assert result["scan_metadata"]["accounts_scanned"] == 0
        assert result["scan_metadata"]["accounts_failed"] == 0
        assert result["accounts"] == []
        assert result["summary"] == {"total": 0, "active": 0, "orphaned": 0, "at_risk": 0}
        assert base.sts.assume_role.call_count == 0

    def test_skip_accounts_excludes(self, patched_from_credentials):
        base = _BaseStubSession(account_id="111111111111")
        base.organizations.get_paginator.return_value = _list_accounts_response([
            {"id": "111111111111", "name": "mgmt"},
            {"id": "222222222222", "name": "prod"},
        ])
        _empty_iam(base.iam)
        base.iam.get_paginator.return_value = _list_users_paginator([])

        scanner = OrgScanner(base_session=base)
        result = scanner.scan_all(skip_accounts=["222222222222"])

        assert [a["account_id"] for a in result["accounts"]] == ["111111111111"]


class TestFormatters:
    def test_table_renders_error_block_for_failed_account(self):
        result = {
            "scan_metadata": {
                "mode": "org",
                "management_account_id": "111111111111",
                "scan_time": "2026-05-10T00:00:00+00:00",
                "caller_arn": "arn:aws:iam::111111111111:user/admin",
                "role_assumed": DEFAULT_ORG_ROLE,
                "accounts_total": 1,
                "accounts_scanned": 0,
                "accounts_failed": 1,
            },
            "summary": {"total": 0, "active": 0, "orphaned": 0, "at_risk": 0},
            "accounts": [
                {"account_id": "222222222222", "account_name": "denied",
                 "status": "error", "error": "AssumeRole arn:...: AccessDenied",
                 "summary": {"total": 0, "active": 0, "orphaned": 0, "at_risk": 0}},
            ],
        }
        rendered = format_org_table_report(result)
        # ANSI styling is emitted; assert the substring presence not exact bytes.
        assert "Account: 222222222222 (denied)" in rendered
        assert "ERROR" in rendered
        assert "AccessDenied" in rendered

    def test_table_includes_at_risk_remediation_callout(self):
        """When the org has at-risk phantoms, the formatter prints the revoke-key
        remediation block so SOC operators know what to do next.
        """
        result = {
            "scan_metadata": {
                "mode": "org", "management_account_id": "111111111111",
                "scan_time": "2026-05-10T00:00:00+00:00",
                "caller_arn": "arn:aws:iam::111111111111:user/admin",
                "role_assumed": DEFAULT_ORG_ROLE,
                "accounts_total": 1, "accounts_scanned": 1, "accounts_failed": 0,
            },
            "summary": {"total": 1, "active": 0, "orphaned": 0, "at_risk": 1},
            "accounts": [
                {"account_id": "222222222222", "account_name": "prod",
                 "status": "ok",
                 "phantom_users": [
                    {"username": "BedrockAPIKey-x", "status": "AT RISK",
                     "created": datetime(2026, 1, 1, tzinfo=timezone.utc),
                     "active_bedrock_credentials": 0, "active_access_keys": 1,
                     "bedrock_credentials": 0, "access_keys": 1,
                     "access_key_ids": ["AKIAEXAMPLE"], "attached_policies": [], "inline_policies": []},
                 ],
                 "summary": {"total": 1, "active": 0, "orphaned": 0, "at_risk": 1}},
            ],
        }
        rendered = format_org_table_report(result)
        assert "AT RISK" in rendered
        assert "revoke-key" in rendered

    def test_csv_rows_one_per_phantom_with_account_columns(self):
        result = {
            "accounts": [
                {"account_id": "111111111111", "account_name": "mgmt",
                 "status": "ok", "phantom_users": [
                    {"username": "BedrockAPIKey-x", "status": "ORPHANED",
                     "created": datetime(2026, 1, 1, tzinfo=timezone.utc),
                     "active_bedrock_credentials": 0, "active_access_keys": 0,
                     "bedrock_credentials": 0, "access_keys": 0,
                     "access_key_ids": [], "attached_policies": [], "inline_policies": []},
                 ], "summary": {"total": 1, "active": 0, "orphaned": 1, "at_risk": 0}},
                {"account_id": "222222222222", "account_name": "denied",
                 "status": "error", "error": "x", "phantom_users": [],
                 "summary": {"total": 0, "active": 0, "orphaned": 0, "at_risk": 0}},
            ]
        }
        rows = org_csv_rows(result)
        assert len(rows) == 1
        assert rows[0]["account_id"] == "111111111111"
        assert rows[0]["account_name"] == "mgmt"
        assert rows[0]["username"] == "BedrockAPIKey-x"

    def test_json_report_serializes_datetimes(self):
        result = {
            "scan_metadata": {
                "mode": "org",
                "scan_time": datetime(2026, 5, 10, tzinfo=timezone.utc),
                "accounts_total": 1, "accounts_scanned": 1, "accounts_failed": 0,
            },
            "summary": {"total": 1, "active": 0, "orphaned": 1, "at_risk": 0},
            "accounts": [],
        }
        payload = json.loads(org_json_report(result))
        assert payload["scan_metadata"]["mode"] == "org"
        assert payload["scan_metadata"]["scan_time"] == "2026-05-10T00:00:00+00:00"

    def test_csv_report_writes_flattened_rows_with_account_columns(self, tmp_path):
        result = {
            "accounts": [
                {"account_id": "111111111111", "account_name": "mgmt",
                 "status": "ok", "phantom_users": [
                    {"username": "BedrockAPIKey-x", "user_id": "AID1", "status": "ORPHANED",
                     "created": datetime(2026, 1, 1, tzinfo=timezone.utc),
                     "active_bedrock_credentials": 0, "active_access_keys": 0,
                     "bedrock_credentials": 0, "access_keys": 0,
                     "access_key_ids": [], "attached_policies": ["AmazonBedrockLimitedAccess"],
                     "inline_policies": []},
                 ], "summary": {"total": 1, "active": 0, "orphaned": 1, "at_risk": 0}},
            ]
        }
        output_path = tmp_path / "org.csv"
        org_csv_report(result, str(output_path))
        content = output_path.read_text()
        assert content.startswith("account_id,account_name,username,")
        assert "111111111111,mgmt,BedrockAPIKey-x" in content
        assert "AmazonBedrockLimitedAccess" in content


class TestCliWiring:
    def test_org_role_without_org_flag_errors(self, monkeypatch):
        # Avoid building an AWSSession (which would call STS) by short-circuiting Context.scanner.
        # The validation we want runs before scanner is touched.
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--org-role", "MyRole"])
        assert result.exit_code != 0
        assert "--org" in result.output

    def test_invalid_org_accounts_format_rejected(self, monkeypatch):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--org", "--org-accounts", "not-an-account"])
        assert result.exit_code != 0
        assert "12-digit" in result.output

    def test_org_role_with_invalid_chars_rejected(self, monkeypatch):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "--org", "--org-role", "bad role with spaces"])
        assert result.exit_code != 0
        assert "--org-role" in result.output
