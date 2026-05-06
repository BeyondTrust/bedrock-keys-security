"""CLI UX tests for the v1.1.0 polish work.

Covers behavior that the decoder suite does not reach:
- output.set_quiet() suppression rules (info/success/warning/high_risk
  silenced; error always emits to stderr)
- format_decode_table_output() no longer carries a "Format:" line for
  either key type
- PhantomUserScanner.report_header() shape (2 visible lines)
- PhantomUserScanner.find_phantom_users() sets last_users_scanned to
  the total IAM users iterated, not just phantom matches
- cleanup_orphaned_users() pluralization at n=1 vs n>1
- build_output_path() shape and outputs/ directory creation

Stubs are intentionally minimal (MagicMock for the IAM client, a small
session-shape object) so the tests stay readable.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock

import click
import pytest

from bedrock_keys_security.commands.scan import build_output_path
from bedrock_keys_security.core.scanner import PhantomUserScanner
from bedrock_keys_security.utils import output


class _StubSession:
    """Just the AWSSession attributes PhantomUserScanner.__init__ reads."""

    def __init__(self, account_id="123456789012", region="us-east-1"):
        self.iam = MagicMock()
        self.sts = MagicMock()
        self.cloudtrail = MagicMock()
        self.account_id = account_id
        self.caller_arn = f"arn:aws:iam::{account_id}:user/test"
        self.region = region


def _stub_iam_empty(iam: MagicMock) -> None:
    """Make every IAM list_* call relevant to enrichment / cleanup return empty."""
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_user_policies.return_value = {"PolicyNames": []}


def _phantom(username: str, status: str, created: datetime = None) -> dict:
    return {
        "username": username,
        "status": status,
        "created": created or datetime(2026, 1, 1, tzinfo=timezone.utc),
    }


@pytest.fixture(autouse=True)
def _reset_quiet_mode():
    """Quiet flag is module-global; reset after each test so order does not matter."""
    yield
    output.set_quiet(False)


class TestOutputQuiet:
    def test_info_silenced_when_quiet(self, capsys):
        output.set_quiet(True)
        output.info("info-marker-12345")
        captured = capsys.readouterr()
        assert "info-marker-12345" not in captured.out
        assert "info-marker-12345" not in captured.err

    def test_success_silenced_when_quiet(self, capsys):
        output.set_quiet(True)
        output.success("success-marker-12345")
        captured = capsys.readouterr()
        assert "success-marker-12345" not in captured.out

    def test_warning_silenced_when_quiet(self, capsys):
        output.set_quiet(True)
        output.warning("warning-marker-12345")
        captured = capsys.readouterr()
        assert "warning-marker-12345" not in captured.out

    def test_high_risk_silenced_when_quiet(self, capsys):
        output.set_quiet(True)
        output.high_risk("high-risk-marker-12345")
        captured = capsys.readouterr()
        assert "high-risk-marker-12345" not in captured.out

    def test_error_still_emits_to_stderr_when_quiet(self, capsys):
        output.set_quiet(True)
        output.error("error-marker-12345")
        captured = capsys.readouterr()
        assert "error-marker-12345" in captured.err
        assert "error-marker-12345" not in captured.out

    def test_info_emits_when_not_quiet(self, capsys):
        output.set_quiet(False)
        output.info("info-when-loud-12345")
        captured = capsys.readouterr()
        assert "info-when-loud-12345" in captured.out


class TestFormatDecodeTableOutput:
    def test_long_term_omits_format_line(self):
        result = {
            "type": "long-term",
            "key_position": "primary",
            "username": "BedrockAPIKey-test",
            "iam_user_arn": "arn:aws:iam::123456789012:user/BedrockAPIKey-test",
            "account_id": "123456789012",
            "secret_preview": "abc12345...",
            "secret_length": 24,
            "secret_sha256_16": "deadbeefcafebabe",
        }
        rendered = click.unstyle(output.format_decode_table_output(result))
        assert "Format:" not in rendered
        assert "Type:" in rendered
        assert "BedrockAPIKey-test" in rendered

    def test_short_term_omits_format_line(self):
        result = {
            "type": "short-term",
            "hostname": "bedrock.amazonaws.com",
            "action": "CallWithBearerToken",
            "api_version": "2023-09-30",
            "access_key_id": "ASIATESTEXAMPLE",
            "service": "bedrock",
            "region": "us-east-1",
            "account_id": "123456789012",
            "issued_at": "2026-05-04T12:00:00+00:00",
            "expires_at": "2026-05-05T00:00:00+00:00",
            "expires_in_seconds": 43200,
            "algorithm": "AWS4-HMAC-SHA256",
            "signed_headers": "host",
            "signature_preview": "abc...",
        }
        rendered = click.unstyle(output.format_decode_table_output(result))
        assert "Format:" not in rendered
        assert "ASIATESTEXAMPLE" in rendered


class TestReportHeader:
    def test_two_line_banner(self):
        session = _StubSession(account_id="123456789012", region="eu-west-1")
        scanner = PhantomUserScanner(aws_session=session)

        visible = click.unstyle(scanner.report_header()).strip()
        lines = visible.splitlines()

        assert len(lines) == 2
        assert lines[0].startswith("bks v")
        assert "BedrockAPIKey-* phantom user scanner" in lines[0]
        assert "Account: 123456789012" in lines[1]
        assert "Region: eu-west-1" in lines[1]


class TestLastUsersScanned:
    def test_counts_all_iterated_users_not_just_phantoms(self):
        session = _StubSession()
        _stub_iam_empty(session.iam)
        paginator = MagicMock()
        paginator.paginate.return_value = iter([
            {"Users": [
                {"UserName": "alice", "UserId": "AID1", "Arn": "arn:1",
                 "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc), "Path": "/"},
                {"UserName": "BedrockAPIKey-aaa1", "UserId": "AID2", "Arn": "arn:2",
                 "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc), "Path": "/"},
            ]},
            {"Users": [
                {"UserName": "bob", "UserId": "AID3", "Arn": "arn:3",
                 "CreateDate": datetime(2026, 1, 1, tzinfo=timezone.utc), "Path": "/"},
            ]},
        ])
        session.iam.get_paginator.return_value = paginator

        scanner = PhantomUserScanner(aws_session=session)
        phantoms = scanner.find_phantom_users()

        assert scanner.last_users_scanned == 3
        assert [p["username"] for p in phantoms] == ["BedrockAPIKey-aaa1"]


class TestCleanupPluralization:
    def test_one_orphan_uses_singular_phrasing(self, capsys):
        session = _StubSession()
        _stub_iam_empty(session.iam)
        scanner = PhantomUserScanner(aws_session=session)

        scanner.cleanup_orphaned_users(
            [_phantom("BedrockAPIKey-aaa1", "ORPHANED")],
            dry_run=True,
            force=True,
        )

        out = click.unstyle(capsys.readouterr().out)
        assert "Orphaned Phantom User Found: 1" in out
        assert "Orphaned Phantom Users Found" not in out
        assert "This user has no active credentials" in out

    def test_multiple_orphans_use_plural_phrasing(self, capsys):
        session = _StubSession()
        _stub_iam_empty(session.iam)
        scanner = PhantomUserScanner(aws_session=session)

        phantoms = [
            _phantom(f"BedrockAPIKey-aaa{i}", "ORPHANED")
            for i in range(3)
        ]
        scanner.cleanup_orphaned_users(phantoms, dry_run=True, force=True)

        out = click.unstyle(capsys.readouterr().out)
        assert "Orphaned Phantom Users Found: 3" in out
        assert "The following users have no active credentials" in out


class TestBuildOutputPath:
    def test_scan_filename_shape(self, tmp_path):
        path = build_output_path("scan", "123456789012", "json", output_dir=tmp_path)
        assert path.parent == tmp_path
        assert path.name.startswith("bks-scan-123456789012-")
        assert path.name.endswith(".json")
        ts = path.stem.split("-")[-1]
        assert len(ts) == len("YYYYMMDDTHHMMSSZ")
        assert ts.endswith("Z")

    def test_decode_filename_shape(self, tmp_path):
        path = build_output_path("decode", "123456789012", "json", output_dir=tmp_path)
        assert path.name.startswith("bks-decode-123456789012-")
        assert path.name.endswith(".json")

    def test_creates_directory_when_missing(self, tmp_path):
        target = tmp_path / "nested" / "outputs"
        assert not target.exists()
        path = build_output_path("scan", "123456789012", "csv", output_dir=target)
        assert target.is_dir()
        assert path.parent == target
