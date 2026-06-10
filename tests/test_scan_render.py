"""Tests for the combined single-account scan rendering.

Exercises the shared-chrome layout: one header, a per-service section
(label + grid + one-line summary), one combined remediation block, one
footer, identical styling across both surfaces. Scanners are built on
mocked sessions with find_phantom_users stubbed, so the suite runs offline.
"""

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import click

from bedrock_keys_security.commands import scan as scan_mod
from bedrock_keys_security.commands.cleanup import _render_combined_cleanup
from bedrock_keys_security.commands.scan import _render_combined_scan, _resolve_services
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


def _scanner(cls, phantoms, users_scanned=49):
    sc = cls(aws_session=_session())
    sc.last_users_scanned = users_scanned
    # The combined render pages the account-wide user list once (shared across
    # surfaces) then filters per surface; the stub returns a list whose length
    # drives the "N IAM users" footer and ignores it when producing phantoms.
    sc.list_iam_users = lambda: [None] * users_scanned
    sc.find_phantom_users = lambda users=None: phantoms
    return sc


def _ctx(quiet=False):
    return SimpleNamespace(obj=SimpleNamespace(quiet=quiet, output_dir=Path("output"), verbose=False))


def _D(y, m, d):
    return datetime(y, m, d, tzinfo=timezone.utc)


_BEDROCK = [
    {"username": "BedrockAPIKey-aa", "created": _D(2026, 1, 23), "status": "AT RISK",
     "active_bedrock_credentials": 0, "active_access_keys": 2},
    {"username": "BedrockAPIKey-bb", "created": _D(2026, 1, 24), "status": "ACTIVE",
     "active_bedrock_credentials": 1, "active_access_keys": 0},
    {"username": "BedrockAPIKey-cc", "created": _D(2026, 1, 25), "status": "ORPHANED",
     "active_bedrock_credentials": 0, "active_access_keys": 0},
]
_CLAUDE = [
    {"username": "AeaApiKey-xx", "created": _D(2026, 5, 13), "status": "ACTIVE",
     "active_claude_platform_credentials": 1, "active_access_keys": 0},
    {"username": "AeaApiKey-yy", "created": _D(2026, 5, 14), "status": "ORPHANED",
     "active_claude_platform_credentials": 0, "active_access_keys": 0},
]


class TestSummaryHelpers:
    def test_section_label(self):
        assert _scanner(PhantomUserScanner, []).section_label() == "Bedrock phantom users  (BedrockAPIKey-*)"
        assert (
            _scanner(ClaudePlatformPhantomScanner, []).section_label()
            == "Claude Platform phantom users  (AeaApiKey-*)"
        )

    def test_summary_line_bedrock_includes_at_risk(self):
        line = _scanner(PhantomUserScanner, _BEDROCK).summary_line(_BEDROCK)
        assert line == "3 phantom users  ·  1 at risk  ·  1 active  ·  1 orphaned"

    def test_summary_line_claude_omits_at_risk(self):
        line = _scanner(ClaudePlatformPhantomScanner, _CLAUDE).summary_line(_CLAUDE)
        assert "at risk" not in line
        assert line == "2 phantom users  ·  1 active  ·  1 orphaned"


class TestCombinedScan:
    def test_one_header_one_footer_combined_orphaned(self, capsys):
        bedrock = _scanner(PhantomUserScanner, _BEDROCK)
        claude = _scanner(ClaudePlatformPhantomScanner, _CLAUDE)

        n = _render_combined_scan(
            _ctx(), [(bedrock, "scan-bedrock"), (claude, "scan-claude-platform")],
            output_json=False, output_csv=False,
        )
        out = click.unstyle(capsys.readouterr().out)

        assert n == 5
        # Single shared header naming both surfaces; not repeated per service.
        assert out.count("phantom user scan: Bedrock + Claude Platform") == 1
        assert "Account: 123456789012  Region: us-east-1" in out
        # Per-service sections.
        assert "Bedrock phantom users  (BedrockAPIKey-*)" in out
        assert "Claude Platform phantom users  (AeaApiKey-*)" in out
        # One IAM-user count, one Scan complete footer.
        assert out.count("Scan complete") == 1
        assert "49 IAM users  ·  5 phantom users" in out
        # AT RISK is Bedrock-only; ORPHANED is combined (1 + 1).
        assert "AT RISK · 1 phantom user with persistent IAM credentials" in out
        assert "ORPHANED · 2 phantom users with no active credentials" in out

    def test_single_service_titles_one_surface(self, capsys):
        bedrock = _scanner(PhantomUserScanner, _BEDROCK)

        _render_combined_scan(
            _ctx(), [(bedrock, "scan")], output_json=False, output_csv=False,
        )
        out = click.unstyle(capsys.readouterr().out)

        assert "phantom user scan: Bedrock" in out
        assert "Claude Platform" not in out
        assert out.count("Scan complete") == 1

    def test_quiet_suppresses_console(self, capsys):
        bedrock = _scanner(PhantomUserScanner, _BEDROCK)
        claude = _scanner(ClaudePlatformPhantomScanner, _CLAUDE)

        _render_combined_scan(
            _ctx(quiet=True), [(bedrock, "scan-bedrock"), (claude, "scan-claude-platform")],
            output_json=False, output_csv=False,
        )
        out = capsys.readouterr().out

        assert out.strip() == ""


class TestResolveServices:
    def test_single_bedrock_keeps_bare_tag(self):
        ctx = _ctx()
        ctx.obj.scanner = object()
        ctx.obj.claude_platform_scanner = object()
        services = _resolve_services(ctx, "bedrock", "scan")
        assert [t for _, t in services] == ["scan"]

    def test_all_disambiguates_tags(self):
        ctx = _ctx()
        ctx.obj.scanner = object()
        ctx.obj.claude_platform_scanner = object()
        services = _resolve_services(ctx, "all", "cleanup")
        assert [t for _, t in services] == ["cleanup-bedrock", "cleanup-claude-platform"]


def _empty_iam(scanner):
    scanner.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    scanner.iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
    scanner.iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    scanner.iam.list_user_policies.return_value = {"PolicyNames": []}
    return scanner


class TestCombinedCleanup:
    def test_one_header_both_sections(self, capsys):
        bedrock = _empty_iam(_scanner(PhantomUserScanner, _BEDROCK))
        claude = _empty_iam(_scanner(ClaudePlatformPhantomScanner, _CLAUDE))

        failed = _render_combined_cleanup(
            _ctx(), [(bedrock, "cleanup-bedrock"), (claude, "cleanup-claude-platform")],
            dry_run=True, force=True, output_json=False,
        )
        out = click.unstyle(capsys.readouterr().out)

        assert failed == 0
        # Same shared chrome as scan: one header, both per-service sections.
        assert out.count("phantom user cleanup: Bedrock + Claude Platform") == 1
        assert "Bedrock phantom users  (BedrockAPIKey-*)" in out
        assert "Claude Platform phantom users  (AeaApiKey-*)" in out
        # Dry-run never deletes.
        bedrock.iam.delete_user.assert_not_called()
        claude.iam.delete_user.assert_not_called()


class TestCombinedOrgScan:
    def test_one_banner_one_footer_combined_totals(self, capsys, monkeypatch):
        class _FakeOrg:
            _totals = iter([2, 1])  # bedrock -> 2 phantoms, claude -> 1

            def __init__(self, **kwargs):
                pass

            def scan_all(self, **kwargs):
                return {
                    "scan_metadata": {"accounts_total": 3, "accounts_scanned": 3,
                                      "accounts_failed": 0, "role_assumed": "OrgRole"},
                    "summary": {"total": next(_FakeOrg._totals)},
                    "accounts": [],
                }

        monkeypatch.setattr(scan_mod, "OrgScanner", _FakeOrg)
        monkeypatch.setattr(
            scan_mod, "format_org_table_report",
            lambda result, scanner_class=None: f"[table total={result['summary']['total']}]",
        )

        base = MagicMock()
        base.aws_session = MagicMock(account_id="123456789012", region="us-east-1")
        ctx = SimpleNamespace(
            obj=SimpleNamespace(quiet=False, verbose=False, output_dir=Path("output"), scanner=base)
        )

        scan_mod._run_org_scans(
            ctx, org_role="OrgRole", accounts_filter=None, skip_accounts=None,
            output_json=False, output_csv=False,
            service_choices=["bedrock", "claude-platform"], combined_run=True,
        )
        out = click.unstyle(capsys.readouterr().out)

        # One banner, one management-account line, one footer with combined totals.
        assert out.count("org scan: Bedrock + Claude Platform") == 1
        assert out.count("Management account: 123456789012") == 1
        assert out.count("Org scan complete") == 1
        assert "3/3 accounts" in out
        assert "3 phantom users" in out  # 2 + 1 across surfaces
