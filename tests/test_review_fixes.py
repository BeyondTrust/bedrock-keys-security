"""Regression tests for the code-review findings fixed before Arsenal.

Each test pins the corrected behaviour of one finding and would fail against
the pre-fix code, so the suite both validates the fix and guards the regression.
Everything runs offline on mocked boto3 clients.

Findings covered here:
  #1  combined cleanup isolates a per-surface scan failure (no partial crash)
  #5  revoke-key --dry-run honours the self-revoke gate (preview == real run)
  #6  Bedrock report --json carries a top-level "service" key (parity)
  #8  combined scan isolates a per-surface failure and still exits non-zero
  #9  short-term issuer resolution reports a root principal (not "not found")
  #10 generate_timeline rejects a call with no anchor instead of crashing deep
  #11 report --json --output collects incident data once, not twice
  #12 combined scan pages iam:ListUsers once, shared across surfaces
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import click
import pytest
from botocore.exceptions import ClientError
from click.testing import CliRunner

from bedrock_keys_security.cli import Context
from bedrock_keys_security.commands.cleanup import _render_combined_cleanup
from bedrock_keys_security.commands.report import report
from bedrock_keys_security.commands.scan import _render_combined_scan
from bedrock_keys_security.core.scanner import PhantomUserScanner
from bedrock_keys_security.core.scanner_claude_platform import (
    ClaudePlatformPhantomScanner,
)


def _session(account_id="123456789012", region="us-east-1", caller_arn=None):
    s = MagicMock()
    s.session = MagicMock()
    s.iam = MagicMock()
    s.sts = MagicMock()
    s.cloudtrail = MagicMock()
    s.account_id = account_id
    s.caller_arn = caller_arn or f"arn:aws:iam::{account_id}:user/admin"
    s.region = region
    return s


def _ctx(quiet=False):
    return SimpleNamespace(
        obj=SimpleNamespace(quiet=quiet, output_dir=Path("output"), verbose=False)
    )


def _D(y, m, d):
    return datetime(y, m, d, tzinfo=timezone.utc)


def _scan_scanner(cls, phantoms, users_scanned=49):
    sc = cls(aws_session=_session())
    sc.last_users_scanned = users_scanned
    sc.list_iam_users = lambda: [None] * users_scanned
    sc.find_phantom_users = lambda users=None: phantoms
    return sc


def _empty_iam(sc):
    sc.iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    sc.iam.list_service_specific_credentials.return_value = {"ServiceSpecificCredentials": []}
    sc.iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    sc.iam.list_user_policies.return_value = {"PolicyNames": []}
    return sc


_BEDROCK = [
    {"username": "BedrockAPIKey-bb", "created": _D(2026, 1, 24), "status": "ACTIVE",
     "active_bedrock_credentials": 1, "active_access_keys": 0},
    {"username": "BedrockAPIKey-cc", "created": _D(2026, 1, 25), "status": "ORPHANED",
     "active_bedrock_credentials": 0, "active_access_keys": 0},
]
_CLAUDE = [
    {"username": "AeaApiKey-yy", "created": _D(2026, 5, 14), "status": "ORPHANED",
     "active_claude_platform_credentials": 0, "active_access_keys": 0},
]


def _client_error(code="AccessDenied", op="ListUsers"):
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, op)


# --- #10 ------------------------------------------------------------------

def test_generate_timeline_requires_an_anchor():
    """No username and no access key is a programming error, not a deep crash."""
    sc = PhantomUserScanner(aws_session=_session())
    with pytest.raises(ValueError):
        sc.generate_timeline()


# --- #6 -------------------------------------------------------------------

def test_incident_data_service_key_parity():
    """report --json carries a top-level service tag on both surfaces."""
    bedrock = PhantomUserScanner(aws_session=_session())
    bedrock.iam.get_user.side_effect = _client_error("NoSuchEntity", "GetUser")
    assert bedrock.collect_incident_data("BedrockAPIKey-x")["service"] == "bedrock"

    claude = ClaudePlatformPhantomScanner(aws_session=_session())
    claude.iam.get_user.side_effect = _client_error("NoSuchEntity", "GetUser")
    assert claude.collect_incident_data("AeaApiKey-x")["service"] == "claude-platform"


# --- #5 -------------------------------------------------------------------

def _self_revoke_scanner():
    caller = "arn:aws:sts::123456789012:assumed-role/MyRole/session-1"
    sc = PhantomUserScanner(aws_session=_session(caller_arn=caller))
    sc._decode_short_term = lambda key: {
        "access_key_id": "ASIAEXAMPLE0000000001",
        "account_id": "123456789012",
        "region": "us-east-1",
    }
    sc._find_short_term_issuer = lambda akid: (
        "arn:aws:iam::123456789012:role/MyRole", "MyRole", "role",
        {"arn": caller},
    )
    return sc


def test_dryrun_self_revoke_without_force_refuses():
    """Preview must mirror the real run: a self-revoke without --force is refused."""
    sc = _self_revoke_scanner()
    result = sc.revoke_short_term_key("dummy", dry_run=True, force=False)
    assert result["self_revoke"] is True
    assert result["success"] is False
    assert result["error"] == "self-revoke blocked without --force"


def test_dryrun_self_revoke_with_force_still_previews_apply():
    """--force keeps the would-apply preview (guards against over-correcting #5)."""
    sc = _self_revoke_scanner()
    result = sc.revoke_short_term_key("dummy", dry_run=True, force=True)
    assert result["success"] is True
    assert "error" not in result


# --- #9 -------------------------------------------------------------------

def test_short_term_issuer_reports_root():
    """A key used under root resolves to a root principal, not '(None)'."""
    sc = PhantomUserScanner(aws_session=_session())
    root_event = {"CloudTrailEvent": json.dumps({
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "sourceIPAddress": "1.2.3.4", "userAgent": "agent/1.0",
    })}
    sc.cloudtrail.get_paginator.return_value.paginate.return_value = [
        {"Events": [root_event]}
    ]
    arn, name, kind, actor = sc._find_short_term_issuer("ASIAEXAMPLE0000000001")
    assert kind == "root"
    assert arn == "arn:aws:iam::123456789012:root"
    assert actor["source_ip"] == "1.2.3.4"


def test_revoke_short_term_root_principal_reports_clear_error():
    """Root is not revocable via an IAM user/role policy: clear error, no put_*_policy."""
    sc = PhantomUserScanner(aws_session=_session())
    sc._decode_short_term = lambda key: {
        "access_key_id": "ASIAEXAMPLE0000000001",
        "account_id": "123456789012", "region": "us-east-1",
    }
    sc._find_short_term_issuer = lambda akid: (
        "arn:aws:iam::123456789012:root", "root", "root",
        {"arn": "arn:aws:iam::123456789012:root"},
    )
    result = sc.revoke_short_term_key("dummy", dry_run=False, force=True)
    assert result["success"] is False
    assert result["error"] == "root principal; not revocable via IAM policy"
    sc.iam.put_user_policy.assert_not_called()
    sc.iam.put_role_policy.assert_not_called()


# --- #8 -------------------------------------------------------------------

def test_combined_scan_isolates_surface_failure(capsys):
    """One surface's IAM error is reported and skipped; the other still renders
    and a non-zero exit is still raised at the end."""
    bedrock = _scan_scanner(PhantomUserScanner, _BEDROCK)
    claude = _scan_scanner(ClaudePlatformPhantomScanner, _CLAUDE)
    claude.find_phantom_users = MagicMock(side_effect=_client_error())

    with pytest.raises(SystemExit) as exc:
        _render_combined_scan(
            _ctx(), [(bedrock, "scan-bedrock"), (claude, "scan-claude-platform")],
            output_json=False, output_csv=False,
        )
    assert exc.value.code == 1

    out = click.unstyle(capsys.readouterr().out)
    assert "Bedrock phantom users  (BedrockAPIKey-*)" in out       # working surface rendered
    assert "BedrockAPIKey-bb" in out                 # ... including its phantom rows
    assert "surface(s) failed to scan" in out        # the failure is reported, not swallowed
    assert "Scan complete" in out                    # footer still printed for the survivor


def test_combined_scan_all_surfaces_fail_emits_no_success_footer(capsys):
    """When every surface fails, no 'Scan complete' success line is printed (it
    would mislead a log scraper); the run still exits non-zero."""
    bedrock = _scan_scanner(PhantomUserScanner, _BEDROCK)
    claude = _scan_scanner(ClaudePlatformPhantomScanner, _CLAUDE)
    bedrock.find_phantom_users = MagicMock(side_effect=_client_error())
    claude.find_phantom_users = MagicMock(side_effect=_client_error())

    with pytest.raises(SystemExit) as exc:
        _render_combined_scan(
            _ctx(), [(bedrock, "scan-bedrock"), (claude, "scan-claude-platform")],
            output_json=False, output_csv=False,
        )
    assert exc.value.code == 1
    out = click.unstyle(capsys.readouterr().out)
    assert "Scan complete" not in out                # no success-looking footer
    assert "2 surface(s) failed to scan" in out


# --- #1 -------------------------------------------------------------------

def test_combined_cleanup_isolates_second_surface_failure(capsys):
    """A second-surface scan failure is caught (no raw traceback) after the
    first surface already ran, and it counts toward the non-zero exit."""
    bedrock = _empty_iam(_scan_scanner(PhantomUserScanner, _BEDROCK))
    claude = _scan_scanner(ClaudePlatformPhantomScanner, _CLAUDE)
    claude.find_phantom_users = MagicMock(side_effect=_client_error(op="ListUsers"))

    # Must not raise: the failure is isolated, not propagated as a crash.
    failed = _render_combined_cleanup(
        _ctx(), [(bedrock, "cleanup-bedrock"), (claude, "cleanup-claude-platform")],
        dry_run=True, force=True, output_json=False,
    )
    assert failed >= 1
    out = click.unstyle(capsys.readouterr().out)
    assert "Bedrock phantom users  (BedrockAPIKey-*)" in out
    bedrock.iam.delete_user.assert_not_called()  # dry-run never deletes


# --- #12 ------------------------------------------------------------------

def test_combined_scan_pages_list_users_once():
    """Both surfaces share one iam:ListUsers pass instead of paging it twice."""
    session = _session()
    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Users": [
            {"UserName": "alice", "UserId": "AID", "Arn": "arn:aws:iam::123456789012:user/alice",
             "CreateDate": _D(2026, 1, 1), "Path": "/"},
        ]}
    ]
    session.iam.get_paginator.return_value = paginator

    bedrock = PhantomUserScanner(aws_session=session)
    claude = ClaudePlatformPhantomScanner(aws_session=session)

    _render_combined_scan(
        _ctx(quiet=True), [(bedrock, "scan-bedrock"), (claude, "scan-claude-platform")],
        output_json=False, output_csv=False,
    )

    list_users_calls = [
        c for c in session.iam.get_paginator.call_args_list if c.args == ("list_users",)
    ]
    assert len(list_users_calls) == 1


# --- #11 ------------------------------------------------------------------

def _incident_dict():
    return {
        "service": "bedrock",
        "username": "BedrockAPIKey-x",
        "account_id": "123456789012",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user": None,
        "bedrock_credentials": [],
        "iam_access_keys": [],
        "attached_policies": [],
        "inline_policies": [],
        "errors": [],
    }


def test_report_json_and_output_collects_once(tmp_path):
    """report --json --output reuses the collected snapshot for the text report
    instead of fetching the same IAM data a second time."""
    sc = PhantomUserScanner(aws_session=_session())
    sc.collect_incident_data = MagicMock(return_value=_incident_dict())

    ctx_obj = Context()
    ctx_obj._scanner = sc                 # bypass lazy AWS init
    ctx_obj.output_dir = tmp_path

    out_file = tmp_path / "report.txt"
    result = CliRunner().invoke(
        report,
        ["BedrockAPIKey-x", "--json", "--output", str(out_file)],
        obj=ctx_obj,
    )

    assert result.exit_code == 0, result.output
    assert sc.collect_incident_data.call_count == 1
    assert out_file.exists()


def test_incident_report_file_is_not_world_readable(tmp_path):
    """The text incident report (--output FILE) is chmod 0600 like JSON/CSV outputs;
    it carries full ARNs / access-key ids / policies and must not be world-readable."""
    sc = PhantomUserScanner(aws_session=_session())
    sc.collect_incident_data = MagicMock(return_value=_incident_dict())
    out = tmp_path / "report.txt"
    sc.generate_incident_report("BedrockAPIKey-x", output_file=str(out))
    assert out.exists()
    mode = out.stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)
