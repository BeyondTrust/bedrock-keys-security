"""Organization-wide phantom user scanner.

Runs from a delegated-admin or management account, calls
organizations:ListAccounts to enumerate members, AssumeRoles into each
ACTIVE account using a shared role name, then runs the existing
PhantomUserScanner per account in parallel. Results are merged into a
single aggregate report.

Per-account failures (AssumeRole denied, IAM throttled, etc.) are
captured per-account and do not abort the scan; the failing account is
marked status=error in the output.
"""

import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional

from botocore.exceptions import BotoCoreError, ClientError
from tabulate import tabulate

from bedrock_keys_security.core.scanner import PhantomUserScanner, _csv_safe, _json_default
from bedrock_keys_security.utils import output
from bedrock_keys_security.utils.aws import AWSSession


DEFAULT_ORG_ROLE = "OrganizationAccountAccessRole"

# AssumeRole + per-account IAM enumeration is heavier than single-account
# scan; cap account concurrency conservatively to avoid throttling the
# management account's STS endpoint and the per-account IAM endpoint.
ORG_MAX_WORKERS = 8

# 15 minutes is enough for the IAM list + enrich cycle of one account.
# Short duration limits blast radius if a session token leaks via logs.
ORG_ASSUME_DURATION = 900


class OrgScanError(Exception):
    """Raised for org-level setup failures (ListAccounts denied, etc.).

    Per-account failures during scan_all are captured in the result dict,
    not raised, so a single bad account doesn't abort the whole run.
    """


def _empty_summary() -> Dict[str, int]:
    return {"total": 0, "active": 0, "orphaned": 0, "at_risk": 0}


def _summarize(phantoms: List[Dict]) -> Dict[str, int]:
    return {
        "total": len(phantoms),
        "active": sum(1 for p in phantoms if p["status"] == "ACTIVE"),
        "orphaned": sum(1 for p in phantoms if p["status"] == "ORPHANED"),
        "at_risk": sum(1 for p in phantoms if p["status"] == "AT RISK"),
    }


class OrgScanner:
    """Scan every active account in an AWS Organization for phantom Bedrock users."""

    def __init__(
        self,
        base_session: AWSSession,
        role_name: str = DEFAULT_ORG_ROLE,
        verbose: bool = False,
        max_workers: int = ORG_MAX_WORKERS,
    ):
        self.base = base_session
        self.role_name = role_name
        self.verbose = verbose
        self.max_workers = max_workers
        self.organizations = base_session.session.client(
            "organizations", region_name=base_session.region
        )
        self.sts = base_session.sts

    def list_accounts(self) -> List[Dict]:
        """List ACTIVE member accounts in the organization."""
        accounts: List[Dict] = []
        try:
            paginator = self.organizations.get_paginator("list_accounts")
            for page in paginator.paginate():
                for acct in page.get("Accounts", []):
                    if acct.get("Status") == "ACTIVE":
                        accounts.append({
                            "account_id": acct["Id"],
                            "account_name": acct.get("Name", ""),
                            "email": acct.get("Email", ""),
                        })
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            raise OrgScanError(
                f"organizations:ListAccounts failed ({code}). "
                "Run from the management account or a delegated admin "
                "(register with `aws organizations register-delegated-administrator "
                "--service-principal=member.org.stacksets.cloudformation.amazonaws.com`)."
            ) from e
        return accounts

    def _assume_role(self, account_id: str) -> AWSSession:
        """sts:AssumeRole into target account; return an AWSSession bound to its credentials."""
        role_arn = f"arn:aws:iam::{account_id}:role/{self.role_name}"
        try:
            resp = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"bks-org-scan-{account_id}-{int(time.time())}",
                DurationSeconds=ORG_ASSUME_DURATION,
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            raise OrgScanError(f"AssumeRole {role_arn}: {code}") from e

        creds = resp["Credentials"]
        return AWSSession.from_credentials(
            access_key=creds["AccessKeyId"],
            secret_key=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
            region=self.base.region,
            account_id=account_id,
            caller_arn=resp["AssumedRoleUser"]["Arn"],
            verbose=False,
        )

    def _scan_account(self, account: Dict) -> Dict:
        """Scan a single account; capture errors as record fields rather than raising."""
        account_id = account["account_id"]
        record: Dict = {
            "account_id": account_id,
            "account_name": account.get("account_name", ""),
            "status": "ok",
            "phantom_users": [],
            "summary": _empty_summary(),
        }
        try:
            if account_id == self.base.account_id:
                target = self.base
            else:
                target = self._assume_role(account_id)

            scanner = PhantomUserScanner(aws_session=target, verbose=False)
            phantoms = scanner.find_phantom_users()
        except OrgScanError as e:
            record["status"] = "error"
            record["error"] = str(e)
            return record
        except (ClientError, BotoCoreError) as e:
            record["status"] = "error"
            record["error"] = str(e)
            return record
        except Exception as e:
            # Defense in depth: a bug or malformed response in scanner must not
            # crash the whole org run. Tag as unexpected so it stands out in the
            # JSON output and the user can file a bug report.
            record["status"] = "error"
            record["error"] = f"unexpected: {type(e).__name__}: {e}"
            return record

        record["phantom_users"] = phantoms
        record["summary"] = _summarize(phantoms)
        return record

    def scan_all(
        self,
        accounts_filter: Optional[List[str]] = None,
        skip_accounts: Optional[List[str]] = None,
    ) -> Dict:
        """Run the per-account scan in parallel; return a single aggregate dict."""
        accounts = self.list_accounts()

        if accounts_filter:
            wanted = set(accounts_filter)
            accounts = [a for a in accounts if a["account_id"] in wanted]
        if skip_accounts:
            blocked = set(skip_accounts)
            accounts = [a for a in accounts if a["account_id"] not in blocked]

        if not accounts:
            return {
                "scan_metadata": self._metadata(0, 0, 0),
                "summary": _empty_summary(),
                "accounts": [],
            }

        if self.verbose:
            output.info(
                f"Scanning {len(accounts)} accounts via AssumeRole '{self.role_name}'"
            )

        results: List[Dict] = []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(accounts))) as pool:
            futs = {pool.submit(self._scan_account, a): a for a in accounts}
            for fut in as_completed(futs):
                results.append(fut.result())

        # Surface failures + at-risk accounts first; deterministic by account_id.
        results.sort(
            key=lambda r: (
                0 if r["status"] == "error" else 1,
                -r["summary"].get("at_risk", 0),
                -r["summary"].get("active", 0),
                r["account_id"],
            )
        )

        agg = _empty_summary()
        for r in results:
            for k in agg:
                agg[k] += r["summary"].get(k, 0)

        ok = sum(1 for r in results if r["status"] == "ok")
        failed = sum(1 for r in results if r["status"] == "error")

        return {
            "scan_metadata": self._metadata(len(accounts), ok, failed),
            "summary": agg,
            "accounts": results,
        }

    def _metadata(self, total: int, ok: int, failed: int) -> Dict:
        return {
            "mode": "org",
            "management_account_id": self.base.account_id,
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "caller_arn": self.base.caller_arn,
            "role_assumed": self.role_name,
            "accounts_total": total,
            "accounts_scanned": ok,
            "accounts_failed": failed,
        }


def format_org_table_report(result: Dict) -> str:
    """Render the org scan as a per-account table block + aggregate footer."""
    lines: List[str] = []
    meta = result["scan_metadata"]
    summary = result["summary"]
    accounts = result["accounts"]

    header = (
        f"{output.bold(output.cyan('Org scan'))}: "
        f"{meta['accounts_total']} accounts "
        f"({output.green(str(meta['accounts_scanned'])+' ok')}, "
        f"{output.red(str(meta['accounts_failed'])+' failed') if meta['accounts_failed'] else '0 failed'})  "
        f"Role: {meta['role_assumed']}"
    )
    lines.append(header)
    lines.append("")

    if not accounts:
        lines.append(output.yellow("No accounts to scan."))
        return "\n".join(lines)

    for acct in accounts:
        label = f"{acct['account_id']}"
        if acct.get("account_name"):
            label += f" ({acct['account_name']})"
        if acct["status"] == "error":
            lines.append(output.red(f"Account: {label}  ✗ ERROR"))
            lines.append(output.red(f"   {acct.get('error', 'unknown error')}"))
            lines.append("")
            continue

        phantoms = acct["phantom_users"]
        s = acct["summary"]
        badge = ""
        if s["at_risk"]:
            badge = output.red(f"  ⚠ {s['at_risk']} AT RISK")
        elif s["active"]:
            badge = output.green(f"  ✓ {s['active']} ACTIVE")
        elif s["total"]:
            badge = output.yellow(f"  ▸ {s['orphaned']} ORPHANED")
        else:
            badge = output.green("  ✓ clean")
        lines.append(output.bold(f"Account: {label}{badge}"))

        if phantoms:
            table = []
            for u in phantoms:
                table.append([
                    u["username"],
                    u["created"].strftime("%Y-%m-%d") if hasattr(u["created"], "strftime") else u["created"],
                    u["active_bedrock_credentials"],
                    u["active_access_keys"],
                    output.style_status(u["status"]),
                ])
            lines.append(
                tabulate(
                    table,
                    headers=["Username", "Created", "Active API Keys", "Access Keys", "Status"],
                    tablefmt="grid",
                )
            )
        lines.append("")

    lines.append(output.bold("Aggregate summary:"))
    lines.append(f"  Accounts scanned:  {output.cyan(str(meta['accounts_scanned']))}/{meta['accounts_total']}")
    if meta["accounts_failed"]:
        lines.append(f"  Accounts failed:   {output.red(str(meta['accounts_failed']))}")
    lines.append(f"  Total phantoms:    {output.cyan(str(summary['total']))}")
    lines.append(f"  At Risk:           {output.red(str(summary['at_risk']))}")
    lines.append(f"  Active:            {output.green(str(summary['active']))}")
    lines.append(f"  Orphaned:          {output.yellow(str(summary['orphaned']))}")

    if summary["at_risk"]:
        lines.append("")
        lines.append(output.red(
            f"⚠ {summary['at_risk']} phantom user(s) with persistent IAM credentials across the org."
        ))
        lines.append(output.red(
            "   For each AT RISK row above: assume into the listed account and run"
        ))
        lines.append(output.red(
            "   `bks revoke-key <username>` to contain."
        ))

    return "\n".join(lines)


def org_csv_rows(result: Dict) -> List[Dict]:
    """Flatten the org result to one CSV row per phantom user, prefixed with account context."""
    rows: List[Dict] = []
    for acct in result["accounts"]:
        if acct["status"] != "ok":
            continue
        for u in acct["phantom_users"]:
            row = dict(u)
            row["account_id"] = acct["account_id"]
            row["account_name"] = acct.get("account_name", "")
            rows.append(row)
    return rows


_ORG_CSV_FIELDS = [
    'account_id', 'account_name',
    'username', 'user_id', 'created', 'status',
    'active_bedrock_credentials', 'bedrock_credentials',
    'active_access_keys', 'access_keys',
    'access_key_ids', 'attached_policies', 'inline_policies',
]


def org_json_report(result: Dict) -> str:
    """Serialize the org scan result as an indented JSON string."""
    return json.dumps(result, indent=2, default=_json_default)


def org_csv_report(result: Dict, output_file: str) -> None:
    """Flatten the org result to one row per phantom user and write CSV to output_file."""
    rows = org_csv_rows(result)
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=_ORG_CSV_FIELDS, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            row = dict(row)
            created = row.get('created')
            if isinstance(created, datetime):
                row['created'] = created.isoformat()
            row['access_key_ids'] = ','.join(row.get('access_key_ids') or [])
            row['attached_policies'] = ','.join(row.get('attached_policies') or [])
            row['inline_policies'] = ','.join(row.get('inline_policies') or [])
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})
