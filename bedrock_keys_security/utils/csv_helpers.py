"""Shared helpers for CSV / JSON output across scanners.

The Bedrock and Claude Platform scanners both serialise scan results to
JSON and CSV. The helpers in this module are service-agnostic.
"""

from datetime import datetime


def json_default(obj):
    """Fallback serializer for ``json.dumps``. Handles datetime fields returned by AWS APIs."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


_CSV_INJECTION_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def csv_safe(value):
    """Neutralize Excel / Google Sheets formula injection on dangerous leading characters.

    IAM allows ``=`` in usernames (charset ``[\\w+=,.@-]``) so a hostile
    actor could plant a phantom user whose CSV row triggers RCE in a SOC
    analyst's spreadsheet on open. Cells starting with ``= + - @ \\t \\r``
    are prefixed with ``'`` to defang the cell.
    """
    if isinstance(value, str) and value and value[0] in _CSV_INJECTION_PREFIXES:
        return "'" + value
    return value
