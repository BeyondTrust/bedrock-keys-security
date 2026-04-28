"""Resolve build/version metadata. Commit SHA is shown by `bks --version`
when bks is run from a git checkout, or when the publish workflow stamps it
into `_build.py` before producing the wheel."""

import subprocess
from pathlib import Path
from typing import Optional


def get_commit() -> Optional[str]:
    try:
        from bedrock_keys_security._build import __commit__  # type: ignore[import-not-found]
        if __commit__:
            return __commit__
    except ImportError:
        pass

    pkg_root = Path(__file__).resolve().parents[1]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            cwd=pkg_root,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None

    sha = result.stdout.strip()
    return sha if result.returncode == 0 and sha else None
