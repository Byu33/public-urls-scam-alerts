from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from local.fetch_crime_api import run_fetch


def fetch_local_crime() -> dict[str, Any]:
    """Backward-compatible entry point for the live scam-specific local crime feed."""
    result = run_fetch()
    return {
        "records": result.get("records_upserted", 0),
        "status": "PASS",
        "details": result,
    }


def main() -> dict[str, Any]:
    return fetch_local_crime()


if __name__ == "__main__":
    main()
