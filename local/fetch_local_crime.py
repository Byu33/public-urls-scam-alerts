from __future__ import annotations

import csv
import json
from datetime import date, timedelta
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "sharepoint_output"
CSV_PATH = OUTPUT_DIR / "Local_Crime_LA.csv"
JSON_PATH = OUTPUT_DIR / "Local_Crime_LA.json"


def _local_crime_rows() -> list[dict[str, Any]]:
    """Return local crime context rows used by the weekly briefing export."""
    today = date.today()
    week_start = today - timedelta(days=7)
    return [
        {
            "source": "Los Angeles local public safety context",
            "jurisdiction": "Los Angeles, CA",
            "state": "CA",
            "week_start": week_start.isoformat(),
            "week_end": today.isoformat(),
            "category": "Fraud/Scam",
            "incident_count": 0,
            "signal": "No local crime feed configured in repository; placeholder context generated.",
            "status": "feed_not_configured",
        }
    ]


def fetch_local_crime() -> dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    rows = _local_crime_rows()

    with CSV_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    JSON_PATH.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    result = {
        "records": len(rows),
        "csv_path": str(CSV_PATH.relative_to(REPO_ROOT)),
        "json_path": str(JSON_PATH.relative_to(REPO_ROOT)),
        "status": "PASS",
        "warnings": [
            "No live local crime source exists in this repository; generated configured placeholder output."
        ],
    }
    print(json.dumps(result, indent=2))
    return result


def main() -> dict[str, Any]:
    return fetch_local_crime()


if __name__ == "__main__":
    main()
