from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path

from dotenv import load_dotenv
from supabase import Client, create_client


TEST_STATE = "ZZ"
TEST_SCAM_TYPE = "Synthetic Test Scam"


def get_client() -> Client:
    repo_root = Path(__file__).resolve().parents[2]
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()

    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        raise ValueError("Missing SUPABASE_URL and SUPABASE_KEY/SERVICE_ROLE/ANON")
    return create_client(url, key)


def main() -> None:
    client = get_client()
    today = date.today()

    rows = []
    for week_idx in range(16):
        week_ending = today - timedelta(days=today.weekday() + 1) - timedelta(weeks=15 - week_idx)
        report_count = 12 + week_idx
        if week_idx >= 14:
            report_count += 30
        rows.append(
            {
                "week_ending": week_ending.isoformat(),
                "scam_type": TEST_SCAM_TYPE,
                "state": TEST_STATE,
                "report_count": report_count,
                "avg_dollar_amount": 150 + (week_idx * 5),
                "dominant_subtype": "SyntheticSubtype",
                "dominant_contact_method": "SyntheticContact",
            }
        )

    client.table("bbb_trends").upsert(rows, on_conflict="week_ending,scam_type,state").execute()
    print(f"Inserted/updated synthetic rows: {len(rows)}")


if __name__ == "__main__":
    main()
