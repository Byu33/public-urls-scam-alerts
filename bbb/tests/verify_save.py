from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from supabase import Client, create_client


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
    response = (
        client.table("bbb_scam_reports")
        .select("id,reported_date,scam_type,state,dollar_amount")
        .order("reported_date", desc=True)
        .limit(5)
        .execute()
    )
    rows = response.data or []

    print("5 most recent bbb_scam_reports records:")
    if not rows:
        print("- none")
        return

    for row in rows:
        print(row)


if __name__ == "__main__":
    main()
