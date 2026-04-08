from __future__ import annotations

import os
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
    response = (
        client.table("bbb_trends")
        .delete()
        .eq("scam_type", TEST_SCAM_TYPE)
        .eq("state", TEST_STATE)
        .execute()
    )
    removed = response.data or []
    print(f"Removed synthetic rows: {len(removed)}")


if __name__ == "__main__":
    main()
