from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from supabase import Client, create_client

PAGE_SIZE = 1000


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


def fetch_all_trends(client: Client) -> list[dict]:
    rows = []
    start = 0
    while True:
        response = (
            client.table("bbb_trends")
            .select("week_ending,scam_type,state,report_count")
            .range(start, start + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return rows


def main() -> None:
    client = get_client()
    rows = fetch_all_trends(client)

    print(f"total rows: {len(rows)}")

    weeks = sorted({r.get("week_ending") for r in rows if r.get("week_ending")})
    print(f"date range: {weeks[0] if weeks else 'N/A'} to {weeks[-1] if weeks else 'N/A'}")
    print(f"distinct week count: {len(weeks)}")

    scam_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}

    for r in rows:
        scam = str(r.get("scam_type") or "UNKNOWN")
        state = str(r.get("state") or "UNKNOWN")
        count = int(r.get("report_count") or 0)
        scam_counts[scam] = scam_counts.get(scam, 0) + count
        state_counts[state] = state_counts.get(state, 0) + count

    print("top 10 scam types:")
    for scam, count in sorted(scam_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"- {scam}: {count}")

    print("top 5 states:")
    for state, count in sorted(state_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"- {state}: {count}")


if __name__ == "__main__":
    main()
