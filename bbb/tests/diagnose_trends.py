from __future__ import annotations

import os
from collections import defaultdict
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


def fetch_rows(client: Client) -> list[dict]:
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
    rows = fetch_rows(client)

    by_combo: dict[tuple[str, str], set[str]] = defaultdict(set)
    all_weeks: set[str] = set()

    for r in rows:
        scam = str(r.get("scam_type") or "UNKNOWN")
        state = str(r.get("state") or "UNKNOWN")
        week = str(r.get("week_ending") or "")
        if week:
            by_combo[(scam, state)].add(week)
            all_weeks.add(week)

    total_weeks = len(all_weeks)
    print(f"gap analysis: total distinct weeks={total_weeks}")

    counts = [
        (combo[0], combo[1], len(weeks))
        for combo, weeks in by_combo.items()
    ]
    counts_sorted = sorted(counts, key=lambda x: x[2], reverse=True)

    print("top combinations by week coverage:")
    for scam, state, week_count in counts_sorted[:10]:
        print(f"- {scam} / {state}: {week_count} weeks")

    print("bottom combinations by week coverage:")
    for scam, state, week_count in counts_sorted[-10:]:
        print(f"- {scam} / {state}: {week_count} weeks")

    def print_combo_timeline(target_state: str) -> None:
        timeline = [
            r for r in rows
            if str(r.get("scam_type") or "") == "Online Purchase"
            and str(r.get("state") or "") == target_state
        ]
        timeline.sort(key=lambda x: str(x.get("week_ending") or ""))
        print(f"Online Purchase {target_state} week by week:")
        if not timeline:
            print("- none")
            return
        for r in timeline:
            print(f"- {r.get('week_ending')}: {r.get('report_count')}")

    print_combo_timeline("CA")
    print_combo_timeline("TX")


if __name__ == "__main__":
    main()
