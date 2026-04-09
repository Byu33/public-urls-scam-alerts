from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client


def get_supabase_client() -> Client:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent

    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()

    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
    )

    if not supabase_url or not supabase_key:
        raise ValueError(
            "Missing SUPABASE credentials. Set SUPABASE_URL and one of "
            "SUPABASE_SERVICE_ROLE_KEY, SUPABASE_KEY, or SUPABASE_ANON_KEY."
        )

    return create_client(supabase_url, supabase_key)


def print_summary(anomaly: dict[str, Any], narratives: list[str]) -> None:
    print("\nNarrative Summary")
    print(
        "- anomaly: "
        f"type={anomaly.get('scam_type')} | "
        f"state={anomaly.get('state')} | "
        f"tier={anomaly.get('alert_tier')} | "
        f"short_dev={anomaly.get('short_deviation')} | "
        f"long_dev={anomaly.get('long_deviation')} | "
        f"count={anomaly.get('current_count')} | "
        f"scope={anomaly.get('scope')} | "
        f"week_ending={anomaly.get('week_ending')}"
    )
    print(f"- total_narratives: {len(narratives)}")
    if narratives:
        first_preview = narratives[0][:100].replace("\n", " ")
        print(f"  first_narrative_preview_100_chars: {first_preview}")


def sample_narratives_for_anomaly(anomaly: dict[str, Any]) -> dict[str, Any] | None:
    scam_type = anomaly.get("scam_type")
    state = anomaly.get("state")
    alert_tier = anomaly.get("alert_tier", "WATCH")

    if not scam_type or not state:
        raise ValueError("Anomaly must include scam_type and state.")

    client = get_supabase_client()

    # Query all narratives for the current week (last 7 days) —
    # no sample size cap, no expiry filter, just reported_date range.
    week_start = (date.today() - timedelta(days=7)).isoformat()
    week_end = date.today().isoformat()

    try:
        response = (
            client.table("bbb_scam_reports")
            .select("reported_date,narrative")
            .eq("scam_type", scam_type)
            .eq("state", state)
            .not_.is_("narrative", "null")
            .is_("narrative_purged_at", "null")
            .gte("reported_date", week_start)
            .lte("reported_date", week_end)
            .order("reported_date", desc=True)
            .execute()
        )
    except APIError as exc:
        raise RuntimeError(f"Supabase query failed: {exc}") from exc

    rows = response.data or []
    narratives = [
        str(row.get("narrative", "")).strip()
        for row in rows
        if isinstance(row.get("narrative"), str) and row.get("narrative", "").strip()
    ]

    if not narratives:
        print(
            "No narratives found for this anomaly in the current week. "
            "Run fetch_reports.py first to populate bbb_scam_reports."
        )
        return None

    result = {
        "anomaly": anomaly,
        "batches": [narratives],
        "batch_count": 1,
        "total_narratives_sampled": len(narratives),
        "alert_tier": alert_tier,
    }

    print_summary(anomaly, narratives)
    return result


if __name__ == "__main__":
    test_anomaly = {
        "scam_type": "Online Purchase",
        "state": "AL",
        "short_deviation": 2.453,
        "long_deviation": 1.637,
        "alert_tier": "CRITICAL",
        "scope": "Local",
        "current_count": 35,
        "week_ending": date.today().isoformat(),
    }

    output = sample_narratives_for_anomaly(test_anomaly)
    if output is None:
        print("Returned: None")
    else:
        print(
            "Returned payload stats: "
            f"batch_count={output['batch_count']} "
            f"total_narratives_sampled={output['total_narratives_sampled']}"
        )
