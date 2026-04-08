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


def determine_sample_size(alert_tier: str, current_count: int) -> int:
    tier = (alert_tier or "").upper().strip()

    if tier == "CRITICAL":
        if current_count > 300:
            return 100
        if 100 <= current_count <= 300:
            return 50
        return 25

    if tier == "ALERT":
        if current_count > 100:
            return 50
        return 25

    return 15


def build_batches(narratives: list[str], sample_size_requested: int) -> list[list[str]]:
    if sample_size_requested == 100:
        return [narratives[:50], narratives[50:100]]
    return [narratives]


def print_summary(anomaly: dict[str, Any], batches: list[list[str]], sample_size_requested: int) -> None:
    total_narratives = sum(len(batch) for batch in batches)
    print("\nNarrative Sampling Summary")
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
    print(f"- sample_size_requested: {sample_size_requested}")
    print(f"- total_narratives_sampled: {total_narratives}")
    print(f"- batch_count: {len(batches)}")

    for idx, batch in enumerate(batches, start=1):
        print(f"- batch_{idx}_narratives: {len(batch)}")
        if not batch:
            print("  (empty)")
            continue
        first_preview = batch[0][:100].replace("\n", " ")
        print(f"  first_narrative_preview_100_chars: {first_preview}")


def sample_narratives_for_anomaly(anomaly: dict[str, Any]) -> dict[str, Any] | None:
    scam_type = anomaly.get("scam_type")
    state = anomaly.get("state")
    alert_tier = anomaly.get("alert_tier", "WATCH")

    if not scam_type or not state:
        raise ValueError("Anomaly must include scam_type and state.")

    current_count = int(anomaly.get("current_count", 0) or 0)
    sample_size_requested = determine_sample_size(str(alert_tier), current_count)

    client = get_supabase_client()

    now_utc = datetime.now(timezone.utc)
    cutoff_date = (date.today() - timedelta(days=14)).isoformat()

    try:
        response = (
            client.table("bbb_scam_reports")
            .select("reported_date,narrative")
            .eq("scam_type", scam_type)
            .eq("state", state)
            .not_.is_("narrative", "null")
            .gt("narrative_expires_at", now_utc.isoformat())
            .is_("narrative_purged_at", "null")
            .gte("reported_date", cutoff_date)
            .order("reported_date", desc=True)
            .limit(sample_size_requested)
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
            "No unexpired narratives exist for this anomaly. "
            "Run fetch_reports.py first to populate bbb_scam_reports."
        )
        return None

    if len(narratives) < sample_size_requested:
        print(
            "Warning: fewer narratives found than requested. "
            f"found={len(narratives)} requested={sample_size_requested}"
        )

    batches = build_batches(narratives, sample_size_requested)

    result = {
        "anomaly": anomaly,
        "batches": batches,
        "batch_count": len(batches),
        "total_narratives_sampled": len(narratives),
        "sample_size_requested": sample_size_requested,
        "alert_tier": alert_tier,
    }

    print_summary(anomaly, batches, sample_size_requested)
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
            f"total_narratives_sampled={output['total_narratives_sampled']} "
            f"sample_size_requested={output['sample_size_requested']}"
        )
