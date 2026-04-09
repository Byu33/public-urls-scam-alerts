from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client


# ── Supabase connection ────────────────────────────────────────────────────────

def get_supabase_client() -> Client:
    repo_root = Path(__file__).resolve().parent.parent
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()

    url = os.getenv("SUPABASE_URL")
    key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
    )
    if not url or not key:
        raise ValueError(
            "Missing Supabase credentials. Set SUPABASE_URL and one of "
            "SUPABASE_SERVICE_ROLE_KEY, SUPABASE_KEY, or SUPABASE_ANON_KEY."
        )
    return create_client(url, key)


# ── Sample size (mirrors bbb/sample_narratives.py) ────────────────────────────

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

    return 15  # WATCH


def build_batches(narratives: list[str], sample_size_requested: int) -> list[list[str]]:
    if sample_size_requested == 100:
        return [narratives[:50], narratives[50:100]]
    return [narratives]


# ── Query ──────────────────────────────────────────────────────────────────────

def sample_cfpb_narratives_for_anomaly(
    anomaly: dict[str, Any],
    client: Client | None = None,
) -> dict[str, Any] | None:
    """
    Query cfpb_complaints for unexpired narratives matching a flagged anomaly.

    Parameters
    ----------
    anomaly : dict with keys product, issue, state, alert_tier, current_count
    client  : optional Supabase client; one is created if not provided

    Returns
    -------
    dict with batches list and metadata, or None if no narratives found.
    """
    product = anomaly.get("product")
    issue = anomaly.get("issue")
    state = anomaly.get("state")
    alert_tier = anomaly.get("alert_tier", "WATCH")
    current_count = int(anomaly.get("current_count", 0) or 0)
    top_company = anomaly.get("top_company")

    if not product or not issue:
        raise ValueError("Anomaly must include product and issue.")

    sample_size_requested = determine_sample_size(str(alert_tier), current_count)

    if client is None:
        client = get_supabase_client()

    now_utc = datetime.now(timezone.utc)
    cutoff_date = (date.today() - timedelta(weeks=8)).isoformat()

    query = (
        client.table("cfpb_complaints")
        .select("date_received,narrative,company_name")
        .eq("product", product)
        .eq("issue", issue)
        .not_.is_("narrative", "null")
        .gt("narrative_expires_at", now_utc.isoformat())
        .is_("narrative_purged_at", "null")
        .gte("date_received", cutoff_date)
        .order("date_received", desc=True)
        .limit(sample_size_requested)
    )

    # State filter: skip for national-level anomalies (state is None)
    if state and state != "NATIONAL":
        query = query.eq("state", state)

    try:
        response = query.execute()
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
            f"No unexpired CFPB narratives for "
            f"{product} / {issue} / {state or 'NATIONAL'} tier={alert_tier}. "
            "Run fetch_complaints.py first to populate cfpb_complaints."
        )
        return None

    if len(narratives) < sample_size_requested:
        print(
            f"Warning: fewer CFPB narratives found than requested. "
            f"found={len(narratives)} requested={sample_size_requested}"
        )

    batches = build_batches(narratives, sample_size_requested)

    _print_summary(anomaly, batches, sample_size_requested, top_company)

    return {
        "anomaly": anomaly,
        "batches": batches,
        "batch_count": len(batches),
        "total_narratives_sampled": len(narratives),
        "sample_size_requested": sample_size_requested,
        "alert_tier": alert_tier,
        "top_company": top_company,
    }


def _print_summary(
    anomaly: dict[str, Any],
    batches: list[list[str]],
    sample_size_requested: int,
    top_company: str | None,
) -> None:
    total = sum(len(b) for b in batches)
    print("\nCFPB Narrative Sampling Summary")
    print(
        f"- anomaly: product={anomaly.get('product')} | "
        f"issue={anomaly.get('issue')} | "
        f"state={anomaly.get('state') or 'NATIONAL'} | "
        f"tier={anomaly.get('alert_tier')} | "
        f"count={anomaly.get('current_count')} | "
        f"top_company={top_company}"
    )
    print(f"- sample_size_requested: {sample_size_requested}")
    print(f"- total_narratives_sampled: {total}")
    print(f"- batch_count: {len(batches)}")
    for idx, batch in enumerate(batches, start=1):
        print(f"- batch_{idx}: {len(batch)} narratives")
        if batch:
            preview = batch[0][:100].replace("\n", " ")
            print(f"  preview: {preview}")


if __name__ == "__main__":
    test_anomaly = {
        "product": "Money transfer, virtual currency, or money service",
        "issue": "Fraud or scam",
        "state": "CA",
        "alert_tier": "ALERT",
        "current_count": 150,
        "top_company": "Zelle",
    }
    result = sample_cfpb_narratives_for_anomaly(test_anomaly)
    if result is None:
        print("Returned: None")
    else:
        print(
            f"batch_count={result['batch_count']}  "
            f"total={result['total_narratives_sampled']}"
        )
