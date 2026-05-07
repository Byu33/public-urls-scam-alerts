from __future__ import annotations

import os
from collections import defaultdict
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from supabase import Client, create_client

UPSERT_BATCH_SIZE = 500


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


# ── Week-ending calculation ────────────────────────────────────────────────────

def to_sunday(d: date) -> date:
    """Return the Sunday that ends the week containing date d."""
    days_to_sunday = (6 - d.weekday()) % 7
    return d + timedelta(days=days_to_sunday)


def _none_if_missing(value: Any) -> Any:
    return None if pd.isna(value) else value


# ── Aggregation ────────────────────────────────────────────────────────────────

def aggregate_trend_rows(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Aggregate raw trend rows into (week_ending, product, issue, state) buckets.

    The CFPB API may return multiple bucket entries that map to the same
    Sunday week_ending (e.g., when date_min falls mid-week). This step
    de-duplicates by summing report_count per unique key.
    """
    if not raw_rows:
        return []

    df = pd.DataFrame(raw_rows)
    df["week_ending"] = pd.to_datetime(df["week_ending"], errors="coerce").dt.date

    # Apply Sunday normalisation to any rows that weren't already normalised
    df["week_ending"] = df["week_ending"].apply(
        lambda d: to_sunday(d) if pd.notna(d) else d
    )

    df["report_count"] = pd.to_numeric(df["report_count"], errors="coerce").fillna(0).astype(int)

    # Keep first non-null sub_product per (week_ending, product, issue, state)
    sub_product_map: dict[tuple, str | None] = {}
    for _, row in df.iterrows():
        key = (row["week_ending"], row["product"], row["issue"], row["state"])
        if key not in sub_product_map:
            sub_product_map[key] = _none_if_missing(row.get("sub_product"))

    agg = (
        df.groupby(["week_ending", "product", "issue", "state"], dropna=False)["report_count"]
        .sum()
        .reset_index()
    )

    result: list[dict[str, Any]] = []
    for _, row in agg.iterrows():
        key = (row["week_ending"], row["product"], row["issue"], row["state"])
        result.append(
            {
                "week_ending": row["week_ending"].isoformat() if pd.notna(row["week_ending"]) else None,
                "product": str(row["product"]),
                "sub_product": _none_if_missing(sub_product_map.get(key)),
                "issue": str(row["issue"]),
                "state": str(row["state"]),
                "report_count": int(row["report_count"]),
            }
        )

    return result


# ── Upsert ─────────────────────────────────────────────────────────────────────

def upsert_cfpb_trends(client: Client, rows: list[dict[str, Any]]) -> int:
    """Upsert aggregated rows to cfpb_trends in batches of UPSERT_BATCH_SIZE."""
    if not rows:
        return 0

    # Remove rows with null week_ending (can't upsert without the key)
    valid_rows = [r for r in rows if r.get("week_ending")]
    skipped = len(rows) - len(valid_rows)
    if skipped:
        print(f"  Skipped {skipped} rows with null week_ending")

    upserted = 0
    for start in range(0, len(valid_rows), UPSERT_BATCH_SIZE):
        batch = valid_rows[start : start + UPSERT_BATCH_SIZE]
        client.table("cfpb_trends").upsert(
            batch,
            on_conflict="week_ending,product,issue,state",
        ).execute()
        upserted += len(batch)

    return upserted


# ── Main entry point ───────────────────────────────────────────────────────────

def build_cfpb_trends(trend_data: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Aggregate raw trend rows and upsert to cfpb_trends.

    Parameters
    ----------
    trend_data : list of dicts from fetch_cfpb_trends()

    Returns
    -------
    dict with keys: raw_rows, aggregated_rows, upserted_rows, date_range
    """
    if not trend_data:
        print("build_cfpb_trends: no trend data provided, nothing to upsert.")
        return {"raw_rows": 0, "aggregated_rows": 0, "upserted_rows": 0, "date_range": None}

    aggregated = aggregate_trend_rows(trend_data)
    if not aggregated:
        print("build_cfpb_trends: aggregation produced no rows.")
        return {"raw_rows": len(trend_data), "aggregated_rows": 0, "upserted_rows": 0, "date_range": None}

    client = get_supabase_client()
    upserted = upsert_cfpb_trends(client, aggregated)

    week_endings = [r["week_ending"] for r in aggregated if r.get("week_ending")]
    date_range = f"{min(week_endings)} to {max(week_endings)}" if week_endings else None

    print(
        f"build_cfpb_trends: raw_rows={len(trend_data)}  "
        f"aggregated_rows={len(aggregated)}  "
        f"upserted_rows={upserted}  "
        f"date_range={date_range}"
    )
    return {
        "raw_rows": len(trend_data),
        "aggregated_rows": len(aggregated),
        "upserted_rows": upserted,
        "date_range": date_range,
    }


def main(trend_data: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if trend_data is None:
        # Standalone mode: fetch first then build
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fetch_trends import fetch_cfpb_trends
        trend_data = fetch_cfpb_trends()
    return build_cfpb_trends(trend_data)


if __name__ == "__main__":
    result = main()
    print(result)
