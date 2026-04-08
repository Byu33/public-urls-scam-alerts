from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client

UPSERT_BATCH_SIZE = 500
QUERY_PAGE_SIZE = 1000


def load_env() -> None:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()


def get_supabase_client() -> Client:
    load_env()
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


def pull_scam_reports_df(client: Client) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    start = 0

    while True:
        response = (
            client.table("bbb_scam_reports")
            .select("reported_date,scam_type,scam_subtype,state,dollar_amount,contact_method")
            .range(start, start + QUERY_PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < QUERY_PAGE_SIZE:
            break
        start += QUERY_PAGE_SIZE

    if not rows:
        return pd.DataFrame(
            columns=[
                "reported_date",
                "scam_type",
                "scam_subtype",
                "state",
                "dollar_amount",
                "contact_method",
            ]
        )

    df = pd.DataFrame(rows)
    df["reported_date"] = pd.to_datetime(df["reported_date"], errors="coerce")
    df = df.dropna(subset=["reported_date", "scam_type", "state"]).copy()
    if df.empty:
        return pd.DataFrame(
            columns=[
                "week_ending",
                "scam_type",
                "state",
                "report_count",
                "avg_dollar_amount",
                "dominant_subtype",
                "dominant_contact_method",
            ]
        )

    df["dollar_amount"] = pd.to_numeric(df["dollar_amount"], errors="coerce").fillna(0)
    return df


def _mode_or_none(series: pd.Series) -> str | None:
    cleaned = series.dropna().astype(str).str.strip()
    cleaned = cleaned[cleaned != ""]
    if cleaned.empty:
        return None
    modes = cleaned.mode(dropna=True)
    if modes.empty:
        return None
    return str(modes.iloc[0])


def build_trends(df: pd.DataFrame) -> list[dict[str, Any]]:
    if df.empty:
        return []

    week_offsets = (6 - df["reported_date"].dt.weekday) % 7
    df["week_ending"] = (df["reported_date"] + pd.to_timedelta(week_offsets, unit="D")).dt.date

    grouped = (
        df.groupby(["week_ending", "scam_type", "state"], dropna=False)
        .agg(
            report_count=("reported_date", "size"),
            avg_dollar_amount=("dollar_amount", "mean"),
            dominant_subtype=("scam_subtype", _mode_or_none),
            dominant_contact_method=("contact_method", _mode_or_none),
        )
        .reset_index()
    )

    grouped["avg_dollar_amount"] = grouped["avg_dollar_amount"].round(2)
    grouped["week_ending"] = grouped["week_ending"].astype(str)
    grouped = grouped.where(pd.notna(grouped), None)

    return grouped.to_dict(orient="records")


def upsert_trends(client: Client, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0

    total_upserted = 0
    for start in range(0, len(rows), UPSERT_BATCH_SIZE):
        batch = rows[start : start + UPSERT_BATCH_SIZE]
        sanitized_batch: list[dict[str, Any]] = []
        for row in batch:
            sanitized_row: dict[str, Any] = {}
            for key, value in row.items():
                sanitized_row[key] = None if pd.isna(value) else value
            sanitized_batch.append(sanitized_row)

        try:
            client.table("bbb_trends").upsert(
                sanitized_batch,
                on_conflict="week_ending,scam_type,state",
            ).execute()
        except APIError as exc:
            message = str(exc)
            missing_dominant_cols = (
                "dominant_subtype" in message or "dominant_contact_method" in message
            )
            if not missing_dominant_cols:
                raise

            core_fields = [
                "week_ending",
                "scam_type",
                "state",
                "report_count",
                "avg_dollar_amount",
            ]
            reduced_batch = [{k: row.get(k) for k in core_fields} for row in sanitized_batch]
            client.table("bbb_trends").upsert(
                reduced_batch,
                on_conflict="week_ending,scam_type,state",
            ).execute()

        total_upserted += len(batch)
        print(f"Upserted batch {start // UPSERT_BATCH_SIZE + 1}: {len(batch)} rows")

    return total_upserted


def run_build_trends() -> dict[str, Any]:
    started_at = time.time()
    client = get_supabase_client()

    print("Pulling bbb_scam_reports from Supabase...")
    df = pull_scam_reports_df(client)
    print(f"Loaded {len(df)} report rows")

    trend_rows = build_trends(df)
    print(f"Built {len(trend_rows)} aggregated trend rows")

    upserted = upsert_trends(client, trend_rows)
    elapsed = time.time() - started_at

    summary = {
        "source_rows": len(df),
        "trend_rows": len(trend_rows),
        "upserted_rows": upserted,
        "elapsed_seconds": round(elapsed, 2),
    }

    print("Build trends summary:")
    print(f"- source_rows: {summary['source_rows']}")
    print(f"- trend_rows: {summary['trend_rows']}")
    print(f"- upserted_rows: {summary['upserted_rows']}")
    print(f"- elapsed_seconds: {summary['elapsed_seconds']}")

    return summary


if __name__ == "__main__":
    try:
        run_build_trends()
    except Exception as exc:
        print(f"build_trends.py failed: {exc}")
        raise
