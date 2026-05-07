from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client

from fetch_trends import CFPB_SCAM_CATEGORIES


PAGE_SIZE = 1000


def get_supabase_client() -> Client:
    repo_root = Path(__file__).resolve().parent.parent
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        raise ValueError("Missing SUPABASE_URL and Supabase service/anon key.")
    return create_client(url, key)


def pull_cfpb_trends(client: Client) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    start = 0
    while True:
        response = (
            client.table("cfpb_trends")
            .select("week_ending,product,issue,scam_type,priority,state,report_count")
            .range(start, start + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    if not rows:
        return pd.DataFrame(columns=["week_ending", "product", "issue", "scam_type", "priority", "state", "report_count"])

    df = pd.DataFrame(rows)
    df["week_ending"] = pd.to_datetime(df["week_ending"], errors="coerce")
    df["report_count"] = pd.to_numeric(df["report_count"], errors="coerce").fillna(0).astype(int)
    return df


def summarize_cfpb_trends(df: pd.DataFrame) -> dict[str, Any]:
    expected_categories = [str(category["scam_type"]) for category in CFPB_SCAM_CATEGORIES]
    if df.empty:
        return {
            "total_rows": 0,
            "distinct_weeks": 0,
            "distinct_categories": 0,
            "date_range": None,
            "top_categories": [],
            "zero_record_weeks": [],
            "data_quality_issues": ["No CFPB trend rows found."],
            "category_row_counts": {},
        }

    df = df[df["scam_type"].notna()].copy()
    total_rows = int(len(df))
    distinct_weeks = int(df["week_ending"].nunique())
    distinct_categories = int(df["scam_type"].nunique())
    date_range = f"{df['week_ending'].min().date().isoformat()} to {df['week_ending'].max().date().isoformat()}"

    top_categories_df = (
        df[df["state"] == "NATIONAL"]
        .groupby("scam_type", dropna=False)["report_count"]
        .sum()
        .sort_values(ascending=False)
        .head(5)
        .reset_index()
    )
    top_categories = [
        {"scam_type": str(row["scam_type"]), "total_complaints": int(row["report_count"])}
        for _, row in top_categories_df.iterrows()
    ]

    weekly_totals = df[df["state"] == "NATIONAL"].groupby("week_ending")["report_count"].sum()
    full_weeks = pd.date_range(df["week_ending"].min(), df["week_ending"].max(), freq="7D")
    zero_record_weeks = [
        week.date().isoformat()
        for week in full_weeks
        if int(weekly_totals.get(week, 0) or 0) == 0
    ]

    category_row_counts = (
        df[df["state"] == "NATIONAL"]
        .groupby("scam_type")["week_ending"]
        .nunique()
        .reindex(expected_categories, fill_value=0)
        .astype(int)
        .to_dict()
    )

    issues: list[str] = []
    missing = [category for category in expected_categories if category_row_counts.get(category, 0) == 0]
    if missing:
        issues.append("Missing expected CFPB categories: " + ", ".join(missing))
    low_history = [category for category, count in category_row_counts.items() if count < 16]
    if low_history:
        issues.append("Categories with fewer than 16 national weeks: " + ", ".join(low_history))
    if zero_record_weeks:
        issues.append(f"Weeks with zero national records across all categories: {len(zero_record_weeks)}")
    if df[["week_ending", "product", "issue", "scam_type", "state"]].isna().any().any():
        issues.append("Null values found in required CFPB trend dimensions.")

    return {
        "total_rows": total_rows,
        "distinct_weeks": distinct_weeks,
        "distinct_categories": distinct_categories,
        "date_range": date_range,
        "top_categories": top_categories,
        "zero_record_weeks": zero_record_weeks,
        "data_quality_issues": issues,
        "category_row_counts": category_row_counts,
    }


def build_cfpb_trends(_: list[dict[str, Any]] | dict[str, Any] | None = None) -> dict[str, Any]:
    client = get_supabase_client()
    try:
        df = pull_cfpb_trends(client)
    except APIError as exc:
        raise RuntimeError("Unable to query cfpb_trends. Apply CFPB scam pipeline migration first.") from exc
    summary = summarize_cfpb_trends(df)

    print("\nCFPB trends table summary")
    print(f"- Total rows: {summary['total_rows']}")
    print(f"- Distinct weeks: {summary['distinct_weeks']}")
    print(f"- Distinct categories: {summary['distinct_categories']}")
    print(f"- Date range: {summary['date_range']}")
    print("- Top 5 categories by total complaint count:")
    for row in summary["top_categories"]:
        print(f"  - {row['scam_type']}: {row['total_complaints']}")
    print("- Weeks with zero records across all categories:")
    print("  - " + (", ".join(summary["zero_record_weeks"]) if summary["zero_record_weeks"] else "None"))
    print("- Data quality issues:")
    print("  - " + ("; ".join(summary["data_quality_issues"]) if summary["data_quality_issues"] else "None"))
    print("- Row count by scam_type:")
    for scam_type, count in summary["category_row_counts"].items():
        print(f"  - {scam_type}: {count}")
    return summary


def main() -> dict[str, Any]:
    return build_cfpb_trends()


if __name__ == "__main__":
    main()
