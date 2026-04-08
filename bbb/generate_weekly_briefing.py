from __future__ import annotations

import os
import time
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client

PAGE_SIZE = 1000


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


def most_recent_completed_sunday(today: date | None = None) -> date:
    if today is None:
        today = date.today()
    return today - timedelta(days=today.weekday() + 1)


def pull_anomaly_alerts_for_week(client: Client, week_ending: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    start = 0
    while True:
        try:
            response = (
                client.table("anomaly_alerts")
                .select("id,run_id,week_ending,scam_type,state,alert_tier,scope,detection_level,current_count,short_deviation,long_deviation")
                .eq("week_ending", week_ending)
                .range(start, start + PAGE_SIZE - 1)
                .execute()
            )
        except APIError as exc:
            code = getattr(exc, "code", None)
            message = str(exc)
            if code == "PGRST205" or "Could not find the table" in message:
                print("WARNING: anomaly_alerts table is missing; proceeding with empty alert set.")
                return []
            raise
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return rows


def pull_trends_for_weeks(client: Client, current_week: str, previous_week: str) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    start = 0
    while True:
        response = (
            client.table("bbb_trends")
            .select("week_ending,scam_type,state,report_count")
            .in_("week_ending", [current_week, previous_week])
            .range(start, start + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["week_ending", "scam_type", "state", "report_count"])
    if not df.empty:
        df["report_count"] = pd.to_numeric(df["report_count"], errors="coerce").fillna(0).astype(int)
    return df


def pull_recent_scam_types(client: Client, week_ending: str) -> set[str]:
    current = pd.to_datetime(week_ending)
    start_week = (current - timedelta(weeks=4)).date().isoformat()

    rows: list[dict[str, Any]] = []
    start = 0
    while True:
        response = (
            client.table("bbb_trends")
            .select("week_ending,scam_type")
            .gte("week_ending", start_week)
            .lt("week_ending", week_ending)
            .range(start, start + PAGE_SIZE - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE

    return {str(r.get("scam_type")) for r in rows if r.get("scam_type")}


def build_markdown(
    week_ending: str,
    alerts: list[dict[str, Any]],
    total_reports_this_week: int,
    total_reports_last_week: int,
    week_over_week_change: float,
    top_5_states: list[dict[str, Any]],
    top_5_scam_types: list[dict[str, Any]],
    new_scam_types: list[str],
    national_flags: list[dict[str, Any]],
    top_finding_summary: str,
    national_summary: str,
) -> str:
    critical = [a for a in alerts if str(a.get("alert_tier", "")).upper() == "CRITICAL"]
    alert = [a for a in alerts if str(a.get("alert_tier", "")).upper() == "ALERT"]
    watch = [a for a in alerts if str(a.get("alert_tier", "")).upper() == "WATCH"]

    lines: list[str] = []
    lines.append(f"# BBB Weekly Scam Briefing ({week_ending})")
    lines.append("")

    lines.append("## Week at a Glance")
    lines.append(f"- {top_finding_summary}")
    lines.append(f"- Total reports this week: {total_reports_this_week}")
    lines.append(f"- Total reports last week: {total_reports_last_week}")
    lines.append(f"- Week-over-week change: {week_over_week_change:+.2f}%")
    lines.append("")

    lines.append("## Critical Alerts")
    if critical:
        for item in critical:
            lines.append(
                f"- {item.get('scam_type')} in {item.get('state') or 'NATIONAL'} "
                f"(count={item.get('current_count')}, scope={item.get('scope')})"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Alert Tier")
    if alert:
        for item in alert:
            lines.append(
                f"- {item.get('scam_type')} in {item.get('state') or 'NATIONAL'} "
                f"(count={item.get('current_count')}, scope={item.get('scope')})"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## Watch List")
    if watch:
        for item in watch:
            lines.append(
                f"- {item.get('scam_type')} in {item.get('state') or 'NATIONAL'} "
                f"(count={item.get('current_count')}, scope={item.get('scope')})"
            )
    else:
        lines.append("- None")
    lines.append("")

    lines.append("## National Patterns")
    lines.append(f"- {national_summary}")
    if national_flags:
        for item in national_flags:
            lines.append(
                f"- {item.get('scam_type')} ({item.get('detection_level')}) "
                f"tier={item.get('alert_tier')} count={item.get('current_count')}"
            )
    else:
        lines.append("- No national-level flags")
    lines.append("")

    lines.append("## New This Week")
    if new_scam_types:
        for scam_type in new_scam_types:
            lines.append(f"- {scam_type}")
    else:
        lines.append("- No new scam types in the last 4-week comparison window")
    lines.append("")

    lines.append("## Volume Summary")
    lines.append("- Top 5 states by report volume:")
    if top_5_states:
        for row in top_5_states:
            lines.append(f"  - {row['state']}: {row['report_count']}")
    else:
        lines.append("  - None")
    lines.append("- Top 5 scam types by report volume:")
    if top_5_scam_types:
        for row in top_5_scam_types:
            lines.append(f"  - {row['scam_type']}: {row['report_count']}")
    else:
        lines.append("  - None")
    lines.append("")

    lines.append("## Week Over Week Comparison")
    lines.append(f"- This week: {total_reports_this_week}")
    lines.append(f"- Last week: {total_reports_last_week}")
    lines.append(f"- Change: {week_over_week_change:+.2f}%")

    return "\n".join(lines)


def generate_weekly_briefing() -> dict[str, Any]:
    started_at = time.time()
    client = get_supabase_client()

    current_week_date = most_recent_completed_sunday()
    previous_week_date = current_week_date - timedelta(days=7)
    current_week = current_week_date.isoformat()
    previous_week = previous_week_date.isoformat()

    print(f"Generating briefing for week ending {current_week}")

    alerts = pull_anomaly_alerts_for_week(client, current_week)
    trends_df = pull_trends_for_weeks(client, current_week, previous_week)

    this_week_df = trends_df[trends_df["week_ending"] == current_week] if not trends_df.empty else pd.DataFrame()
    last_week_df = trends_df[trends_df["week_ending"] == previous_week] if not trends_df.empty else pd.DataFrame()

    total_reports_this_week = int(this_week_df["report_count"].sum()) if not this_week_df.empty else 0
    total_reports_last_week = int(last_week_df["report_count"].sum()) if not last_week_df.empty else 0

    if total_reports_last_week > 0:
        week_over_week_change = ((total_reports_this_week - total_reports_last_week) / total_reports_last_week) * 100
    elif total_reports_this_week > 0:
        week_over_week_change = 100.0
    else:
        week_over_week_change = 0.0

    top_5_states: list[dict[str, Any]] = []
    top_5_scam_types: list[dict[str, Any]] = []

    if not this_week_df.empty:
        state_agg = (
            this_week_df.groupby("state", dropna=False)["report_count"]
            .sum()
            .sort_values(ascending=False)
            .head(5)
            .reset_index()
        )
        top_5_states = [
            {"state": str(row["state"]), "report_count": int(row["report_count"])}
            for _, row in state_agg.iterrows()
        ]

        scam_agg = (
            this_week_df.groupby("scam_type", dropna=False)["report_count"]
            .sum()
            .sort_values(ascending=False)
            .head(5)
            .reset_index()
        )
        top_5_scam_types = [
            {"scam_type": str(row["scam_type"]), "report_count": int(row["report_count"])}
            for _, row in scam_agg.iterrows()
        ]

    this_week_scam_types = {row["scam_type"] for row in top_5_scam_types}
    prior_4_week_types = pull_recent_scam_types(client, current_week)
    new_scam_types = sorted(list(this_week_scam_types - prior_4_week_types))

    national_flags = [
        a
        for a in alerts
        if str(a.get("detection_level", "")).lower() in {"national", "both"}
    ]

    if alerts:
        sorted_alerts = sorted(
            alerts,
            key=lambda a: (
                {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}.get(str(a.get("alert_tier", "WATCH")).upper(), 9),
                -float(a.get("short_deviation", 0) or 0),
            ),
        )
        top_alert = sorted_alerts[0]
        top_finding_summary = (
            f"{top_alert.get('alert_tier', 'WATCH')} activity in {top_alert.get('scam_type')} "
            f"for {top_alert.get('state') or 'NATIONAL'} led this week."
        )
    else:
        top_finding_summary = "No elevated anomaly alerts were generated this week."

    if national_flags:
        national_tier_counts = Counter(str(x.get("alert_tier", "WATCH")).upper() for x in national_flags)
        national_summary = (
            f"National/Both detections: {len(national_flags)} "
            f"(CRITICAL={national_tier_counts.get('CRITICAL', 0)}, "
            f"ALERT={national_tier_counts.get('ALERT', 0)}, "
            f"WATCH={national_tier_counts.get('WATCH', 0)})."
        )
    else:
        national_summary = "No national-level anomalies were flagged this week."

    briefing_markdown = build_markdown(
        week_ending=current_week,
        alerts=alerts,
        total_reports_this_week=total_reports_this_week,
        total_reports_last_week=total_reports_last_week,
        week_over_week_change=week_over_week_change,
        top_5_states=top_5_states,
        top_5_scam_types=top_5_scam_types,
        new_scam_types=new_scam_types,
        national_flags=national_flags,
        top_finding_summary=top_finding_summary,
        national_summary=national_summary,
    )

    payload = {
        "week_ending": current_week,
        "briefing_status": "pending",
        "briefing_markdown": briefing_markdown,
        "total_reports_this_week": total_reports_this_week,
        "total_reports_last_week": total_reports_last_week,
        "week_over_week_change": round(week_over_week_change, 2),
        "top_5_states": top_5_states,
        "top_5_scam_types": top_5_scam_types,
        "new_scam_types": new_scam_types,
        "national_flags": national_flags,
        "top_finding_summary": top_finding_summary,
        "national_summary": national_summary,
    }

    try:
        client.table("weekly_briefings").insert(payload).execute()
    except APIError as exc:
        code = getattr(exc, "code", None)
        message = str(exc)
        if code == "PGRST205" or "Could not find the table" in message:
            print("WARNING: weekly_briefings table is missing; skipping briefing insert.")
        else:
            raise

    elapsed = time.time() - started_at
    print("Weekly briefing generated:")
    print(f"- week_ending: {current_week}")
    print(f"- alerts_included: {len(alerts)}")
    print(f"- total_reports_this_week: {total_reports_this_week}")
    print(f"- total_reports_last_week: {total_reports_last_week}")
    print(f"- elapsed_seconds: {elapsed:.2f}")

    return {
        "week_ending": current_week,
        "alerts_included": len(alerts),
        "elapsed_seconds": round(elapsed, 2),
    }


if __name__ == "__main__":
    try:
        generate_weekly_briefing()
    except Exception as exc:
        print(f"generate_weekly_briefing.py failed: {exc}")
        raise
