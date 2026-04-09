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

from detect_anomalies import sunday_ending_week_containing

PAGE_SIZE = 1000

_CFPB_TABLES_MISSING_WARNING = (
    "WARNING: cfpb_anomaly_alerts table is missing; CFPB section will be empty."
)


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


def pull_cfpb_alerts_for_week(client: Client, week_ending: str) -> list[dict[str, Any]]:
    """Pull CFPB anomaly alerts for the current week, gracefully handling missing table."""
    rows: list[dict[str, Any]] = []
    start = 0
    while True:
        try:
            response = (
                client.table("cfpb_anomaly_alerts")
                .select(
                    "id,week_ending,product,issue,state,alert_tier,scope,"
                    "detection_level,current_count,short_deviation,long_deviation,"
                    "top_company,brands_mentioned,dominant_brand"
                )
                .eq("week_ending", week_ending)
                .range(start, start + PAGE_SIZE - 1)
                .execute()
            )
        except APIError as exc:
            code = getattr(exc, "code", None)
            message = str(exc)
            if code == "PGRST205" or "Could not find the table" in message:
                print(_CFPB_TABLES_MISSING_WARNING)
                return []
            raise
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return rows


def _build_cfpb_stats(
    cfpb_alerts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute CFPB summary stats from alert rows."""
    if not cfpb_alerts:
        return {
            "cfpb_critical_count": 0,
            "cfpb_alert_count": 0,
            "cfpb_watch_count": 0,
            "top_cfpb_companies": "",
            "cfpb_top_finding": "No CFPB anomaly alerts were generated this week.",
        }

    critical = sum(1 for a in cfpb_alerts if str(a.get("alert_tier", "")).upper() == "CRITICAL")
    alert = sum(1 for a in cfpb_alerts if str(a.get("alert_tier", "")).upper() == "ALERT")
    watch = sum(1 for a in cfpb_alerts if str(a.get("alert_tier", "")).upper() == "WATCH")

    # Top companies by frequency across all alerts
    company_counter: Counter = Counter()
    for a in cfpb_alerts:
        for field in ("top_company", "dominant_brand"):
            val = a.get(field)
            if val and str(val).strip():
                company_counter[str(val).strip()] += 1
    top_companies_list = [c for c, _ in company_counter.most_common(5)]
    top_cfpb_companies = ", ".join(top_companies_list) if top_companies_list else ""

    # Top finding: highest severity alert
    sorted_alerts = sorted(
        cfpb_alerts,
        key=lambda a: (
            {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}.get(
                str(a.get("alert_tier", "WATCH")).upper(), 9
            ),
            -float(a.get("short_deviation", 0) or 0),
        ),
    )
    top = sorted_alerts[0]
    cfpb_top_finding = (
        f"{top.get('alert_tier', 'WATCH')} — "
        f"{top.get('product', '')} / {top.get('issue', '')} "
        f"in {top.get('state') or 'NATIONAL'} "
        f"(count={top.get('current_count', 0)}, "
        f"company={top.get('top_company') or 'unknown'})"
    )

    return {
        "cfpb_critical_count": critical,
        "cfpb_alert_count": alert,
        "cfpb_watch_count": watch,
        "top_cfpb_companies": top_cfpb_companies,
        "cfpb_top_finding": cfpb_top_finding,
    }


def _find_combined_signals(
    bbb_alerts: list[dict[str, Any]],
    cfpb_alerts: list[dict[str, Any]],
) -> list[str]:
    """
    Identify scam types or brands appearing in BOTH BBB and CFPB data this week.
    Returns a list of human-readable signal descriptions.
    """
    signals: list[str] = []

    # BBB scam types that have alerts
    bbb_scam_types = {
        str(a.get("scam_type", "")).lower()
        for a in bbb_alerts
        if a.get("scam_type")
    }

    # CFPB products/issues that have alerts
    cfpb_issues = {
        str(a.get("issue", "")).lower()
        for a in cfpb_alerts
        if a.get("issue")
    }

    # Cross-source type overlap (loose keyword match)
    OVERLAP_MAP = {
        "identity theft": ["identity theft", "getting a credit card"],
        "phishing": ["fraud or scam"],
        "investment": ["fraud or scam"],
        "online purchase": ["problem with a purchase shown on your statement",
                            "problem with a purchase or transfer"],
        "romance": ["fraud or scam"],
        "government agency imposter": ["fraud or scam", "false statements or representation"],
    }
    for bbb_type, cfpb_keywords in OVERLAP_MAP.items():
        if bbb_type in bbb_scam_types:
            for keyword in cfpb_keywords:
                if keyword in cfpb_issues:
                    signals.append(
                        f"{bbb_type.title()} (BBB) ↔ {keyword.title()} (CFPB) — "
                        "same scam type flagged in both datasets"
                    )
                    break

    # Brand overlap: brands in BBB alerts also appearing in CFPB top companies
    bbb_brands: set[str] = set()
    for a in bbb_alerts:
        for field in ("brands_mentioned", "dominant_brand"):
            val = a.get(field)
            if val:
                bbb_brands.update(b.strip().lower() for b in str(val).split(",") if b.strip())

    cfpb_brands: set[str] = set()
    for a in cfpb_alerts:
        for field in ("top_company", "dominant_brand", "brands_mentioned"):
            val = a.get(field)
            if val:
                cfpb_brands.update(b.strip().lower() for b in str(val).split(",") if b.strip())

    shared_brands = bbb_brands & cfpb_brands - {""}
    for brand in sorted(shared_brands):
        signals.append(
            f"Brand '{brand}' flagged in both BBB consumer reports and CFPB financial complaints"
        )

    return signals


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
    cfpb_stats: dict[str, Any] | None = None,
    combined_signals: list[str] | None = None,
) -> str:
    critical = [a for a in alerts if str(a.get("alert_tier", "")).upper() == "CRITICAL"]
    alert = [a for a in alerts if str(a.get("alert_tier", "")).upper() == "ALERT"]
    watch = [a for a in alerts if str(a.get("alert_tier", "")).upper() == "WATCH"]

    cfpb = cfpb_stats or {}
    signals = combined_signals or []

    lines: list[str] = []
    lines.append(f"# Weekly Scam Intelligence Briefing ({week_ending})")
    lines.append("")

    # ── Combined signals (highest confidence cross-source detections) ──────────
    if signals:
        lines.append("## ⚠ Combined Signals — Cross-Source Detections")
        lines.append("*These signals appear in BOTH BBB consumer reports and CFPB financial complaints.*")
        lines.append("*Two independent data sources confirming the same active campaign — highest confidence.*")
        lines.append("")
        for sig in signals:
            lines.append(f"- {sig}")
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
    lines.append("")

    # ── CFPB section ────────────────────────────────────────────────────────────
    lines.append("## CFPB Financial Complaint Alerts")
    if cfpb:
        lines.append(
            f"- CRITICAL: {cfpb.get('cfpb_critical_count', 0)}  "
            f"ALERT: {cfpb.get('cfpb_alert_count', 0)}  "
            f"WATCH: {cfpb.get('cfpb_watch_count', 0)}"
        )
        if cfpb.get("top_cfpb_companies"):
            lines.append(f"- Top companies: {cfpb['top_cfpb_companies']}")
        lines.append(f"- Top finding: {cfpb.get('cfpb_top_finding', 'None')}")
    else:
        lines.append("- CFPB data not available this week")

    return "\n".join(lines)


def generate_weekly_briefing() -> dict[str, Any]:
    started_at = time.time()
    client = get_supabase_client()

    current_week_date = sunday_ending_week_containing()
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

    # ── CFPB data ──────────────────────────────────────────────────────────────
    cfpb_alerts = pull_cfpb_alerts_for_week(client, current_week)
    cfpb_stats = _build_cfpb_stats(cfpb_alerts)
    combined_signals = _find_combined_signals(alerts, cfpb_alerts)

    print(
        f"  CFPB alerts for briefing: {len(cfpb_alerts)} "
        f"(CRITICAL={cfpb_stats['cfpb_critical_count']}, "
        f"ALERT={cfpb_stats['cfpb_alert_count']}, "
        f"WATCH={cfpb_stats['cfpb_watch_count']})"
    )
    if combined_signals:
        print(f"  Combined signals found: {len(combined_signals)}")

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
        cfpb_stats=cfpb_stats,
        combined_signals=combined_signals,
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
        "cfpb_critical_count": cfpb_stats["cfpb_critical_count"],
        "cfpb_alert_count": cfpb_stats["cfpb_alert_count"],
        "cfpb_watch_count": cfpb_stats["cfpb_watch_count"],
        "top_cfpb_companies": cfpb_stats["top_cfpb_companies"],
        "cfpb_top_finding": cfpb_stats["cfpb_top_finding"],
    }

    _CFPB_COLS = {"cfpb_critical_count", "cfpb_alert_count", "cfpb_watch_count",
                  "top_cfpb_companies", "cfpb_top_finding"}

    def _insert_briefing(row: dict[str, Any]) -> None:
        try:
            client.table("weekly_briefings").insert(row).execute()
        except APIError as exc:
            code = getattr(exc, "code", None)
            message = str(exc)
            if code == "PGRST205" or "Could not find the table" in message:
                print("WARNING: weekly_briefings table is missing; skipping briefing insert.")
            elif code == "PGRST204" or "Could not find the column" in message:
                # CFPB migration not yet run; retry without CFPB columns
                print(
                    "WARNING: weekly_briefings missing CFPB columns; "
                    "run migration 20260408000001. Retrying insert without CFPB fields."
                )
                row_without_cfpb = {k: v for k, v in row.items() if k not in _CFPB_COLS}
                client.table("weekly_briefings").insert(row_without_cfpb).execute()
            else:
                raise

    _insert_briefing(payload)

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
