from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client


REPO_ROOT = Path(__file__).resolve().parent.parent
AGENTS_DIR = REPO_ROOT / "agents"
OUTPUT_DIR = REPO_ROOT / "sharepoint_output"
CFPB_DIR = REPO_ROOT / "cfpb"
if str(CFPB_DIR) not in sys.path:
    sys.path.insert(0, str(CFPB_DIR))

from fetch_trends import CFPB_SCAM_CATEGORIES  # noqa: E402


PAGE_SIZE = 1000
PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not fieldnames:
        keys: list[str] = []
        for row in rows:
            for key in row:
                if key not in keys:
                    keys.append(key)
        fieldnames = keys or ["message"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        if rows:
            writer.writerows(rows)


def _tier_rows(prefix: str, counts: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"source": prefix, "alert_tier": tier, "count": int(counts.get(tier, 0) or 0)}
        for tier in ("CRITICAL", "ALERT", "WATCH")
    ]


def _get_supabase_client() -> Client | None:
    load_dotenv(REPO_ROOT / ".env.local")
    load_dotenv(REPO_ROOT / ".env")
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        return None
    return create_client(url, key)


def _fetch_all(client: Client, table: str, columns: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    start = 0
    while True:
        response = client.table(table).select(columns).range(start, start + PAGE_SIZE - 1).execute()
        page = response.data or []
        rows.extend(page)
        if len(page) < PAGE_SIZE:
            break
        start += PAGE_SIZE
    return rows


def _fetch_cfpb_data() -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    client = _get_supabase_client()
    if client is None:
        return pd.DataFrame(), pd.DataFrame(), ["Missing Supabase credentials; CFPB workbook sheets are empty."]
    try:
        trends = _fetch_all(client, "cfpb_trends", "week_ending,product,issue,scam_type,priority,state,report_count")
        alerts = _fetch_all(
            client,
            "cfpb_anomaly_alerts",
            "week_ending,product,issue,sub_issue,scam_type,state,alert_tier,scope,short_deviation,"
            "long_deviation,current_count,detection_level,top_company,top_sub_issue,priority,"
            "detection_window_short,detection_window_long",
        )
    except APIError as exc:
        return pd.DataFrame(), pd.DataFrame(), [f"CFPB Supabase query failed: {exc}"]

    trends_df = pd.DataFrame(trends)
    alerts_df = pd.DataFrame(alerts)
    if not trends_df.empty:
        trends_df["week_ending"] = pd.to_datetime(trends_df["week_ending"], errors="coerce")
        trends_df["report_count"] = pd.to_numeric(trends_df["report_count"], errors="coerce").fillna(0).astype(int)
    if not alerts_df.empty:
        alerts_df["week_ending"] = pd.to_datetime(alerts_df["week_ending"], errors="coerce")
        alerts_df["current_count"] = pd.to_numeric(alerts_df["current_count"], errors="coerce").fillna(0).astype(int)
    return trends_df, alerts_df, []


def _cfpb_alert_rows(alerts_df: pd.DataFrame) -> list[dict[str, Any]]:
    if alerts_df.empty:
        return []
    rows: list[dict[str, Any]] = []
    for _, row in alerts_df.sort_values(["week_ending", "alert_tier"], ascending=[False, True]).iterrows():
        rows.append(
            {
                "week_ending": row.get("week_ending").date().isoformat() if pd.notna(row.get("week_ending")) else None,
                "scam_type": row.get("scam_type"),
                "sub_issue": row.get("sub_issue"),
                "top_sub_issue": row.get("top_sub_issue"),
                "priority": row.get("priority"),
                "state": row.get("state"),
                "alert_tier": row.get("alert_tier"),
                "scope": row.get("scope"),
                "current_count": int(row.get("current_count") or 0),
                "short_deviation": row.get("short_deviation"),
                "long_deviation": row.get("long_deviation"),
                "detection_level": row.get("detection_level"),
                "detection_window": f"{int(row.get('detection_window_short') or 8)}w/{int(row.get('detection_window_long') or 16)}w",
                "top_company": row.get("top_company"),
            }
        )
    return rows


def _category_priority(scam_type: str) -> str:
    for category in CFPB_SCAM_CATEGORIES:
        if category["scam_type"] == scam_type:
            return str(category["priority"])
    return "LOW"


def _cfpb_trend_rows(trends_df: pd.DataFrame, alerts_df: pd.DataFrame) -> list[dict[str, Any]]:
    categories = [str(category["scam_type"]) for category in CFPB_SCAM_CATEGORIES]
    if trends_df.empty:
        return [
            {
                "scam_type": scam_type,
                "priority": _category_priority(scam_type),
                "this_week_national_count": 0,
                "week_over_week_change": 0.0,
                "12_week_average": 0.0,
                "current_deviation": 0.0,
            }
            for scam_type in categories
        ]

    national = trends_df[trends_df["state"] == "NATIONAL"].copy()
    current_week = national["week_ending"].max()
    previous_week = current_week - pd.Timedelta(weeks=1)
    rows: list[dict[str, Any]] = []
    for scam_type in categories:
        group = national[national["scam_type"] == scam_type].sort_values("week_ending")
        current_count = int(group.loc[group["week_ending"] == current_week, "report_count"].sum())
        previous_count = int(group.loc[group["week_ending"] == previous_week, "report_count"].sum())
        hist = group[group["week_ending"] < current_week].tail(12)["report_count"]
        avg = float(hist.mean()) if len(hist) else 0.0
        std = float(hist.std(ddof=1)) if len(hist) > 1 else 0.0
        deviation = ((current_count - avg) / std) if std > 0 else 0.0
        wow = ((current_count - previous_count) / previous_count * 100) if previous_count else (100.0 if current_count else 0.0)
        rows.append(
            {
                "scam_type": scam_type,
                "priority": _category_priority(scam_type),
                "this_week_national_count": current_count,
                "week_over_week_change": round(wow, 2),
                "12_week_average": round(avg, 2),
                "current_deviation": round(deviation, 3),
            }
        )
    return rows


def _cfpb_category_summary(trends_df: pd.DataFrame, alerts_df: pd.DataFrame) -> list[dict[str, Any]]:
    trend_rows = _cfpb_trend_rows(trends_df, alerts_df)
    alert_lookup: dict[str, dict[str, Any]] = {}
    if not alerts_df.empty:
        latest_alert_week = alerts_df["week_ending"].max()
        current_alerts = alerts_df[alerts_df["week_ending"] == latest_alert_week]
        tier_rank = {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}
        for scam_type, group in current_alerts.groupby("scam_type", dropna=False):
            ordered = group.sort_values(
                by=["alert_tier", "current_count"],
                key=lambda s: s.map(tier_rank).fillna(9) if s.name == "alert_tier" else s,
                ascending=[True, False],
            )
            alert_lookup[str(scam_type)] = ordered.iloc[0].to_dict()

    rows: list[dict[str, Any]] = []
    for row in trend_rows:
        alert = alert_lookup.get(str(row["scam_type"]), {})
        rows.append(
            {
                "scam_type": row["scam_type"],
                "priority": row["priority"],
                "this_week_national_count": row["this_week_national_count"],
                "12_week_average": row["12_week_average"],
                "current_alert_tier": alert.get("alert_tier"),
                "top_company_this_week": alert.get("top_company"),
            }
        )
    rows.sort(key=lambda r: (PRIORITY_ORDER.get(str(r["priority"]), 99), -int(r["this_week_national_count"] or 0)))
    return rows


def _briefing_markdown(builder: dict[str, Any], verifier: dict[str, Any], quality: dict[str, Any], output_status: str) -> str:
    lines = [
        "# Weekly Scam Intelligence Briefing",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Phase Status",
        f"- Builder: {builder.get('overall_status', 'UNKNOWN')}",
        f"- Verifier: {verifier.get('overall_status', 'UNKNOWN')}",
        f"- Data Quality: {quality.get('overall_status', 'UNKNOWN')}",
        f"- Output: {output_status}",
        "",
        "## Data Summary",
        f"- BBB records ingested: {builder.get('data_summary', {}).get('bbb_records_ingested', 0)}",
        f"- CFPB records ingested: {builder.get('data_summary', {}).get('cfpb_records_ingested', 0)}",
        f"- Local crime records: {builder.get('data_summary', {}).get('local_crime_records', 0)}",
        f"- BBB anomalies: {verifier.get('anomaly_summary', {}).get('bbb_anomalies_by_tier', {})}",
        f"- CFPB anomalies: {verifier.get('anomaly_summary', {}).get('cfpb_anomalies_by_tier', {})}",
        f"- Cross source signals: {quality.get('cross_source_signals', {}).get('count', 0)}",
    ]
    warnings: list[str] = []
    for report in (builder, verifier, quality):
        warnings.extend(report.get("warnings", []) or [])
        warnings.extend(report.get("issues", []) or [])
    if warnings:
        lines.extend(["", "## Warnings and Follow-up"])
        lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines) + "\n"


def write_outputs() -> dict[str, Any]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    builder = _read_json(AGENTS_DIR / "builder_report.json")
    verifier = _read_json(AGENTS_DIR / "verifier_report.json")
    quality = _read_json(AGENTS_DIR / "quality_report.json")
    trends_df, alerts_df, cfpb_warnings = _fetch_cfpb_data()

    table_counts = [{"table": table, "row_count": count} for table, count in sorted((verifier.get("table_counts") or {}).items())]
    cfpb_alert_rows = _cfpb_alert_rows(alerts_df)
    cfpb_trend_rows = _cfpb_trend_rows(trends_df, alerts_df)
    cfpb_category_summary = _cfpb_category_summary(trends_df, alerts_df)

    _write_csv(OUTPUT_DIR / "Supabase_Table_Counts.csv", table_counts, ["table", "row_count"])
    _write_csv(OUTPUT_DIR / "BBB_Anomalies.csv", _tier_rows("BBB", verifier.get("anomaly_summary", {}).get("bbb_anomalies_by_tier", {})), ["source", "alert_tier", "count"])
    _write_csv(OUTPUT_DIR / "CFPB_Anomalies.csv", _tier_rows("CFPB", verifier.get("anomaly_summary", {}).get("cfpb_anomalies_by_tier", {})), ["source", "alert_tier", "count"])
    _write_csv(OUTPUT_DIR / "CFPB_Anomaly_Alerts.csv", cfpb_alert_rows)
    _write_csv(OUTPUT_DIR / "CFPB_Category_Summary.csv", cfpb_category_summary)
    _write_csv(OUTPUT_DIR / "Cross_Source_Signals.csv", quality.get("cross_source_signals", {}).get("signals", []), ["signal_type", "description", "count"])
    _write_csv(
        OUTPUT_DIR / "Pipeline_Phase_Status.csv",
        [
            {"phase": "Builder", "status": builder.get("overall_status", "UNKNOWN")},
            {"phase": "Verifier", "status": verifier.get("overall_status", "UNKNOWN")},
            {"phase": "Data Quality", "status": quality.get("overall_status", "UNKNOWN")},
            {"phase": "Output", "status": "PASS"},
        ],
        ["phase", "status"],
    )

    briefing_path = OUTPUT_DIR / "Weekly_Briefing.md"
    briefing_path.write_text(_briefing_markdown(builder, verifier, quality, "PASS"), encoding="utf-8")

    workbook_path = OUTPUT_DIR / "Scam_Intelligence_Briefing.xlsx"
    sheet_counts: dict[str, int] = {}
    with pd.ExcelWriter(workbook_path, engine="openpyxl") as writer:
        sheets = {
            "Table Counts": pd.DataFrame(table_counts),
            "BBB Anomalies": pd.DataFrame(_tier_rows("BBB", verifier.get("anomaly_summary", {}).get("bbb_anomalies_by_tier", {}))),
            "CFPB Alerts": pd.DataFrame(cfpb_alert_rows),
            "CFPB Trends": pd.DataFrame(cfpb_trend_rows),
            "CFPB Category Summary": pd.DataFrame(cfpb_category_summary),
            "Narrative Samples": pd.DataFrame(quality.get("narrative_samples", [])),
            "Cross Signals": pd.DataFrame(quality.get("cross_source_signals", {}).get("signals", [])),
        }
        for sheet_name, frame in sheets.items():
            frame.to_excel(writer, sheet_name=sheet_name, index=False)
            sheet_counts[sheet_name] = len(frame)

    print("CFPB workbook sheet row counts:")
    for sheet_name, count in sheet_counts.items():
        print(f"- {sheet_name}: {count}")
    print("First 2 CFPB Category Summary rows:")
    for row in cfpb_category_summary[:2]:
        print(f"- {row}")
    for warning in cfpb_warnings:
        print(f"WARNING: {warning}")

    files = sorted(str(path.relative_to(REPO_ROOT)) for path in OUTPUT_DIR.iterdir() if path.is_file())
    result = {
        "overall_status": "PASS",
        "files": files,
        "excel_file": str(workbook_path.relative_to(REPO_ROOT)),
        "briefing_file": str(briefing_path.relative_to(REPO_ROOT)),
        "sheet_counts": sheet_counts,
        "cfpb_category_summary_first_rows": cfpb_category_summary[:2],
        "warnings": cfpb_warnings,
    }
    print(json.dumps(result, indent=2, default=str))
    return result


def main() -> dict[str, Any]:
    return write_outputs()


if __name__ == "__main__":
    main()
