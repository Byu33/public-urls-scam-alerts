from __future__ import annotations

import argparse
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "bbb") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "bbb"))
if str(_REPO_ROOT / "cfpb") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "cfpb"))

from detect_anomalies import STATE_TIERS  # noqa: E402
from fetch_trends import CFPB_SCAM_CATEGORIES  # noqa: E402


SHORT_WINDOW = 8
LONG_WINDOW = 16
WATCH_THRESHOLD = 1.2
ALERT_THRESHOLD = 2.0
CRITICAL_THRESHOLD = 2.5
MIN_STATE_FLOOR = 5
DEFAULT_STATE_TIER = 4
PAGE_SIZE = 1000
UPSERT_BATCH_SIZE = 500

CFPB_NATIONAL_FLOORS: dict[str, int] = {
    "Government Impersonation Debt Collection": 15,
    "Illegal Debt Collection Threats": 20,
    "Phantom Debt Identity Theft": 75,
    "Credit Card Identity Theft": 40,
    "Unauthorized Card Charges": 30,
    "Account Takeover Unauthorized Charges": 50,
    "Fraudulent Account Opening": 15,
    "Explicit Fraud or Scam": 60,
    "Predatory Service Advance Fee": 10,
    "Predatory Upfront Fee Scam": 10,
    "Fraudulent Loan": 15,
    "Student Loan Relief Scam": 10,
    "Payment Transfer Fraud": 75,
    "Prepaid Card Purchase Fraud": 15,
    "Digital Wallet Account Takeover": 25,
    "Unauthorized Loan Identity Theft": 10,
    "default": 25,
}

CFPB_STATE_FLOORS: dict[str, list[int]] = {
    "Government Impersonation Debt Collection": [8, 6, 5, 5, 5, 5],
    "Illegal Debt Collection Threats": [8, 6, 5, 5, 5, 5],
    "Phantom Debt Identity Theft": [20, 12, 8, 6, 5, 5],
    "Credit Card Identity Theft": [15, 10, 7, 5, 5, 5],
    "Unauthorized Card Charges": [12, 8, 6, 5, 5, 5],
    "Account Takeover Unauthorized Charges": [15, 10, 7, 5, 5, 5],
    "Fraudulent Account Opening": [8, 6, 5, 5, 5, 5],
    "Explicit Fraud or Scam": [20, 12, 8, 6, 5, 5],
    "Predatory Service Advance Fee": [6, 5, 5, 5, 5, 5],
    "Predatory Upfront Fee Scam": [6, 5, 5, 5, 5, 5],
    "Fraudulent Loan": [8, 6, 5, 5, 5, 5],
    "Student Loan Relief Scam": [6, 5, 5, 5, 5, 5],
    "Payment Transfer Fraud": [25, 15, 10, 7, 5, 5],
    "Prepaid Card Purchase Fraud": [8, 6, 5, 5, 5, 5],
    "Digital Wallet Account Takeover": [10, 7, 5, 5, 5, 5],
    "Unauthorized Loan Identity Theft": [6, 5, 5, 5, 5, 5],
    "default": [10, 7, 5, 5, 5, 5],
}

TIER_ORDER = {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}


def get_supabase_client() -> Client:
    load_dotenv(_REPO_ROOT / ".env.local")
    load_dotenv(_REPO_ROOT / ".env")
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        raise ValueError("Missing SUPABASE_URL and Supabase service/anon key.")
    return create_client(url, key)


def _category_map() -> dict[str, dict[str, Any]]:
    return {str(category["scam_type"]): category for category in CFPB_SCAM_CATEGORIES}


def _get_state_tier(state: Any) -> int:
    return int(STATE_TIERS.get(str(state).upper().strip(), DEFAULT_STATE_TIER))


def _get_state_floor(scam_type: str, state: Any) -> int:
    tier = _get_state_tier(state)
    floors = CFPB_STATE_FLOORS.get(scam_type, CFPB_STATE_FLOORS["default"])
    value = floors[tier - 1] if 1 <= tier <= 6 else CFPB_STATE_FLOORS["default"][DEFAULT_STATE_TIER - 1]
    return max(int(value), MIN_STATE_FLOOR)


def _get_national_floor(scam_type: str) -> int:
    return int(CFPB_NATIONAL_FLOORS.get(scam_type, CFPB_NATIONAL_FLOORS["default"]))


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
    return df[df["scam_type"].notna()].copy()


def _safe_deviation(value: float, mean: float, std: float) -> float:
    if pd.isna(std) or std <= 0:
        if value > mean:
            return 999.0
        if value < mean:
            return -999.0
        return 0.0
    return (value - mean) / std


def _tier_for(short_deviation: float, long_deviation: float) -> str | None:
    if short_deviation >= CRITICAL_THRESHOLD and long_deviation >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if short_deviation >= ALERT_THRESHOLD or long_deviation >= ALERT_THRESHOLD:
        return "ALERT"
    if short_deviation >= WATCH_THRESHOLD or long_deviation >= WATCH_THRESHOLD:
        return "WATCH"
    return None


def _threshold_for_tier(tier: str) -> float:
    if tier == "CRITICAL":
        return CRITICAL_THRESHOLD
    if tier == "ALERT":
        return ALERT_THRESHOLD
    return WATCH_THRESHOLD


def _elevate_tier(tier: str) -> str:
    if tier == "WATCH":
        return "ALERT"
    return "CRITICAL"


def _series_for_group(group: pd.DataFrame, current_week: pd.Timestamp) -> pd.Series:
    start_week = current_week - pd.Timedelta(weeks=LONG_WINDOW + 2)
    weeks = pd.date_range(start_week, current_week, freq="7D")
    series = (
        group.groupby("week_ending")["report_count"]
        .sum()
        .reindex(weeks, fill_value=0)
        .astype(float)
    )
    return series


def _deviations_for_position(series: pd.Series, position: int) -> tuple[float, float, float, float, float]:
    current = float(series.iloc[position])
    previous = series.iloc[:position]
    short_hist = previous.tail(SHORT_WINDOW)
    long_hist = previous.tail(LONG_WINDOW)
    short_mean = float(short_hist.mean()) if len(short_hist) else 0.0
    short_std = float(short_hist.std(ddof=1)) if len(short_hist) > 1 else 0.0
    long_mean = float(long_hist.mean()) if len(long_hist) else 0.0
    long_std = float(long_hist.std(ddof=1)) if len(long_hist) > 1 else 0.0
    return (
        current,
        _safe_deviation(current, short_mean, short_std),
        _safe_deviation(current, long_mean, long_std),
        short_mean,
        long_mean,
    )


def _passes_consecutive_check(series: pd.Series, tier: str, floor: int) -> bool:
    if len(series) < 2:
        return False
    threshold = _threshold_for_tier(tier)
    prev_position = len(series) - 2
    previous_count, previous_short, previous_long, _, _ = _deviations_for_position(series, prev_position)
    if tier == "CRITICAL":
        previous_threshold = previous_short >= threshold and previous_long >= threshold
    else:
        previous_threshold = previous_short >= threshold or previous_long >= threshold
    return previous_count > floor and previous_threshold


def _trace(enabled: bool, summary: Counter, label: str, message: str) -> None:
    summary[label] += 1
    if enabled:
        print(f"  [{label}] {message}")


def _detect_group(
    group: pd.DataFrame,
    scam_type: str,
    state: str,
    current_week: pd.Timestamp,
    floor: int,
    detection_level: str,
    trace: bool,
    summary: Counter,
) -> dict[str, Any] | None:
    label = f"{detection_level} / {scam_type} / {state}"
    group = group.sort_values("week_ending")
    current_rows = group[group["week_ending"] == current_week]
    if current_rows.empty:
        _trace(trace, summary, "NO_CURRENT", f"{label}: no row for {current_week.date().isoformat()}")
        return None

    series = _series_for_group(group, current_week)
    hist16 = series.iloc[-(LONG_WINDOW + 1) : -1]
    nonzero_weeks = int((hist16 > 0).sum())
    if nonzero_weeks < SHORT_WINDOW:
        _trace(trace, summary, "F1_DATA", f"{label}: {nonzero_weeks} non-zero weeks in 16-week window")
        return None

    current_count, short_dev, long_dev, short_mean, long_mean = _deviations_for_position(series, len(series) - 1)
    tier = _tier_for(short_dev, long_dev)
    if tier is None:
        _trace(trace, summary, "F2_THRESHOLD", f"{label}: short={short_dev:+.3f} long={long_dev:+.3f}")
        return None

    if current_count <= floor:
        _trace(trace, summary, "F3_FLOOR", f"{label}: count={int(current_count)} floor={floor} tier={tier}")
        return None

    if not _passes_consecutive_check(series, tier, floor):
        _trace(trace, summary, "F4_CONSEC", f"{label}: tier={tier} did not persist for 2 consecutive weeks")
        return None

    category = _category_map().get(scam_type, {})
    row = current_rows.iloc[0]
    sub_issues = category.get("sub_issues") or []
    anomaly = {
        "product": row.get("product") or category.get("product"),
        "issue": row.get("issue") or category.get("issue"),
        "sub_issue": ", ".join(sub_issues) if sub_issues else None,
        "scam_type": scam_type,
        "priority": row.get("priority") or category.get("priority"),
        "state": state,
        "alert_tier": tier,
        "scope": "National" if state == "NATIONAL" else "Local",
        "short_deviation": round(short_dev, 3),
        "long_deviation": round(long_dev, 3),
        "current_count": int(current_count),
        "week_ending": current_week.date().isoformat(),
        "detection_level": detection_level,
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "detection_window_short": SHORT_WINDOW,
        "detection_window_long": LONG_WINDOW,
        "baseline_mean_short": round(short_mean, 3),
        "baseline_mean_long": round(long_mean, 3),
    }
    _trace(
        trace,
        summary,
        "PASS",
        f"{label}: tier={tier} count={int(current_count)} floor={floor} short={short_dev:+.3f} long={long_dev:+.3f}",
    )
    return anomaly


def detect_cfpb_anomalies_national(df: pd.DataFrame, trace: bool = True) -> tuple[list[dict[str, Any]], Counter]:
    summary: Counter = Counter()
    if df.empty:
        return [], summary
    current_week = df["week_ending"].max()
    national_df = df[df["state"] == "NATIONAL"]
    anomalies: list[dict[str, Any]] = []
    for scam_type, group in national_df.groupby("scam_type", dropna=False):
        anomaly = _detect_group(
            group=group,
            scam_type=str(scam_type),
            state="NATIONAL",
            current_week=current_week,
            floor=_get_national_floor(str(scam_type)),
            detection_level="National",
            trace=trace,
            summary=summary,
        )
        if anomaly:
            anomalies.append(anomaly)
    return anomalies, summary


def detect_cfpb_anomalies(df: pd.DataFrame, trace: bool = True) -> tuple[list[dict[str, Any]], Counter]:
    summary: Counter = Counter()
    if df.empty:
        return [], summary
    current_week = df["week_ending"].max()
    state_df = df[df["state"] != "NATIONAL"]
    anomalies: list[dict[str, Any]] = []
    for (scam_type, state), group in state_df.groupby(["scam_type", "state"], dropna=False):
        anomaly = _detect_group(
            group=group,
            scam_type=str(scam_type),
            state=str(state),
            current_week=current_week,
            floor=_get_state_floor(str(scam_type), state),
            detection_level="State",
            trace=trace,
            summary=summary,
        )
        if anomaly:
            anomalies.append(anomaly)
    _assign_state_scopes(anomalies, df, current_week)
    return anomalies, summary


def _assign_state_scopes(anomalies: list[dict[str, Any]], df: pd.DataFrame, current_week: pd.Timestamp) -> None:
    flagged_count: Counter = Counter((row["scam_type"], row["week_ending"]) for row in anomalies)
    national_week = df[(df["state"] == "NATIONAL") & (df["week_ending"] == current_week)]
    national_counts = {
        str(row["scam_type"]): int(row["report_count"])
        for _, row in national_week.iterrows()
    }
    for anomaly in anomalies:
        key = (anomaly["scam_type"], anomaly["week_ending"])
        count = flagged_count[key]
        national_volume = national_counts.get(anomaly["scam_type"], 0)
        if count >= 6:
            anomaly["scope"] = "National"
        elif 2 <= count <= 5:
            anomaly["scope"] = "Regional"
        elif national_volume > 0 and anomaly["current_count"] / national_volume > 0.50:
            anomaly["scope"] = "Local"
        else:
            anomaly["scope"] = "Local"


def merge_cfpb_results(
    national: list[dict[str, Any]],
    state: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    national_keys = {(row["scam_type"], row["week_ending"]) for row in national}
    state_keys = {(row["scam_type"], row["week_ending"]) for row in state}
    both = national_keys & state_keys
    merged: list[dict[str, Any]] = []
    for row in national + state:
        copy = row.copy()
        if (copy["scam_type"], copy["week_ending"]) in both:
            copy["detection_level"] = "Both"
            copy["alert_tier"] = _elevate_tier(str(copy["alert_tier"]))
        merged.append(copy)
    merged.sort(key=lambda item: (TIER_ORDER.get(str(item["alert_tier"]), 99), -float(item["short_deviation"])))
    return merged


def upsert_cfpb_anomaly_alerts(client: Client, anomalies: list[dict[str, Any]]) -> int:
    if not anomalies:
        return 0
    payload = [
        {
            "run_timestamp": row["run_timestamp"],
            "product": row["product"],
            "issue": row["issue"],
            "sub_issue": row.get("sub_issue"),
            "scam_type": row["scam_type"],
            "priority": row.get("priority"),
            "state": row["state"],
            "alert_tier": row["alert_tier"],
            "scope": row["scope"],
            "short_deviation": row["short_deviation"],
            "long_deviation": row["long_deviation"],
            "current_count": row["current_count"],
            "week_ending": row["week_ending"],
            "detection_level": row["detection_level"],
            "detection_window_short": SHORT_WINDOW,
            "detection_window_long": LONG_WINDOW,
            "analysis_status": "pending_analysis",
        }
        for row in anomalies
    ]
    upserted = 0
    for start in range(0, len(payload), UPSERT_BATCH_SIZE):
        batch = payload[start : start + UPSERT_BATCH_SIZE]
        try:
            client.table("cfpb_anomaly_alerts").upsert(
                batch,
                on_conflict="week_ending,scam_type,state,detection_level",
            ).execute()
        except APIError as exc:
            raise RuntimeError(
                "cfpb_anomaly_alerts upsert failed. Apply the CFPB scam pipeline migration before detection."
            ) from exc
        upserted += len(batch)
    return upserted


def print_cfpb_results(anomalies: list[dict[str, Any]]) -> None:
    print("\nCFPB anomaly results")
    if not anomalies:
        print("- No CFPB anomalies detected.")
        return
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for anomaly in anomalies:
        grouped[anomaly["scam_type"]].append(anomaly)
    for scam_type in sorted(grouped):
        print(f"\n{scam_type}")
        for row in grouped[scam_type]:
            print(
                f"  [{row['alert_tier']}] state={row['state']} scope={row['scope']} "
                f"level={row['detection_level']} count={row['current_count']} "
                f"short={row['short_deviation']:+.3f} long={row['long_deviation']:+.3f}"
            )

    print("\nHigh priority CFPB focus categories")
    focus_terms = ("Government Impersonation", "Payment Transfer Fraud", "Identity Theft")
    focus = [row for row in anomalies if any(term in row["scam_type"] for term in focus_terms)]
    if not focus:
        print("- None")
        return
    for row in focus:
        print(
            f"- {row['scam_type']} | {row['state']} | {row['alert_tier']} | "
            f"count={row['current_count']} short={row['short_deviation']:+.3f}"
        )


def _print_filter_summary(label: str, summary: Counter) -> None:
    print(f"\n{label} filter summary")
    for key in ("NO_CURRENT", "F1_DATA", "F2_THRESHOLD", "F3_FLOOR", "F4_CONSEC", "PASS"):
        print(f"- {key}: {int(summary.get(key, 0))}")


def run_detection(trace: bool = True, persist: bool = True) -> list[dict[str, Any]]:
    client = get_supabase_client()
    df = pull_cfpb_trends(client)
    if df.empty:
        print("No CFPB trend data found.")
        return []

    print(
        f"Loaded {len(df)} CFPB trends rows | {df['week_ending'].nunique()} weeks | "
        f"{df['scam_type'].nunique()} scam categories"
    )
    national, national_summary = detect_cfpb_anomalies_national(df, trace=trace)
    state, state_summary = detect_cfpb_anomalies(df, trace=trace)
    anomalies = merge_cfpb_results(national, state)
    if persist:
        inserted = upsert_cfpb_anomaly_alerts(client, anomalies)
        print(f"\ncfpb_anomaly_alerts rows upserted: {inserted}")
    _print_filter_summary("National pass", national_summary)
    _print_filter_summary("State pass", state_summary)
    print_cfpb_results(anomalies)
    return anomalies


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect CFPB scam category anomalies.")
    parser.add_argument("--no-trace", action="store_true")
    parser.add_argument("--no-persist", action="store_true")
    args = parser.parse_args()
    run_detection(trace=not args.no_trace, persist=not args.no_persist)
