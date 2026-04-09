from __future__ import annotations

import argparse
import os
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from supabase import Client, create_client


# ── Configuration ──────────────────────────────────────────────────────────────

LOOKBACK_WEEKS = 16
SHORT_WINDOW = 4
LONG_WINDOW = 8
DEVIATION_THRESHOLD = 1.2
HIGH_DEVIATION = 2.0

STATE_TIERS: dict[str, int] = {
    "CA": 1,
    "TX": 1,
    "FL": 1,
    "NY": 1,
    "PA": 2,
    "IL": 2,
    "OH": 2,
    "GA": 2,
    "NC": 2,
    "MI": 2,
    "NJ": 2,
    "VA": 2,
    "WA": 2,
    "AZ": 2,
    "TN": 2,
    "MA": 2,
    "IN": 2,
    "MD": 3,
    "MO": 3,
    "CO": 3,
    "WI": 3,
    "MN": 3,
    "SC": 3,
    "AL": 3,
    "KY": 3,
    "LA": 3,
    "OR": 3,
    "OK": 3,
    "CT": 4,
    "UT": 4,
    "NV": 4,
    "IA": 4,
    "AR": 4,
    "KS": 4,
    "MS": 4,
    "NM": 4,
    "ID": 4,
    "NE": 4,
    "WV": 5,
    "HI": 5,
    "NH": 5,
    "ME": 5,
    "MT": 5,
    "RI": 5,
    "DE": 5,
    "SD": 6,
    "ND": 6,
    "AK": 6,
    "DC": 6,
    "VT": 6,
    "WY": 6,
}

SCAM_TYPE_FLOORS: dict[str, list[int]] = {
    "Online Purchase": [25, 12, 8, 8, 8, 8],
    "Employment": [12, 8, 8, 8, 8, 8],
    "Phishing": [10, 8, 8, 8, 8, 8],
    "Identity Theft": [8, 8, 8, 8, 8, 8],
    "Investment": [8, 8, 8, 8, 8, 8],
    "Government Agency Imposter": [8, 8, 8, 8, 8, 8],
    "Romance": [8, 8, 8, 8, 8, 8],
    "Home Improvement": [8, 8, 8, 8, 8, 8],
    "Healthcare/Medicaid/Medicare": [8, 8, 8, 8, 8, 8],
    "default": [8, 8, 8, 8, 8, 8],
}
DEFAULT_STATE_TIER = 4
MIN_FLOOR = 8

NATIONAL_SHORT_WINDOW = 4
NATIONAL_LONG_WINDOW = 12

NATIONAL_FLOORS: dict[str, int] = {
    "Online Purchase": 165,
    "Employment": 75,
    "Phishing": 55,
    "Identity Theft": 45,
    "Investment": 20,
    "Government Agency Imposter": 20,
    "Romance": 20,
    "Home Improvement": 20,
    "Healthcare/Medicaid/Medicare": 20,
    "default": 25,
}

TIER_ORDER = {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}


def sunday_ending_week_containing(today: date | None = None) -> date:
    """Sunday at end of the Mon–Sun week that contains `today` (may be today or in the future)."""
    if today is None:
        today = date.today()
    return today + timedelta(days=(6 - today.weekday()) % 7)


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


# ── Data loading (single query) ────────────────────────────────────────────────

def pull_trends_data(client: Client) -> pd.DataFrame:
    cutoff = (date.today() - timedelta(weeks=LOOKBACK_WEEKS)).isoformat()
    # Include the week bucket that contains today. `build_trends` maps each report to the
    # Sunday ending its Mon–Sun week; capping at *last* Sunday dropped the in-progress
    # bucket (Mon..today) so mid-week runs saw no "current" spike rows.
    trends_week_upper = sunday_ending_week_containing().isoformat()
    rows: list[dict[str, Any]] = []
    page_size = 1000
    offset = 0

    while True:
        response = (
            client.table("bbb_trends")
            .select("week_ending,scam_type,state,report_count,avg_dollar_amount")
            .gte("week_ending", cutoff)
            .lte("week_ending", trends_week_upper)
            .range(offset, offset + page_size - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < page_size:
            break
        offset += page_size

    if not rows:
        return pd.DataFrame(
            columns=["week_ending", "scam_type", "state", "report_count", "avg_dollar_amount"]
        )

    df = pd.DataFrame(rows)
    df["week_ending"] = pd.to_datetime(df["week_ending"], errors="coerce")
    df["report_count"] = pd.to_numeric(df["report_count"], errors="coerce").fillna(0)
    df["avg_dollar_amount"] = pd.to_numeric(df["avg_dollar_amount"], errors="coerce").fillna(0)
    return df


# ── Helpers ────────────────────────────────────────────────────────────────────

def get_state_tier(state: Any) -> int:
    state_code = str(state).upper().strip() if state is not None else ""
    return STATE_TIERS.get(state_code, DEFAULT_STATE_TIER)


def get_floor(scam_type: str, state: Any) -> int:
    tier = get_state_tier(state)
    floors = SCAM_TYPE_FLOORS.get(scam_type, SCAM_TYPE_FLOORS["default"])
    value = floors[tier - 1] if 1 <= tier <= 6 else SCAM_TYPE_FLOORS["default"][DEFAULT_STATE_TIER - 1]
    return max(int(value), MIN_FLOOR)


def get_national_floor(scam_type: str) -> int:
    return NATIONAL_FLOORS.get(scam_type, NATIONAL_FLOORS["default"])


def build_national_df(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate state-level rows into national totals per scam_type per week."""
    return (
        df.groupby(["scam_type", "week_ending"], dropna=False)
        .agg(
            report_count=("report_count", "sum"),
            avg_dollar_amount=("avg_dollar_amount", "mean"),
        )
        .reset_index()
    )


def safe_zscore(value: float, mean: float, std: float) -> float:
    if pd.isna(std) or std == 0:
        return 0.0
    return (value - mean) / std


def base_tier(short_dev: float, long_dev: float) -> str:
    if short_dev > HIGH_DEVIATION and long_dev > HIGH_DEVIATION:
        return "CRITICAL"
    if short_dev > HIGH_DEVIATION or long_dev > HIGH_DEVIATION:
        return "ALERT"
    return "WATCH"


def elevate_tier(tier: str) -> str:
    if tier == "WATCH":
        return "ALERT"
    return "CRITICAL"


# ── Filter trace (--test mode) ────────────────────────────────────────────────

def _trace(enabled: bool, label: str, msg: str) -> None:
    if enabled:
        print(f"  {label}  {msg}")


# ── Core detection ─────────────────────────────────────────────────────────────

def detect_anomalies(df: pd.DataFrame, trace: bool = False) -> list[dict[str, Any]]:
    if df.empty:
        return []

    current_week = df["week_ending"].max()
    candidates: list[dict[str, Any]] = []
    trace_counts: dict[str, int] = {"no_current": 0, "f1": 0, "f2": 0, "f3": 0, "f4": 0, "survived": 0}

    for (scam_type, state), group in df.groupby(["scam_type", "state"], dropna=False):
        combo = f"{scam_type} / {state}"
        group = group.sort_values("week_ending").reset_index(drop=True)

        # ── Find the current-week row for this (scam_type, state) ────────────
        current_rows = group[group["week_ending"] == current_week]
        if current_rows.empty:
            trace_counts["no_current"] += 1
            _trace(trace, "[SKIP  ]", f"{combo}  →  no data for current week")
            continue
        current_row = current_rows.iloc[0]
        current_count = float(current_row["report_count"])
        current_dollar = float(current_row["avg_dollar_amount"])
        state_tier = get_state_tier(state)
        floor = get_floor(str(scam_type), state)
        _trace(trace, "[TIER   ]", f"{combo}  →  tier={state_tier} floor={floor}")

        # All weeks strictly before the current week, sorted oldest→newest
        historical = group[group["week_ending"] < current_week].sort_values("week_ending")

        # ── Filter 1: data sufficiency guard ─────────────────────────────────
        # Need at least LONG_WINDOW (8) historical rows for the long-window baseline.
        if len(historical) < LONG_WINDOW:
            trace_counts["f1"] += 1
            _trace(
                trace, "[F1 DROP]",
                f"{combo}  →  only {len(historical)} historical weeks (need {LONG_WINDOW})"
            )
            continue

        short_hist = historical.tail(SHORT_WINDOW)     # 4 most recent historical
        long_hist = historical.tail(LONG_WINDOW)        # 8 most recent historical

        # ── Filter 2: dual threshold statistical baseline ─────────────────────
        short_mean = short_hist["report_count"].mean()
        short_std = short_hist["report_count"].std(ddof=1)
        long_mean = long_hist["report_count"].mean()
        long_std = long_hist["report_count"].std(ddof=1)

        short_deviation = safe_zscore(current_count, short_mean, short_std)
        long_deviation = safe_zscore(current_count, long_mean, long_std)

        # Drop if BOTH deviations are below threshold
        if short_deviation < DEVIATION_THRESHOLD and long_deviation < DEVIATION_THRESHOLD:
            trace_counts["f2"] += 1
            _trace(
                trace, "[F2 DROP]",
                f"{combo}  →  short={short_deviation:+.3f}  long={long_deviation:+.3f}"
                f"  (both below ±{DEVIATION_THRESHOLD})  count={int(current_count)}"
            )
            continue

        # ── Filter 3: per-scam-type volume floor ──────────────────────────────
        if current_count < floor:
            trace_counts["f3"] += 1
            _trace(
                trace, "[F3 DROP]",
                f"{combo}  →  tier={state_tier}  count={int(current_count)} < floor={floor}"
                f"  (short={short_deviation:+.3f}  long={long_deviation:+.3f})"
            )
            continue

        # ── Filter 4: trend shape — previous week must also be above floor ────
        prev_row = historical.tail(1)
        prev_count = float(prev_row.iloc[0]["report_count"]) if not prev_row.empty else 0.0
        if prev_row.empty or prev_count < floor:
            trace_counts["f4"] += 1
            _trace(
                trace, "[F4 DROP]",
                f"{combo}  →  tier={state_tier}  prev_count={int(prev_count)} < floor={floor}"
                f"  (single-week spike, not sustained)"
            )
            continue

        # ── Filter 5: dollar amount trajectory ───────────────────────────────
        short_dollar_mean = short_hist["avg_dollar_amount"].mean()
        short_dollar_std = short_hist["avg_dollar_amount"].std(ddof=1)
        dollar_trajectory = (
            not pd.isna(short_dollar_std)
            and short_dollar_std > 0
            and current_dollar > short_dollar_mean + short_dollar_std
        )

        # ── Alert tier classification (with dollar trajectory elevation) ──────
        tier = base_tier(short_deviation, long_deviation)
        pre_elevation_tier = tier
        if dollar_trajectory:
            tier = elevate_tier(tier)

        trace_counts["survived"] += 1
        _trace(
            trace, "[PASS  ]",
            f"{combo}  →  count={int(current_count)}  short={short_deviation:+.3f}"
            f"  long={long_deviation:+.3f}  tier={state_tier}  floor={floor}"
            f"  $▲={'YES' if dollar_trajectory else 'no'}"
            + (f"  tier={pre_elevation_tier}→{tier}" if dollar_trajectory else f"  tier={tier}")
        )

        candidates.append(
            {
                "scam_type": scam_type,
                "state": state,
                "short_deviation": round(short_deviation, 3),
                "long_deviation": round(long_deviation, 3),
                "current_count": int(current_count),
                "alert_tier": tier,
                "dollar_trajectory": dollar_trajectory,
                "week_ending": (
                    current_week.date().isoformat() if pd.notna(current_week) else None
                ),
                    "detection_level": "State",
            }
        )

    if trace:
        total = sum(trace_counts.values())
        print(
            f"\n  Filter trace summary:"
            f"  total={total}"
            f"  no_current={trace_counts['no_current']}"
            f"  F1(data)={trace_counts['f1']}"
            f"  F2(deviation)={trace_counts['f2']}"
            f"  F3(volume)={trace_counts['f3']}"
            f"  F4(shape)={trace_counts['f4']}"
            f"  survived={trace_counts['survived']}\n"
        )

    if not candidates:
        return []

    # ── Scope classification ──────────────────────────────────────────────────
    # National total per scam_type for the current week (from full in-memory df)
    current_df = df[df["week_ending"] == current_week]
    national_totals: dict[str, float] = (
        current_df.groupby("scam_type", dropna=False)["report_count"]
        .sum()
        .to_dict()
    )

    # Number of distinct flagged states per scam_type
    flagged_state_count: dict[str, int] = {}
    for c in candidates:
        key = str(c["scam_type"])
        flagged_state_count[key] = flagged_state_count.get(key, 0) + 1

    for c in candidates:
        st = str(c["scam_type"])
        n_flagged = flagged_state_count.get(st, 1)
        nat_total = float(national_totals.get(st, 0))

        if n_flagged > 6:
            scope = "National"
        elif n_flagged >= 3:
            scope = "Regional"
        elif nat_total > 0 and c["current_count"] / nat_total > 0.50:
            scope = "Local"
        else:
            scope = "Local"

        c["scope"] = scope

    # ── Sort: CRITICAL first, then by short_deviation descending ─────────────
    candidates.sort(
        key=lambda r: (TIER_ORDER.get(r["alert_tier"], 99), -r["short_deviation"])
    )
    return candidates


# ── National-level detection ───────────────────────────────────────────────────

def detect_anomalies_national(df: pd.DataFrame, trace: bool = False) -> list[dict[str, Any]]:
    """Run anomaly detection on aggregated national totals (all states summed per week)."""
    national_df = build_national_df(df)
    if national_df.empty:
        return []

    current_week = national_df["week_ending"].max()
    candidates: list[dict[str, Any]] = []
    trace_counts: dict[str, int] = {
        "no_current": 0, "f1": 0, "f2": 0, "f3": 0, "f4": 0, "survived": 0,
    }

    for scam_type, group in national_df.groupby("scam_type", dropna=False):
        label = f"NATIONAL / {scam_type}"
        group = group.sort_values("week_ending").reset_index(drop=True)

        current_rows = group[group["week_ending"] == current_week]
        if current_rows.empty:
            trace_counts["no_current"] += 1
            _trace(trace, "[NAT-SKIP  ]", f"{label}  →  no data for current week")
            continue
        current_row = current_rows.iloc[0]
        current_count = float(current_row["report_count"])
        current_dollar = float(current_row["avg_dollar_amount"])

        historical = group[group["week_ending"] < current_week].sort_values("week_ending")

        # Filter 1: need NATIONAL_LONG_WINDOW (12) historical weeks
        if len(historical) < NATIONAL_LONG_WINDOW:
            trace_counts["f1"] += 1
            _trace(
                trace, "[NAT-F1 DROP]",
                f"{label}  →  only {len(historical)} historical weeks"
                f" (need {NATIONAL_LONG_WINDOW})",
            )
            continue

        short_hist = historical.tail(NATIONAL_SHORT_WINDOW)
        long_hist = historical.tail(NATIONAL_LONG_WINDOW)

        # Filter 2: dual threshold
        short_mean = short_hist["report_count"].mean()
        short_std = short_hist["report_count"].std(ddof=1)
        long_mean = long_hist["report_count"].mean()
        long_std = long_hist["report_count"].std(ddof=1)

        short_deviation = safe_zscore(current_count, short_mean, short_std)
        long_deviation = safe_zscore(current_count, long_mean, long_std)

        floor = get_national_floor(str(scam_type))
        prev_row = historical.tail(1)
        prev_count = float(prev_row.iloc[0]["report_count"]) if not prev_row.empty else 0.0

        _trace(
            trace,
            "[NAT-STAT ]",
            f"{label}  →  hist_weeks={len(historical)}  count={int(current_count)}"
            f"  short(mu={short_mean:.2f}, sd={short_std:.2f}, z={short_deviation:+.3f})"
            f"  long(mu={long_mean:.2f}, sd={long_std:.2f}, z={long_deviation:+.3f})"
            f"  floor={floor}  prev_count={int(prev_count)}",
        )

        if short_deviation < DEVIATION_THRESHOLD and long_deviation < DEVIATION_THRESHOLD:
            trace_counts["f2"] += 1
            _trace(
                trace, "[NAT-F2 DROP]",
                f"{label}  →  short={short_deviation:+.3f}  long={long_deviation:+.3f}"
                f"  (need at least one >= {DEVIATION_THRESHOLD:.1f})"
                f"  short_ok={short_deviation >= DEVIATION_THRESHOLD}"
                f"  long_ok={long_deviation >= DEVIATION_THRESHOLD}",
            )
            continue

        # Filter 3: national volume floor
        if current_count < floor:
            trace_counts["f3"] += 1
            _trace(
                trace, "[NAT-F3 DROP]",
                f"{label}  →  count={int(current_count)} < floor={floor}"
                f"  (required count >= {floor})"
                f"  short={short_deviation:+.3f}  long={long_deviation:+.3f}",
            )
            continue

        # Filter 4: previous week also above national floor
        if prev_row.empty or prev_count < floor:
            trace_counts["f4"] += 1
            _trace(
                trace, "[NAT-F4 DROP]",
                f"{label}  →  prev_count={int(prev_count)} < floor={floor}"
                f"  (required prev_count >= {floor}; single-week spike)",
            )
            continue

        # Filter 5: dollar trajectory
        short_dollar_mean = short_hist["avg_dollar_amount"].mean()
        short_dollar_std = short_hist["avg_dollar_amount"].std(ddof=1)
        dollar_trajectory = (
            not pd.isna(short_dollar_std)
            and short_dollar_std > 0
            and current_dollar > short_dollar_mean + short_dollar_std
        )

        tier = base_tier(short_deviation, long_deviation)
        pre_elevation_tier = tier
        if dollar_trajectory:
            tier = elevate_tier(tier)

        trace_counts["survived"] += 1
        _trace(
            trace, "[NAT-PASS  ]",
            f"{label}  →  count={int(current_count)}  short={short_deviation:+.3f}"
            f"  long={long_deviation:+.3f}  floor={floor}"
            f"  $▲={'YES' if dollar_trajectory else 'no'}"
            + (f"  tier={pre_elevation_tier}→{tier}" if dollar_trajectory else f"  tier={tier}"),
        )

        candidates.append(
            {
                "scam_type": scam_type,
                "state": None,
                "short_deviation": round(short_deviation, 3),
                "long_deviation": round(long_deviation, 3),
                "current_count": int(current_count),
                "alert_tier": tier,
                "dollar_trajectory": dollar_trajectory,
                "week_ending": (
                    current_week.date().isoformat() if pd.notna(current_week) else None
                ),
                "detection_level": "National",
            }
        )

    if trace:
        total = sum(trace_counts.values())
        print(
            f"\n  National filter trace summary:"
            f"  total={total}"
            f"  no_current={trace_counts['no_current']}"
            f"  F1(data)={trace_counts['f1']}"
            f"  F2(deviation)={trace_counts['f2']}"
            f"  F3(volume)={trace_counts['f3']}"
            f"  F4(shape)={trace_counts['f4']}"
            f"  survived={trace_counts['survived']}\n"
        )

    candidates.sort(
        key=lambda r: (TIER_ORDER.get(r["alert_tier"], 99), -r["short_deviation"])
    )
    return candidates


def merge_detection_results(
    national: list[dict[str, Any]],
    state: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge national and state results; tag detection_level and elevate tier for Both."""
    national_types = {r["scam_type"] for r in national}
    state_types = {r["scam_type"] for r in state}
    both_types = national_types & state_types

    merged: list[dict[str, Any]] = []

    for r in national:
        r = r.copy()
        if r["scam_type"] in both_types:
            r["detection_level"] = "Both"
            r["alert_tier"] = elevate_tier(r["alert_tier"])
        merged.append(r)

    for r in state:
        r = r.copy()
        if r["scam_type"] in both_types:
            r["detection_level"] = "Both"
            r["alert_tier"] = elevate_tier(r["alert_tier"])
        merged.append(r)

    return merged


# ── Output formatting ──────────────────────────────────────────────────────────

_DIVIDER_HEAVY = "=" * 78
_DIVIDER_MED = "-" * 78
_DIVIDER_LIGHT = "." * 78

_TIER_DIVIDER = {
    "CRITICAL": _DIVIDER_HEAVY,
    "ALERT": _DIVIDER_MED,
    "WATCH": _DIVIDER_LIGHT,
}

_STATE_FIELDS = [
    ("scam_type",       "Type"),
    ("state",           "State"),
    ("week_ending",     "Week"),
    ("current_count",   "Count"),
    ("short_deviation", "ShortDev"),
    ("long_deviation",  "LongDev"),
    ("alert_tier",      "Tier"),
    ("scope",           "Scope"),
    ("dollar_trajectory", "$▲"),
]

_NATIONAL_FIELDS = [
    ("scam_type",         "Type"),
    ("week_ending",       "Week"),
    ("current_count",     "NatCount"),
    ("short_deviation",   "ShortDev"),
    ("long_deviation",    "LongDev"),
    ("alert_tier",        "Tier"),
    ("dollar_trajectory", "$▲"),
]


def _format_row(a: dict[str, Any]) -> str:
    fields = _NATIONAL_FIELDS if a.get("state") is None else _STATE_FIELDS
    parts = []
    for key, label in fields:
        val = a.get(key, "")
        if key == "dollar_trajectory":
            val = "YES" if val else "no"
        elif key in ("short_deviation", "long_deviation"):
            val = f"{val:+.3f}"
        parts.append(f"{label}: {val}")
    return "  " + "  |  ".join(parts)


def print_results(anomalies: list[dict[str, Any]]) -> None:
    if not anomalies:
        print("\nNo anomalies detected for the current week.")
        return

    both_rows     = [a for a in anomalies if a.get("detection_level") == "Both"]
    national_rows = [a for a in anomalies if a.get("detection_level") == "National"]
    state_rows    = [a for a in anomalies if a.get("detection_level") == "State"]

    n_total = len(anomalies)
    n_by_tier = {t: sum(1 for a in anomalies if a["alert_tier"] == t) for t in TIER_ORDER}

    print(f"\n{'#' * 78}")
    print(
        f"  ANOMALY DETECTION RESULTS  |  "
        f"Total entries: {n_total}  |  "
        f"CRITICAL: {n_by_tier['CRITICAL']}  "
        f"ALERT: {n_by_tier['ALERT']}  "
        f"WATCH: {n_by_tier['WATCH']}"
    )
    print(
        f"  Both: {len(both_rows) // 2 if both_rows else 0} scam type(s)  |  "
        f"National-only: {len(national_rows)}  |  "
        f"State-only: {len(state_rows)}"
    )
    print(f"{'#' * 78}")

    # ── Section 1: Both — highest confidence (national AND state flagged) ──────
    print(f"\n{'#' * 78}")
    print(f"  ★  SECTION 1 — BOTH  (Flagged at National + State Level)")
    print(f"     Tier elevated one level for all entries in this section.")
    print(f"{'#' * 78}")

    if not both_rows:
        print("  No scam types flagged at both levels this week.")
    else:
        both_national = [r for r in both_rows if r.get("state") is None]
        both_state    = [r for r in both_rows if r.get("state") is not None]
        for scam_type in sorted({r["scam_type"] for r in both_rows}):
            nat_entry  = next((r for r in both_national if r["scam_type"] == scam_type), None)
            st_entries = sorted(
                [r for r in both_state if r["scam_type"] == scam_type],
                key=lambda r: (TIER_ORDER.get(r["alert_tier"], 99), -r["short_deviation"]),
            )
            tier = (nat_entry or st_entries[0])["alert_tier"] if (nat_entry or st_entries) else "WATCH"
            div  = _TIER_DIVIDER.get(tier, _DIVIDER_LIGHT)
            print(f"\n{div}")
            print(f"  ▶  {scam_type}  [{tier}]")
            print(div)
            if nat_entry:
                print(f"  ► National  {_format_row(nat_entry)}")
            for r in st_entries:
                print(f"  ► State     {_format_row(r)}")

    # ── Section 2: National-only detections ────────────────────────────────────
    print(f"\n{_DIVIDER_HEAVY}")
    print(f"  SECTION 2 — NATIONAL DETECTIONS  [{len(national_rows)} entries]")
    print(f"  Scam types anomalous at the national aggregate level only.")
    print(_DIVIDER_HEAVY)

    if not national_rows:
        print("  No national-only anomalies detected this week.")
    else:
        for tier in ("CRITICAL", "ALERT", "WATCH"):
            tier_rows = [a for a in national_rows if a["alert_tier"] == tier]
            if not tier_rows:
                continue
            div = _TIER_DIVIDER[tier]
            print(f"\n{div}")
            print(f"  ▶  {tier}  ({len(tier_rows)} national anomaly/-ies)")
            print(div)
            for a in tier_rows:
                print(_format_row(a))

    # ── Section 3: State-only detections ───────────────────────────────────────
    print(f"\n{_DIVIDER_HEAVY}")
    print(f"  SECTION 3 — STATE DETECTIONS  [{len(state_rows)} entries]")
    print(f"  Scam types anomalous at the state level only.")
    print(_DIVIDER_HEAVY)

    if not state_rows:
        print("  No state-only anomalies detected this week.")
    else:
        for tier in ("CRITICAL", "ALERT", "WATCH"):
            tier_rows = [a for a in state_rows if a["alert_tier"] == tier]
            if not tier_rows:
                continue
            div = _TIER_DIVIDER[tier]
            print(f"\n{div}")
            print(f"  ▶  {tier}  ({len(tier_rows)} state anomaly/-ies)")
            print(div)
            for a in tier_rows:
                print(_format_row(a))

    print(f"\n{_DIVIDER_HEAVY}\n")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BBB scam anomaly detection")
    parser.add_argument(
        "--test",
        action="store_true",
        help="Print a filter trace for every scam_type/state combination showing "
             "which filter dropped it and why, or its final alert tier if it survived.",
    )
    parser.add_argument(
        "--national-test",
        "-national-test",
        action="store_true",
        help="Print only the national pass filter trace (no state trace).",
    )
    args = parser.parse_args()

    national_trace = args.test or args.national_test
    state_trace = args.test and not args.national_test

    client = get_supabase_client()
    df = pull_trends_data(client)

    if df.empty:
        print("No trend data found for the last 16 weeks.")
    else:
        n_combos = df.groupby(["scam_type", "state"], dropna=False).ngroups
        print(
            f"Loaded {len(df)} rows | "
            f"{df['week_ending'].nunique()} weeks | "
            f"{n_combos} scam_type/state combinations"
        )
        if args.test or args.national_test:
            print(f"\n{'=' * 78}")
            if args.national_test and not args.test:
                print("  FILTER TRACE  (-national-test mode: national only)")
            else:
                print("  FILTER TRACE  (--test mode)")
            print(f"{'=' * 78}")
            print("\n  ── National pass ──────────────────────────────────────")
        national_anomalies = detect_anomalies_national(df, trace=national_trace)
        if state_trace:
            print("\n  ── State pass ─────────────────────────────────────────")
        state_anomalies = detect_anomalies(df, trace=state_trace)
        anomalies = merge_detection_results(national_anomalies, state_anomalies)
        print_results(anomalies)
