from __future__ import annotations

import argparse
import os
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from dotenv import load_dotenv
from supabase import Client, create_client

# ── Import STATE_TIERS from BBB detect_anomalies ──────────────────────────────
# cfpb/ sits one level below repo root; bbb/ is a sibling directory.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "bbb") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "bbb"))

from detect_anomalies import STATE_TIERS  # noqa: E402


# ── Configuration ──────────────────────────────────────────────────────────────

LOOKBACK_WEEKS = 24
SHORT_WINDOW = 4
LONG_WINDOW = 8
DEVIATION_THRESHOLD = 1.0
HIGH_DEVIATION = 2.0

NATIONAL_SHORT_WINDOW = 4
NATIONAL_LONG_WINDOW = 8

DEFAULT_STATE_TIER = 4
MIN_FLOOR = 5
RECENT_WEEK_COMPLETENESS_WINDOW = 4
MIN_RECENT_WEEK_COMPLETENESS = 0.50
REQUIRE_PREVIOUS_WEEK_ABOVE_FLOOR = False

CFPB_NATIONAL_FLOORS: dict[str, int] = {
    "Fraud or scam": 120,
    "Managing an account": 90,
    "Problem with a lender or other company charging your account": 60,
    "Problem with a purchase shown on your statement": 80,
    "Getting a credit card": 45,
    "False statements or representation": 100,
    "Problem with a purchase or transfer": 15,
    "Didn't provide services promised": 10,
    "default": 50,
}

# Six-tier state floors keyed by CFPB issue, values are [T1, T2, T3, T4, T5, T6]
CFPB_STATE_FLOORS: dict[str, list[int]] = {
    "Fraud or scam": [8, 5, 5, 5, 5, 5],
    "Managing an account": [8, 5, 5, 5, 5, 5],
    "Problem with a lender or other company charging your account": [8, 5, 5, 5, 5, 5],
    "Problem with a purchase shown on your statement": [10, 6, 5, 5, 5, 5],
    "Getting a credit card": [8, 5, 5, 5, 5, 5],
    "False statements or representation": [10, 6, 5, 5, 5, 5],
    "Problem with a purchase or transfer": [5, 5, 5, 5, 5, 5],
    "Didn't provide services promised": [5, 5, 5, 5, 5, 5],
    "default": [5, 5, 5, 5, 5, 5],
}

TIER_ORDER = {"CRITICAL": 0, "ALERT": 1, "WATCH": 2}


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


# ── Data loading ───────────────────────────────────────────────────────────────

def pull_cfpb_trends(client: Client) -> pd.DataFrame:
    cutoff = (date.today() - timedelta(weeks=LOOKBACK_WEEKS)).isoformat()
    days_since_last_sunday = date.today().weekday() + 1
    last_sunday = (date.today() - timedelta(days=days_since_last_sunday)).isoformat()

    rows: list[dict[str, Any]] = []
    page_size = 1000
    offset = 0

    while True:
        response = (
            client.table("cfpb_trends")
            .select("week_ending,product,issue,state,report_count")
            .gte("week_ending", cutoff)
            .lte("week_ending", last_sunday)
            .range(offset, offset + page_size - 1)
            .execute()
        )
        page = response.data or []
        rows.extend(page)
        if len(page) < page_size:
            break
        offset += page_size

    if not rows:
        return pd.DataFrame(columns=["week_ending", "product", "issue", "state", "report_count"])

    df = pd.DataFrame(rows)
    df["week_ending"] = pd.to_datetime(df["week_ending"], errors="coerce")
    df["report_count"] = pd.to_numeric(df["report_count"], errors="coerce").fillna(0)
    return df


# ── Floor helpers ──────────────────────────────────────────────────────────────

def _get_state_tier(state: Any) -> int:
    code = str(state).upper().strip() if state is not None else ""
    return STATE_TIERS.get(code, DEFAULT_STATE_TIER)


def _get_state_floor(scam_type: str, state: Any) -> int:
    tier = _get_state_tier(state)
    floors = CFPB_STATE_FLOORS.get(scam_type, CFPB_STATE_FLOORS["default"])
    value = floors[tier - 1] if 1 <= tier <= 6 else CFPB_STATE_FLOORS["default"][DEFAULT_STATE_TIER - 1]
    return max(int(value), MIN_FLOOR)


def _get_national_floor(scam_type: str) -> int:
    return CFPB_NATIONAL_FLOORS.get(scam_type, CFPB_NATIONAL_FLOORS["default"])


# ── Statistical helpers ────────────────────────────────────────────────────────

def _safe_zscore(value: float, mean: float, std: float) -> float:
    if pd.isna(std) or std == 0:
        return 0.0
    return (value - mean) / std


def _base_tier(short_dev: float, long_dev: float) -> str:
    if short_dev > HIGH_DEVIATION and long_dev > HIGH_DEVIATION:
        return "CRITICAL"
    if short_dev > HIGH_DEVIATION or long_dev > HIGH_DEVIATION:
        return "ALERT"
    return "WATCH"


def _elevate_tier(tier: str) -> str:
    if tier == "WATCH":
        return "ALERT"
    return "CRITICAL"


# ── Filter trace ───────────────────────────────────────────────────────────────

def _trace(enabled: bool, label: str, msg: str) -> None:
    if enabled:
        print(f"  {label}  {msg}")


# ── National aggregate ─────────────────────────────────────────────────────────

def _build_national_df(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate state-level cfpb_trends rows into national totals per product/issue/week.

    Rows with state='NATIONAL' are used directly if present; otherwise
    state-level rows are summed to produce national totals.
    """
    national_rows = df[df["state"] == "NATIONAL"]
    if not national_rows.empty:
        return national_rows[["product", "issue", "week_ending", "report_count"]].copy()

    # Fall back: aggregate from state rows
    state_rows = df[df["state"] != "NATIONAL"]
    if state_rows.empty:
        return pd.DataFrame(columns=["product", "issue", "week_ending", "report_count"])

    return (
        state_rows.groupby(["product", "issue", "week_ending"], dropna=False)
        .agg(report_count=("report_count", "sum"))
        .reset_index()
    )


def _select_analysis_week(df: pd.DataFrame, trace: bool = False) -> pd.Timestamp:
    """Choose the latest CFPB week that is not obviously suppressed by reporting lag."""
    if "state" in df.columns:
        weekly_df = _build_national_df(df)
    else:
        weekly_df = df

    totals = (
        weekly_df.groupby("week_ending", dropna=False)["report_count"]
        .sum()
        .sort_index()
    )
    if totals.empty:
        return df["week_ending"].max()

    selected_week = totals.index.max()
    for week in sorted(totals.index, reverse=True):
        previous = totals[totals.index < week].tail(RECENT_WEEK_COMPLETENESS_WINDOW)
        if len(previous) < RECENT_WEEK_COMPLETENESS_WINDOW:
            selected_week = week
            break

        baseline = float(previous.median())
        current_total = float(totals.loc[week])
        minimum_total = baseline * MIN_RECENT_WEEK_COMPLETENESS
        if baseline <= 0 or current_total >= minimum_total:
            selected_week = week
            break

        _trace(
            trace,
            "[WEEK DROP]",
            f"{week.date().isoformat()} total={int(current_total)}"
            f" < {MIN_RECENT_WEEK_COMPLETENESS:.0%} of recent median {int(baseline)}"
            " (likely CFPB reporting lag)",
        )

    if selected_week != totals.index.max():
        _trace(trace, "[WEEK USE]", f"using {selected_week.date().isoformat()} for CFPB alerts")
    return selected_week


# ── State-level detection ──────────────────────────────────────────────────────

def detect_cfpb_anomalies(df: pd.DataFrame, trace: bool = False) -> list[dict[str, Any]]:
    """Detect anomalies at the state level using SHORT_WINDOW / LONG_WINDOW."""
    state_df = df[df["state"] != "NATIONAL"]
    if state_df.empty:
        return []

    current_week = _select_analysis_week(df, trace=trace)
    candidates: list[dict[str, Any]] = []
    trace_counts: dict[str, int] = {
        "no_current": 0, "f1": 0, "f2": 0, "f3": 0, "f4": 0, "survived": 0,
    }

    for (product, issue, state), group in state_df.groupby(
        ["product", "issue", "state"], dropna=False
    ):
        combo = f"{product} / {issue} / {state}"
        group = group.sort_values("week_ending").reset_index(drop=True)

        current_rows = group[group["week_ending"] == current_week]
        if current_rows.empty:
            trace_counts["no_current"] += 1
            _trace(trace, "[SKIP  ]", f"{combo}  →  no data for current week")
            continue

        current_count = float(current_rows.iloc[0]["report_count"])
        floor = _get_state_floor(str(issue), state)
        state_tier = _get_state_tier(state)
        _trace(trace, "[TIER  ]", f"{combo}  →  tier={state_tier}  floor={floor}")

        historical = group[group["week_ending"] < current_week].sort_values("week_ending")

        # Filter 1: data sufficiency — need LONG_WINDOW historical rows
        if len(historical) < LONG_WINDOW:
            trace_counts["f1"] += 1
            _trace(
                trace, "[F1 DROP]",
                f"{combo}  →  only {len(historical)} historical weeks (need {LONG_WINDOW})"
            )
            continue

        short_hist = historical.tail(SHORT_WINDOW)
        long_hist = historical.tail(LONG_WINDOW)

        # Filter 2: dual threshold
        short_mean = short_hist["report_count"].mean()
        short_std = short_hist["report_count"].std(ddof=1)
        long_mean = long_hist["report_count"].mean()
        long_std = long_hist["report_count"].std(ddof=1)

        short_dev = _safe_zscore(current_count, short_mean, short_std)
        long_dev = _safe_zscore(current_count, long_mean, long_std)

        if short_dev < DEVIATION_THRESHOLD and long_dev < DEVIATION_THRESHOLD:
            trace_counts["f2"] += 1
            _trace(
                trace, "[F2 DROP]",
                f"{combo}  →  short={short_dev:+.3f}  long={long_dev:+.3f}"
                f"  (both below {DEVIATION_THRESHOLD})"
            )
            continue

        # Filter 3: volume floor
        if current_count < floor:
            trace_counts["f3"] += 1
            _trace(
                trace, "[F3 DROP]",
                f"{combo}  →  count={int(current_count)} < floor={floor}"
            )
            continue

        # Filter 4: optional trend shape — previous week also above floor
        prev_row = historical.tail(1)
        prev_count = float(prev_row.iloc[0]["report_count"]) if not prev_row.empty else 0.0
        if REQUIRE_PREVIOUS_WEEK_ABOVE_FLOOR and (prev_row.empty or prev_count < floor):
            trace_counts["f4"] += 1
            _trace(
                trace, "[F4 DROP]",
                f"{combo}  →  prev_count={int(prev_count)} < floor={floor}  (single-week spike)"
            )
            continue
        if prev_row.empty or prev_count < floor:
            _trace(
                trace, "[F4 NOTE]",
                f"{combo}  →  prev_count={int(prev_count)} < floor={floor}  (allowed)",
            )

        # No Filter 5 (dollar trajectory) — CFPB trends have no dollar data

        tier = _base_tier(short_dev, long_dev)
        trace_counts["survived"] += 1
        _trace(
            trace, "[PASS  ]",
            f"{combo}  →  count={int(current_count)}  short={short_dev:+.3f}"
            f"  long={long_dev:+.3f}  tier={tier}"
        )

        candidates.append(
            {
                "product": product,
                "issue": issue,
                "state": state,
                "short_deviation": round(short_dev, 3),
                "long_deviation": round(long_dev, 3),
                "current_count": int(current_count),
                "alert_tier": tier,
                "week_ending": (
                    current_week.date().isoformat() if pd.notna(current_week) else None
                ),
                "detection_level": "State",
            }
        )

    if trace:
        total = sum(trace_counts.values())
        print(
            f"\n  CFPB state filter summary: total={total}"
            f"  no_current={trace_counts['no_current']}"
            f"  F1={trace_counts['f1']}  F2={trace_counts['f2']}"
            f"  F3={trace_counts['f3']}  F4={trace_counts['f4']}"
            f"  survived={trace_counts['survived']}\n"
        )

    if not candidates:
        return []

    # Scope classification
    current_df = df[df["week_ending"] == current_week]
    national_totals: dict[tuple, float] = {}
    for (product, issue), grp in current_df.groupby(["product", "issue"], dropna=False):
        national_totals[(product, issue)] = float(grp["report_count"].sum())

    flagged_state_count: dict[tuple, int] = {}
    for c in candidates:
        key = (c["product"], c["issue"])
        flagged_state_count[key] = flagged_state_count.get(key, 0) + 1

    for c in candidates:
        key = (c["product"], c["issue"])
        n_flagged = flagged_state_count.get(key, 1)
        nat_total = national_totals.get(key, 0.0)

        if n_flagged > 6:
            scope = "National"
        elif n_flagged >= 3:
            scope = "Regional"
        elif nat_total > 0 and c["current_count"] / nat_total > 0.50:
            scope = "Local"
        else:
            scope = "Local"

        c["scope"] = scope

    candidates.sort(key=lambda r: (TIER_ORDER.get(r["alert_tier"], 99), -r["short_deviation"]))
    return candidates


# ── National-level detection ───────────────────────────────────────────────────

def detect_cfpb_anomalies_national(df: pd.DataFrame, trace: bool = False) -> list[dict[str, Any]]:
    """Detect anomalies at the national level."""
    national_df = _build_national_df(df)
    if national_df.empty:
        return []

    current_week = _select_analysis_week(national_df, trace=trace)
    candidates: list[dict[str, Any]] = []
    trace_counts: dict[str, int] = {
        "no_current": 0, "f1": 0, "f2": 0, "f3": 0, "f4": 0, "survived": 0,
    }

    for (product, issue), group in national_df.groupby(["product", "issue"], dropna=False):
        label = f"NATIONAL / {product} / {issue}"
        group = group.sort_values("week_ending").reset_index(drop=True)

        current_rows = group[group["week_ending"] == current_week]
        if current_rows.empty:
            trace_counts["no_current"] += 1
            _trace(trace, "[NAT-SKIP]", f"{label}  →  no data for current week")
            continue

        current_count = float(current_rows.iloc[0]["report_count"])
        historical = group[group["week_ending"] < current_week].sort_values("week_ending")

        # Filter 1
        if len(historical) < NATIONAL_LONG_WINDOW:
            trace_counts["f1"] += 1
            _trace(
                trace, "[NAT-F1 DROP]",
                f"{label}  →  only {len(historical)} historical weeks (need {NATIONAL_LONG_WINDOW})"
            )
            continue

        short_hist = historical.tail(NATIONAL_SHORT_WINDOW)
        long_hist = historical.tail(NATIONAL_LONG_WINDOW)

        short_mean = short_hist["report_count"].mean()
        short_std = short_hist["report_count"].std(ddof=1)
        long_mean = long_hist["report_count"].mean()
        long_std = long_hist["report_count"].std(ddof=1)

        short_dev = _safe_zscore(current_count, short_mean, short_std)
        long_dev = _safe_zscore(current_count, long_mean, long_std)

        floor = _get_national_floor(str(issue))
        prev_row = historical.tail(1)
        prev_count = float(prev_row.iloc[0]["report_count"]) if not prev_row.empty else 0.0

        _trace(
            trace, "[NAT-STAT]",
            f"{label}  →  hist={len(historical)}  count={int(current_count)}"
            f"  short(z={short_dev:+.3f})  long(z={long_dev:+.3f})"
            f"  floor={floor}  prev={int(prev_count)}"
        )

        # Filter 2
        if short_dev < DEVIATION_THRESHOLD and long_dev < DEVIATION_THRESHOLD:
            trace_counts["f2"] += 1
            _trace(trace, "[NAT-F2 DROP]", f"{label}  →  both below {DEVIATION_THRESHOLD}")
            continue

        # Filter 3
        if current_count < floor:
            trace_counts["f3"] += 1
            _trace(trace, "[NAT-F3 DROP]", f"{label}  →  count={int(current_count)} < floor={floor}")
            continue

        # Filter 4
        if REQUIRE_PREVIOUS_WEEK_ABOVE_FLOOR and (prev_row.empty or prev_count < floor):
            trace_counts["f4"] += 1
            _trace(trace, "[NAT-F4 DROP]", f"{label}  →  prev={int(prev_count)} < floor={floor}")
            continue
        if prev_row.empty or prev_count < floor:
            _trace(trace, "[NAT-F4 NOTE]", f"{label}  →  prev={int(prev_count)} < floor={floor}  (allowed)")

        tier = _base_tier(short_dev, long_dev)
        trace_counts["survived"] += 1
        _trace(
            trace, "[NAT-PASS]",
            f"{label}  →  count={int(current_count)}  short={short_dev:+.3f}"
            f"  long={long_dev:+.3f}  tier={tier}"
        )

        candidates.append(
            {
                "product": product,
                "issue": issue,
                "state": None,
                "short_deviation": round(short_dev, 3),
                "long_deviation": round(long_dev, 3),
                "current_count": int(current_count),
                "alert_tier": tier,
                "week_ending": (
                    current_week.date().isoformat() if pd.notna(current_week) else None
                ),
                "detection_level": "National",
            }
        )

    if trace:
        total = sum(trace_counts.values())
        print(
            f"\n  CFPB national filter summary: total={total}"
            f"  no_current={trace_counts['no_current']}"
            f"  F1={trace_counts['f1']}  F2={trace_counts['f2']}"
            f"  F3={trace_counts['f3']}  F4={trace_counts['f4']}"
            f"  survived={trace_counts['survived']}\n"
        )

    candidates.sort(key=lambda r: (TIER_ORDER.get(r["alert_tier"], 99), -r["short_deviation"]))
    return candidates


# ── Merge ──────────────────────────────────────────────────────────────────────

def merge_cfpb_results(
    national: list[dict[str, Any]],
    state: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge national and state results; elevate tier for Both detections."""
    # Key by (product, issue) for national matches
    national_keys = {(r["product"], r["issue"]) for r in national}
    state_keys = {(r["product"], r["issue"]) for r in state}
    both_keys = national_keys & state_keys

    merged: list[dict[str, Any]] = []

    for r in national:
        r = r.copy()
        if (r["product"], r["issue"]) in both_keys:
            r["detection_level"] = "Both"
            r["alert_tier"] = _elevate_tier(r["alert_tier"])
        merged.append(r)

    for r in state:
        r = r.copy()
        if (r["product"], r["issue"]) in both_keys:
            r["detection_level"] = "Both"
            r["alert_tier"] = _elevate_tier(r["alert_tier"])
        merged.append(r)

    return merged


# ── Output ─────────────────────────────────────────────────────────────────────

def print_cfpb_results(anomalies: list[dict[str, Any]]) -> None:
    if not anomalies:
        print("\nNo CFPB anomalies detected for the current week.")
        return

    n_by_tier = {t: sum(1 for a in anomalies if a["alert_tier"] == t) for t in TIER_ORDER}
    both_rows = [a for a in anomalies if a.get("detection_level") == "Both"]
    nat_rows = [a for a in anomalies if a.get("detection_level") == "National"]
    state_rows = [a for a in anomalies if a.get("detection_level") == "State"]

    print(f"\n{'#' * 78}")
    print(
        f"  CFPB ANOMALY RESULTS  |  Total: {len(anomalies)}  |  "
        f"CRITICAL: {n_by_tier['CRITICAL']}  "
        f"ALERT: {n_by_tier['ALERT']}  "
        f"WATCH: {n_by_tier['WATCH']}"
    )
    print(
        f"  Both: {len(both_rows) // 2 if both_rows else 0}  |  "
        f"National-only: {len(nat_rows)}  |  "
        f"State-only: {len(state_rows)}"
    )
    print(f"{'#' * 78}")

    for section_label, section_rows in [
        ("BOTH (national + state flagged)", both_rows),
        ("NATIONAL ONLY", nat_rows),
        ("STATE ONLY", state_rows),
    ]:
        print(f"\n--- {section_label} ---")
        if not section_rows:
            print("  None")
            continue
        for a in section_rows:
            print(
                f"  [{a['alert_tier']:8s}]  "
                f"{str(a.get('product',''))[:35]:35s}  "
                f"{str(a.get('issue',''))[:35]:35s}  "
                f"state={str(a.get('state') or 'NATIONAL'):12s}  "
                f"count={a.get('current_count',0):5d}  "
                f"short={a.get('short_deviation',0):+.3f}  "
                f"long={a.get('long_deviation',0):+.3f}  "
                f"scope={a.get('scope','')}"
            )

    print(f"\n{'#' * 78}\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def run_detection(trace: bool = False) -> list[dict[str, Any]]:
    client = get_supabase_client()
    df = pull_cfpb_trends(client)

    if df.empty:
        print("No CFPB trend data found for the last 24 weeks.")
        return []

    n_combos = df[df["state"] != "NATIONAL"].groupby(
        ["product", "issue", "state"], dropna=False
    ).ngroups
    print(
        f"Loaded {len(df)} CFPB trend rows | "
        f"{df['week_ending'].nunique()} weeks | "
        f"{n_combos} product/issue/state combinations"
    )

    national = detect_cfpb_anomalies_national(df, trace=trace)
    state = detect_cfpb_anomalies(df, trace=trace)
    anomalies = merge_cfpb_results(national, state)
    print_cfpb_results(anomalies)
    return anomalies


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CFPB anomaly detection")
    parser.add_argument("--test", action="store_true", help="Print filter trace")
    args = parser.parse_args()
    run_detection(trace=args.test)
