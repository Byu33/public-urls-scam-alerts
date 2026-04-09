from __future__ import annotations

"""
fetch_cfpb_historical.py
------------------------
Build a 52-week baseline of CFPB trend data in cfpb_trends.

Strategy (one call per category per state for the full date range):
  1. For each of the 8 CFPB categories, call the CFPB complaints API with a
     52-week date window and paginate through all raw records.
  2. Do a national call (no state filter) and per-state calls for all 51 states.
  3. Aggregate the raw records into weekly counts in Python, then upsert to
     cfpb_trends in batches of 500.

This approach uses ~(8 national + 8x51 state) = ~416 API calls rather than
52 weeks x 400+ calls, making the historical backfill feasible.
"""

import logging
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any

# Add cfpb and repo root to path for sibling imports
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_REPO_ROOT / "cfpb") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "cfpb"))

from fetch_trends import (  # noqa: E402
    CFPB_CATEGORIES,
    ALL_STATES,
    REQUEST_DELAY_SECONDS,
    _fetch_category,
)
from build_cfpb_trends import get_supabase_client, upsert_cfpb_trends, aggregate_trend_rows  # noqa: E402


# ── Logging ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename="cfpb_historical_errors.log",
    level=logging.ERROR,
    format="%(asctime)s  %(levelname)s  %(message)s",
)

INTER_CALL_DELAY = 1.0   # seconds between API calls
INTER_STATE_DELAY = 0.0  # no extra delay between states (INTER_CALL_DELAY covers it)


def run_historical_backfill(lookback_weeks: int = 52) -> dict[str, Any]:
    """
    Fetch 52 weeks of CFPB trend data for all categories and states,
    then upsert to cfpb_trends.

    Returns summary dict with total_calls, total_rows_upserted, errors.
    """
    today = date.today()
    date_min = (today - timedelta(weeks=lookback_weeks)).isoformat()
    date_max = today.isoformat()

    print(
        f"\nCFPB Historical Backfill\n"
        f"  Date range : {date_min} to {date_max}\n"
        f"  Categories : {len(CFPB_CATEGORIES)}\n"
        f"  States     : {len(ALL_STATES)} + NATIONAL\n"
        f"  Total calls: ~{len(CFPB_CATEGORIES) * (1 + len(ALL_STATES))}"
    )

    client = get_supabase_client()

    total_calls = 0
    total_rows_upserted = 0
    errors: list[str] = []

    # ── National pass ──────────────────────────────────────────────────────────
    print(f"\n{'-' * 60}")
    print("  NATIONAL PASS")
    print(f"{'-' * 60}")

    all_national_rows: list[dict[str, Any]] = []
    for cat in CFPB_CATEGORIES:
        try:
            rows = _fetch_category(cat, date_min, date_max, state=None)
            all_national_rows.extend(rows)
            print(
                f"  [NATIONAL] {cat['scam_type']:35s}  buckets={len(rows)}"
            )
        except Exception as exc:
            msg = f"NATIONAL / {cat['scam_type']}: {exc}"
            logging.error(msg)
            errors.append(msg)
            print(f"  ERROR: {msg}")

        total_calls += 1
        time.sleep(INTER_CALL_DELAY)

    if all_national_rows:
        aggregated = aggregate_trend_rows(all_national_rows)
        upserted = upsert_cfpb_trends(client, aggregated)
        total_rows_upserted += upserted
        print(f"  National upserted: {upserted} rows")

    # ── State pass ─────────────────────────────────────────────────────────────
    print(f"\n{'-' * 60}")
    print(f"  STATE PASS  ({len(ALL_STATES)} states × {len(CFPB_CATEGORIES)} categories)")
    print(f"{'-' * 60}")

    for state_idx, state in enumerate(ALL_STATES, start=1):
        state_rows: list[dict[str, Any]] = []
        state_errors = 0

        for cat in CFPB_CATEGORIES:
            try:
                rows = _fetch_category(cat, date_min, date_max, state=state)
                state_rows.extend(rows)
            except Exception as exc:
                msg = f"{state} / {cat['scam_type']}: {exc}"
                logging.error(msg)
                errors.append(msg)
                state_errors += 1

            total_calls += 1
            time.sleep(INTER_CALL_DELAY)

        if state_rows:
            aggregated = aggregate_trend_rows(state_rows)
            upserted = upsert_cfpb_trends(client, aggregated)
            total_rows_upserted += upserted
        else:
            upserted = 0

        print(
            f"  [{state_idx:2d}/{len(ALL_STATES)}]  {state}  "
            f"rows={len(state_rows)}  upserted={upserted}"
            + (f"  errors={state_errors}" if state_errors else "")
        )

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("  CFPB Historical Backfill Complete")
    print(f"  Total API calls       : {total_calls}")
    print(f"  Total rows upserted   : {total_rows_upserted}")
    print(f"  Errors                : {len(errors)}")
    if errors:
        print(f"  Error log             : cfpb_historical_errors.log")
    print(f"{'=' * 60}\n")

    return {
        "total_calls": total_calls,
        "total_rows_upserted": total_rows_upserted,
        "errors": len(errors),
        "date_min": date_min,
        "date_max": date_max,
    }


if __name__ == "__main__":
    result = run_historical_backfill(lookback_weeks=52)
    sys.exit(0 if result["errors"] == 0 else 1)
