from __future__ import annotations

import time
from datetime import date, timedelta
from typing import Any

import requests

# ── CFPB API ───────────────────────────────────────────────────────────────────

CFPB_API_BASE = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"

# All US states + DC used for state-level trend calls
ALL_STATES = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DC", "DE", "FL",
    "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME",
    "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH",
    "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI",
    "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
]

# ── Category definitions ───────────────────────────────────────────────────────

CFPB_CATEGORIES: list[dict[str, Any]] = [
    {
        "product": "Money transfer, virtual currency, or money service",
        "sub_products": [
            "Domestic money transfer",
            "International money transfer",
            "Virtual currency",
        ],
        "issue": "Fraud or scam",
        "scam_type": "Payment Fraud",
    },
    {
        "product": "Checking or savings account",
        "sub_products": ["Checking account"],
        "issue": "Problem with a lender or other company charging your account",
        "scam_type": "Account Takeover",
    },
    {
        "product": "Checking or savings account",
        "sub_products": ["Checking account"],
        "issue": "Managing an account",
        "scam_type": "Debit Card Fraud",
    },
    {
        "product": "Credit card or prepaid card",
        "sub_products": ["General-purpose credit card or charge card"],
        "issue": "Problem with a purchase shown on your statement",
        "scam_type": "Credit Card Fraud",
    },
    {
        "product": "Credit card or prepaid card",
        "sub_products": ["General-purpose credit card or charge card"],
        "issue": "Getting a credit card",
        "scam_type": "Identity Theft",
    },
    {
        "product": "Debt collection",
        "sub_products": [],
        "issue": "False statements or representation",
        "scam_type": "Debt Collection Fraud",
    },
    {
        "product": "Credit card or prepaid card",
        "sub_products": ["General-purpose prepaid card", "Gift card"],
        "issue": "Problem with a purchase or transfer",
        "scam_type": "Gift Card Scam",
    },
    {
        "product": "Debt or credit management",
        "sub_products": ["Student loan debt relief", "Mortgage modification"],
        "issue": "Didn't provide services promised",
        "scam_type": "Predatory Service Scam",
    },
]

REQUEST_DELAY_SECONDS = 0.5
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_WAIT_SECONDS = 5

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
}

# Page size for paginated record fetches
PAGE_SIZE = 5000

# Lookback used by fetch_trends (24 weeks for detection context)
LOOKBACK_WEEKS = 24


# ── HTTP helper ────────────────────────────────────────────────────────────────

def _get_with_retry(params: dict[str, Any]) -> Any:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                CFPB_API_BASE,
                params=params,
                headers=_HEADERS,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            print(f"  Timeout on attempt {attempt}/{MAX_RETRIES}")
        except requests.exceptions.HTTPError as exc:
            print(f"  HTTP {exc.response.status_code} on attempt {attempt}/{MAX_RETRIES}")
        except Exception as exc:
            print(f"  Request error on attempt {attempt}/{MAX_RETRIES}: {exc}")

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_WAIT_SECONDS)

    return None


# ── Record parsing ─────────────────────────────────────────────────────────────

def _extract_records(data: Any) -> list[dict[str, Any]]:
    """
    Extract the list of complaint records from an API response.

    The CFPB API returns a flat list of complaint objects (each with a _source
    key) rather than Elasticsearch-style aggregation buckets.
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Some response shapes nest records under a 'hits' key
        hits = data.get("hits")
        if isinstance(hits, list):
            return hits
        if isinstance(hits, dict):
            inner = hits.get("hits")
            if isinstance(inner, list):
                return inner
    return []


def _aggregate_records_by_week(
    records: list[dict[str, Any]],
    product: str,
    sub_products: list[str],
    issue: str,
    scam_type: str,
    state: str,
) -> list[dict[str, Any]]:
    """
    Count complaints per week_ending from a flat list of raw complaint records.

    Each record is expected to have a date_received field (YYYY-MM-DD or
    similar ISO string) inside _source or at the top level.
    """
    week_counts: dict[str, int] = {}

    for item in records:
        src = item.get("_source") if isinstance(item, dict) else None
        if src is None:
            src = item

        date_str = src.get("date_received") if isinstance(src, dict) else None
        if not date_str:
            continue

        try:
            d = date.fromisoformat(str(date_str)[:10])
        except ValueError:
            continue

        # Advance to the Sunday ending of this week
        days_to_sunday = (6 - d.weekday()) % 7
        week_ending = (d + timedelta(days=days_to_sunday)).isoformat()
        week_counts[week_ending] = week_counts.get(week_ending, 0) + 1

    rows: list[dict[str, Any]] = []
    for week_ending, count in sorted(week_counts.items()):
        rows.append(
            {
                "week_ending": week_ending,
                "product": product,
                "sub_product": sub_products[0] if len(sub_products) == 1 else None,
                "issue": issue,
                "scam_type": scam_type,
                "state": state,
                "report_count": count,
            }
        )

    return rows


# ── Single category fetch ──────────────────────────────────────────────────────

def _fetch_category(
    category: dict[str, Any],
    date_min: str,
    date_max: str,
    state: str | None = None,
) -> list[dict[str, Any]]:
    """
    Fetch all complaint records for one category over the given date range,
    then aggregate into weekly row dicts.

    The CFPB API returns raw records (not aggregation buckets), so we paginate
    through all records using 'from' / 'size' and count by week ourselves.
    """
    product = category["product"]
    issue = category["issue"]
    sub_products = category.get("sub_products", [])

    all_records: list[dict[str, Any]] = []
    offset = 0

    while True:
        params: dict[str, Any] = {
            "product": product,
            "issue": issue,
            "date_received_min": date_min,
            "date_received_max": date_max,
            "no_aggs": "true",
            "format": "json",
            "size": PAGE_SIZE,
            "from": offset,
        }

        if len(sub_products) == 1:
            params["sub_product"] = sub_products[0]

        if state is not None:
            params["state"] = state

        data = _get_with_retry(params)
        if data is None:
            break

        page = _extract_records(data)
        all_records.extend(page)

        if len(page) < PAGE_SIZE:
            break

        offset += PAGE_SIZE
        time.sleep(REQUEST_DELAY_SECONDS)

    return _aggregate_records_by_week(
        records=all_records,
        product=product,
        sub_products=sub_products,
        issue=issue,
        scam_type=category["scam_type"],
        state=state if state is not None else "NATIONAL",
    )


# ── Main entry point ───────────────────────────────────────────────────────────

def fetch_cfpb_trends(
    lookback_weeks: int = LOOKBACK_WEEKS,
    states: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Pull weekly CFPB trend data for all 8 categories.

    - National call (state='NATIONAL') for each category.
    - Per-state calls for every state in `states` (defaults to ALL_STATES).

    Returns a flat list of row dicts ready for build_cfpb_trends.py.
    """
    if states is None:
        states = ALL_STATES

    today = date.today()
    date_min = (today - timedelta(weeks=lookback_weeks)).isoformat()
    date_max = today.isoformat()

    all_rows: list[dict[str, Any]] = []
    total_calls = 0

    # ── National pass ──────────────────────────────────────────────────────────
    print(f"Fetching national CFPB trends  ({len(CFPB_CATEGORIES)} categories)")
    for cat in CFPB_CATEGORIES:
        rows = _fetch_category(cat, date_min, date_max, state=None)
        all_rows.extend(rows)
        total_calls += 1
        print(
            f"  [NATIONAL] {cat['scam_type']:30s}  weeks={len(rows)}"
        )
        time.sleep(REQUEST_DELAY_SECONDS)

    # ── State pass ─────────────────────────────────────────────────────────────
    print(
        f"\nFetching state-level CFPB trends  "
        f"({len(states)} states x {len(CFPB_CATEGORIES)} categories = "
        f"{len(states) * len(CFPB_CATEGORIES)} calls)"
    )

    for state in states:
        state_rows = 0
        for cat in CFPB_CATEGORIES:
            rows = _fetch_category(cat, date_min, date_max, state=state)
            all_rows.extend(rows)
            state_rows += len(rows)
            total_calls += 1
            time.sleep(REQUEST_DELAY_SECONDS)
        print(f"  [{state}]  total_weeks={state_rows}")

    print(
        f"\nfetch_cfpb_trends complete: "
        f"total_api_calls={total_calls}  "
        f"total_data_points={len(all_rows)}"
    )
    return all_rows


def main() -> list[dict[str, Any]]:
    return fetch_cfpb_trends()


if __name__ == "__main__":
    rows = main()
    print(f"Returned {len(rows)} trend rows")
    if rows:
        print(f"Date range: {min(r['week_ending'] for r in rows)} to {max(r['week_ending'] for r in rows)}")
        from collections import Counter
        scam_counts = Counter(r["scam_type"] for r in rows)
        for scam_type, count in scam_counts.most_common():
            print(f"  {scam_type}: {count} rows")
