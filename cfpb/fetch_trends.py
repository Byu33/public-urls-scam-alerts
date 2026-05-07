from __future__ import annotations

import argparse
import os
import time
from collections import defaultdict
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client


CFPB_API_BASE = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"
TRENDS_ENDPOINT = CFPB_API_BASE + "trends"

ALL_STATES = [
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DC", "DE", "FL",
    "GA", "HI", "ID", "IL", "IN", "IA", "KS", "KY", "LA", "ME",
    "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH",
    "NJ", "NM", "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI",
    "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV", "WI", "WY",
]

CFPB_SCAM_CATEGORIES: list[dict[str, Any]] = [
    {
        "scam_type": "Government Impersonation Debt Collection",
        "product": "Debt collection",
        "issue": "False statements or representation",
        "sub_issues": [
            "Impersonated attorney, law enforcement, or government official",
            "Indicated you were committing crime by not paying debt",
        ],
        "priority": "HIGH",
        "volume_weight": 0.3,
    },
    {
        "scam_type": "Illegal Debt Collection Threats",
        "product": "Debt collection",
        "issue": "Took or threatened to take negative or legal action",
        "sub_issues": [
            "Threatened to arrest you or take you to jail if you do not pay",
            "Threatened to turn you in to immigration or deport you",
        ],
        "priority": "HIGH",
        "volume_weight": 0.4,
    },
    {
        "scam_type": "Phantom Debt Identity Theft",
        "product": "Debt collection",
        "issue": "Attempts to collect debt not owed",
        "sub_issues": [
            "Debt is not yours",
            "Debt was result of identity theft",
        ],
        "priority": "HIGH",
        "volume_weight": 1.5,
    },
    {
        "scam_type": "Credit Card Identity Theft",
        "product": "Credit card or prepaid card",
        "issue": "Getting a credit card",
        "sub_issues": [
            "Card opened without my consent or knowledge",
            "Card opened as result of identity theft or fraud",
        ],
        "priority": "HIGH",
        "volume_weight": 0.8,
    },
    {
        "scam_type": "Unauthorized Card Charges",
        "product": "Credit card or prepaid card",
        "issue": "Problem with a purchase shown on your statement",
        "sub_issues": [
            "Card was charged for something you did not purchase with the card",
        ],
        "priority": "HIGH",
        "volume_weight": 0.6,
    },
    {
        "scam_type": "Account Takeover Unauthorized Charges",
        "product": "Checking or savings account",
        "issue": "Problem with a lender or other company charging your account",
        "sub_issues": [
            "Transaction was not authorized",
            "Can't stop withdrawals from your account",
        ],
        "priority": "HIGH",
        "volume_weight": 1.0,
    },
    {
        "scam_type": "Fraudulent Account Opening",
        "product": "Checking or savings account",
        "issue": "Opening an account",
        "sub_issues": [
            "Account opened without my consent or knowledge",
            "Account opened as a result of fraud",
        ],
        "priority": "HIGH",
        "volume_weight": 0.3,
    },
    {
        "scam_type": "Explicit Fraud or Scam",
        "product": "Credit monitoring or identity theft protection services",
        "issue": "Fraud or scam",
        "sub_issues": [],
        "priority": "HIGH",
        "volume_weight": 1.2,
    },
    {
        "scam_type": "Predatory Service Advance Fee",
        "product": "Debt or credit management",
        "issue": "Didn't provide services promised",
        "sub_issues": [],
        "priority": "MEDIUM",
        "volume_weight": 0.2,
    },
    {
        "scam_type": "Predatory Upfront Fee Scam",
        "product": "Debt or credit management",
        "issue": "Charged upfront or unexpected fees",
        "sub_issues": [],
        "priority": "MEDIUM",
        "volume_weight": 0.2,
    },
    {
        "scam_type": "Fraudulent Loan",
        "product": "Payday loan, title loan, personal loan, or advance loan",
        "issue": "Getting a loan",
        "sub_issues": [
            "Loan opened without my consent or knowledge",
            "Fraudulent loan",
        ],
        "priority": "MEDIUM",
        "volume_weight": 0.3,
    },
    {
        "scam_type": "Student Loan Relief Scam",
        "product": "Student loan",
        "issue": "Dealing with your lender or servicer",
        "sub_issues": [
            "Didn't provide services promised",
            "Received bad information about your loan",
        ],
        "priority": "MEDIUM",
        "volume_weight": 0.2,
    },
    {
        "scam_type": "Payment Transfer Fraud",
        "product": "Money transfer, virtual currency, or money service",
        "issue": "Fraud or scam",
        "sub_issues": [],
        "priority": "HIGH",
        "volume_weight": 1.5,
    },
    {
        "scam_type": "Prepaid Card Purchase Fraud",
        "product": "Credit card or prepaid card",
        "issue": "Problem with a purchase or transfer",
        "sub_issues": [
            "Charged for a purchase or transfer you did not make with the card",
        ],
        "priority": "MEDIUM",
        "volume_weight": 0.3,
    },
    {
        "scam_type": "Digital Wallet Account Takeover",
        "product": "Checking or savings account",
        "issue": "Managing an account",
        "sub_issues": [
            "Problem using a debit or ATM card",
            "Funds not handled or disbursed as instructed",
        ],
        "priority": "MEDIUM",
        "volume_weight": 0.5,
    },
    {
        "scam_type": "Unauthorized Loan Identity Theft",
        "product": "Vehicle loan or lease",
        "issue": "Getting a loan or lease",
        "sub_issues": [
            "Loan opened without my consent or knowledge",
            "Fraudulent loan",
        ],
        "priority": "MEDIUM",
        "volume_weight": 0.2,
    },
]

REQUEST_DELAY_SECONDS = float(os.getenv("CFPB_REQUEST_DELAY_SECONDS", "0.5"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("CFPB_REQUEST_TIMEOUT_SECONDS", "30"))
UPSERT_BATCH_SIZE = 500

_HEADERS = {
    "User-Agent": "public-urls-scam-alerts/1.0 (CFPB scam alert pipeline)",
    "Accept": "application/json",
}


def get_supabase_client() -> Client:
    repo_root = Path(__file__).resolve().parent.parent
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY") or os.getenv("SUPABASE_ANON_KEY")
    if not url or not key:
        raise ValueError("Missing SUPABASE_URL and Supabase service/anon key.")
    return create_client(url, key)


def sunday_ending_week_containing(day: date) -> date:
    return day + timedelta(days=(6 - day.weekday()) % 7)


def _parse_date(value: Any) -> date | None:
    if value is None:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).date()
    except ValueError:
        try:
            return date.fromisoformat(str(value)[:10])
        except ValueError:
            return None


def _extract_trend_buckets(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(payload.get("trend_period"), list):
        return [
            {"date": item.get("date") or item.get("key_as_string"), "count": item.get("count") or item.get("doc_count", 0)}
            for item in payload["trend_period"]
        ]

    aggregations = payload.get("aggregations") or {}
    area = aggregations.get("dateRangeArea") or {}
    buckets = (area.get("dateRangeArea") or {}).get("buckets")
    if isinstance(buckets, list):
        return [
            {"date": item.get("date") or item.get("key_as_string"), "count": item.get("count") or item.get("doc_count", 0)}
            for item in buckets
        ]
    return []


def _issue_filter(issue: str, sub_issue: str | None) -> str:
    return f"{issue}\u2022{sub_issue}" if sub_issue else issue


def _get_trends(params: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    for attempt in (1, 2):
        try:
            response = requests.get(TRENDS_ENDPOINT, params=params, headers=_HEADERS, timeout=REQUEST_TIMEOUT_SECONDS)
            if response.status_code == 429 and attempt == 1:
                print("  CFPB rate limited request; waiting 15 seconds before retry.")
                time.sleep(15)
                continue
            response.raise_for_status()
            return response.json(), None
        except requests.exceptions.RequestException as exc:
            if attempt == 1 and not isinstance(exc, requests.exceptions.HTTPError):
                print(f"  CFPB connection error; retrying once: {exc}")
                time.sleep(2)
                continue
            return None, str(exc)
    return None, "request failed"


def _normalise_states(states: list[str] | str | None) -> list[str]:
    if states is None:
        return []
    raw = states.split(",") if isinstance(states, str) else states
    values = [str(item).strip().upper() for item in raw if str(item).strip()]
    if any(item == "ALL" for item in values):
        return ALL_STATES.copy()
    return [item for item in values if item != "NATIONAL"]


def _category_priority(scam_type: str) -> str:
    for category in CFPB_SCAM_CATEGORIES:
        if category["scam_type"] == scam_type:
            return str(category["priority"])
    return "LOW"


def _upsert_cfpb_trends(client: Client, rows: list[dict[str, Any]]) -> int:
    upserted = 0
    for start in range(0, len(rows), UPSERT_BATCH_SIZE):
        batch = rows[start : start + UPSERT_BATCH_SIZE]
        try:
            client.table("cfpb_trends").upsert(
                batch,
                on_conflict="week_ending,product,issue,scam_type,state",
            ).execute()
        except APIError as exc:
            raise RuntimeError(
                "cfpb_trends upsert failed. Apply the CFPB scam pipeline migration before running fetch_trends.py."
            ) from exc
        upserted += len(batch)
    return upserted


def fetch_cfpb_trends(
    lookback_weeks: int = 52,
    states: list[str] | str | None = None,
    upsert: bool = True,
) -> dict[str, Any]:
    today = date.today()
    date_min = (today - timedelta(weeks=lookback_weeks)).isoformat()
    date_max = today.isoformat()
    state_codes = _normalise_states(states)
    locations: list[tuple[str, str | None]] = [("NATIONAL", None)] + [(state, state) for state in state_codes]

    all_rows: list[dict[str, Any]] = []
    insufficient: list[str] = []
    call_count = 0
    errors: list[str] = []
    category_week_counts: dict[str, int] = {}

    for category in CFPB_SCAM_CATEGORIES:
        scam_type = str(category["scam_type"])
        sub_issues = category.get("sub_issues") or [None]
        category_counts: dict[tuple[str, str], int] = defaultdict(int)

        for state_label, state_filter in locations:
            for sub_issue in sub_issues:
                params: dict[str, Any] = {
                    "product": category["product"],
                    "issue": _issue_filter(str(category["issue"]), sub_issue),
                    "sub_issue": sub_issue,
                    "trend_by": "week",
                    "trend_interval": "week",
                    "lens": "overview",
                    "date_received_min": date_min,
                    "date_received_max": date_max,
                    "no_aggs": "false",
                    "format": "json",
                }
                if state_filter:
                    params["state"] = state_filter

                payload, error = _get_trends({k: v for k, v in params.items() if v is not None})
                call_count += 1
                if error:
                    message = f"{scam_type} / {state_label} / {sub_issue or 'all sub-issues'}: {error}"
                    errors.append(message)
                    print(f"  ERROR {message}")
                    time.sleep(REQUEST_DELAY_SECONDS)
                    continue

                buckets = _extract_trend_buckets(payload or {})
                if not buckets:
                    message = f"{scam_type} / {state_label} missing trend_period/dateRangeArea buckets"
                    errors.append(message)
                    print(f"  WARNING {message}")
                    time.sleep(REQUEST_DELAY_SECONDS)
                    continue

                for bucket in buckets:
                    bucket_date = _parse_date(bucket.get("date"))
                    if bucket_date is None:
                        continue
                    week_ending = sunday_ending_week_containing(bucket_date).isoformat()
                    category_counts[(week_ending, state_label)] += int(bucket.get("count") or 0)

                time.sleep(REQUEST_DELAY_SECONDS)

        category_rows = [
            {
                "week_ending": week_ending,
                "product": category["product"],
                "issue": category["issue"],
                "scam_type": scam_type,
                "priority": category["priority"],
                "state": state_label,
                "report_count": count,
            }
            for (week_ending, state_label), count in sorted(category_counts.items())
        ]
        all_rows.extend(category_rows)

        national_rows = [row for row in category_rows if row["state"] == "NATIONAL"]
        category_week_counts[scam_type] = len(national_rows)
        if len(national_rows) < 16:
            insufficient.append(scam_type)

        if national_rows:
            dates = [row["week_ending"] for row in national_rows]
            counts = [int(row["report_count"]) for row in national_rows]
            print(
                f"{scam_type}: weeks={len(national_rows)} date_range={min(dates)} to {max(dates)} "
                f"min_count={min(counts)} max_count={max(counts)} sufficient={len(national_rows) >= 16}"
            )
        else:
            print(f"{scam_type}: weeks=0 date_range=N/A sufficient=False")

    upserted = 0
    if upsert and all_rows:
        client = get_supabase_client()
        upserted = _upsert_cfpb_trends(client, all_rows)

    date_values = [row["week_ending"] for row in all_rows]
    summary = {
        "total_api_calls": call_count,
        "total_weekly_data_points": len(all_rows),
        "rows_upserted": upserted,
        "date_range": f"{min(date_values)} to {max(date_values)}" if date_values else None,
        "distinct_weeks_per_category": category_week_counts,
        "insufficient_categories": insufficient,
        "errors": errors,
    }

    print("\nCFPB trends fetch summary")
    print(f"- Total API calls made: {call_count}")
    print(f"- Total weekly data points collected: {len(all_rows)}")
    print(f"- Rows upserted: {upserted}")
    print(f"- Date range covered: {summary['date_range']}")
    print("- Distinct weeks per category:")
    for scam_type, weeks in category_week_counts.items():
        print(f"  - {scam_type}: {weeks}")
    print("- Categories with insufficient data (<16 weeks):")
    print("  - " + (", ".join(insufficient) if insufficient else "None"))
    return summary


def _states_arg_default() -> str:
    return os.getenv("CFPB_TRENDS_STATES", "NATIONAL")


def main() -> dict[str, Any]:
    parser = argparse.ArgumentParser(description="Fetch CFPB scam category trends and upsert to Supabase.")
    parser.add_argument("--lookback-weeks", type=int, default=int(os.getenv("CFPB_TRENDS_LOOKBACK_WEEKS", "52")))
    parser.add_argument(
        "--states",
        default=_states_arg_default(),
        help="Comma-separated state codes, ALL for every state, or NATIONAL for national-only.",
    )
    parser.add_argument("--no-upsert", action="store_true")
    args = parser.parse_args()
    return fetch_cfpb_trends(
        lookback_weeks=args.lookback_weeks,
        states=args.states,
        upsert=not args.no_upsert,
    )


if __name__ == "__main__":
    main()
