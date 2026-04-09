from __future__ import annotations

import os
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from supabase import Client, create_client

# ── CFPB API ───────────────────────────────────────────────────────────────────

CFPB_API_BASE = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"

NARRATIVE_EXPIRY_DAYS = 7
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_WAIT_SECONDS = 5
REQUEST_DELAY_SECONDS = 0.5

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
}

UPSERT_BATCH_SIZE = 500


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


# ── Sample size logic ──────────────────────────────────────────────────────────

def determine_sample_size(alert_tier: str, current_count: int) -> int:
    tier = (alert_tier or "").upper().strip()

    if tier == "CRITICAL":
        if current_count > 300:
            return 100
        if 100 <= current_count <= 300:
            return 50
        return 25

    if tier == "ALERT":
        if current_count > 100:
            return 50
        return 25

    return 15  # WATCH


# ── HTTP helper ────────────────────────────────────────────────────────────────

def _get_with_retry(params: dict[str, Any]) -> dict[str, Any] | None:
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


# ── Complaint parsing ──────────────────────────────────────────────────────────

def _parse_complaint(hit: dict[str, Any], narrative_expires_at: str) -> dict[str, Any] | None:
    src = hit.get("_source") or hit
    complaint_id = src.get("complaint_id") or hit.get("_id")
    if not complaint_id:
        return None

    date_received = src.get("date_received")
    if date_received:
        date_received = str(date_received)[:10]  # keep YYYY-MM-DD portion only

    return {
        "id": str(complaint_id),
        "date_received": date_received,
        "product": src.get("product"),
        "sub_product": src.get("sub_product"),
        "issue": src.get("issue"),
        "company_name": src.get("company"),
        "state": src.get("state"),
        "zip_code": src.get("zip_code"),
        "narrative": src.get("complaint_what_happened") or None,
        "narrative_expires_at": narrative_expires_at,
        "narrative_purged_at": None,
    }


# ── API call ───────────────────────────────────────────────────────────────────

def _call_complaints_api(
    product: str,
    issue: str,
    state: str | None,
    sample_size: int,
    date_min: str,
    date_max: str,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {
        "product": product,
        "issue": issue,
        "date_received_min": date_min,
        "date_received_max": date_max,
        "no_aggs": "true",
        "format": "json",
        "size": sample_size,
        "sort": "created_date_desc",
    }

    if state and state != "NATIONAL":
        params["state"] = state

    data = _get_with_retry(params)
    if data is None:
        return []

    # CFPB API returns a flat list of complaint objects.
    # Each object has a _source key containing the complaint fields.
    if isinstance(data, list):
        hits = data
    elif isinstance(data, dict):
        inner = data.get("hits")
        if isinstance(inner, list):
            hits = inner
        elif isinstance(inner, dict):
            hits = inner.get("hits") or []
        else:
            hits = []
    else:
        hits = []

    # Honour the requested sample_size — the API may return more records
    return hits[:sample_size]


# ── Main fetch function ────────────────────────────────────────────────────────

def fetch_complaints_for_anomaly(
    anomaly: dict[str, Any],
    client: Client | None = None,
) -> dict[str, Any]:
    """
    Fetch individual CFPB complaints for a flagged anomaly and upsert to cfpb_complaints.

    Parameters
    ----------
    anomaly : dict with keys product, issue, state, alert_tier, current_count
    client  : optional Supabase client; one is created if not provided

    Returns
    -------
    dict with keys: complaints_fetched, top_company, product, issue, state, alert_tier
    """
    product = anomaly.get("product", "")
    issue = anomaly.get("issue", "")
    state = anomaly.get("state")
    alert_tier = str(anomaly.get("alert_tier", "WATCH"))
    current_count = int(anomaly.get("current_count", 0) or 0)

    sample_size = determine_sample_size(alert_tier, current_count)

    today = date.today()
    date_min = (today - timedelta(weeks=8)).isoformat()
    date_max = today.isoformat()

    now_utc = datetime.now(timezone.utc)
    narrative_expires_at = (now_utc + timedelta(days=NARRATIVE_EXPIRY_DAYS)).isoformat()

    hits = _call_complaints_api(
        product=product,
        issue=issue,
        state=state,
        sample_size=sample_size,
        date_min=date_min,
        date_max=date_max,
    )

    parsed: list[dict[str, Any]] = []
    for hit in hits:
        record = _parse_complaint(hit, narrative_expires_at)
        if record:
            parsed.append(record)

    # Identify top company by frequency
    companies = [r["company_name"] for r in parsed if r.get("company_name")]
    top_company: str | None = None
    if companies:
        top_company = Counter(companies).most_common(1)[0][0]

    # Upsert to cfpb_complaints
    if parsed:
        if client is None:
            client = get_supabase_client()

        for start in range(0, len(parsed), UPSERT_BATCH_SIZE):
            batch = parsed[start : start + UPSERT_BATCH_SIZE]
            client.table("cfpb_complaints").upsert(batch, on_conflict="id").execute()

    state_label = state or "NATIONAL"
    print(
        f"  fetch_complaints: {product[:30]} / {issue[:30]} / {state_label}  "
        f"tier={alert_tier}  fetched={len(parsed)}  top_company={top_company}"
    )

    time.sleep(REQUEST_DELAY_SECONDS)

    return {
        "complaints_fetched": len(parsed),
        "top_company": top_company,
        "product": product,
        "issue": issue,
        "state": state,
        "alert_tier": alert_tier,
    }


if __name__ == "__main__":
    # Standalone test with a sample anomaly
    test_anomaly = {
        "product": "Money transfer, virtual currency, or money service",
        "issue": "Fraud or scam",
        "state": "CA",
        "alert_tier": "ALERT",
        "current_count": 150,
    }
    result = fetch_complaints_for_anomaly(test_anomaly)
    print(result)
