from __future__ import annotations

import argparse
import os
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client


CFPB_API_BASE = "https://www.consumerfinance.gov/data-research/consumer-complaints/search/api/v1/"
COMPLAINTS_ENDPOINT = CFPB_API_BASE
NARRATIVE_EXPIRY_DAYS = 7
REQUEST_TIMEOUT_SECONDS = int(os.getenv("CFPB_REQUEST_TIMEOUT_SECONDS", "30"))
REQUEST_DELAY_SECONDS = float(os.getenv("CFPB_REQUEST_DELAY_SECONDS", "0.5"))
UPSERT_BATCH_SIZE = 500
PAGE_SIZE = 1000

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


def determine_sample_size(alert_tier: str, current_count: int) -> int:
    tier = str(alert_tier or "WATCH").upper()
    if tier == "CRITICAL":
        if current_count > 500:
            return 100
        if 200 <= current_count <= 500:
            return 75
        return 50
    if tier == "ALERT":
        if current_count > 200:
            return 50
        return 25
    return 15


def _get_with_retry(params: dict[str, Any]) -> dict[str, Any] | list[dict[str, Any]] | None:
    for attempt in (1, 2):
        try:
            response = requests.get(COMPLAINTS_ENDPOINT, params=params, headers=_HEADERS, timeout=REQUEST_TIMEOUT_SECONDS)
            if response.status_code == 429 and attempt == 1:
                print("  CFPB rate limited complaint request; waiting 15 seconds before retry.")
                time.sleep(15)
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as exc:
            if attempt == 1 and not isinstance(exc, requests.exceptions.HTTPError):
                print(f"  CFPB complaint connection error; retrying once: {exc}")
                time.sleep(2)
                continue
            print(f"  CFPB complaint request failed: {exc}")
            return None
    return None


def _extract_hits(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        hits = data.get("hits")
        if isinstance(hits, dict):
            inner = hits.get("hits")
            return inner if isinstance(inner, list) else []
        if isinstance(hits, list):
            return hits
    return []


def _parse_complaint(hit: dict[str, Any], narrative_expires_at: str) -> dict[str, Any] | None:
    src = hit.get("_source") if isinstance(hit, dict) else None
    if src is None:
        src = hit
    if not isinstance(src, dict):
        return None
    complaint_id = src.get("complaint_id") or hit.get("_id")
    if not complaint_id:
        return None
    narrative = src.get("consumer_complaint_narrative") or src.get("complaint_what_happened") or None
    return {
        "id": str(complaint_id),
        "date_received": str(src.get("date_received"))[:10] if src.get("date_received") else None,
        "product": src.get("product"),
        "sub_product": src.get("sub_product"),
        "issue": src.get("issue"),
        "sub_issue": src.get("sub_issue"),
        "company_name": src.get("company"),
        "state": src.get("state"),
        "zip_code": src.get("zip_code"),
        "narrative": narrative,
        "narrative_expires_at": narrative_expires_at,
        "narrative_purged_at": None,
    }


def _call_complaints_api(anomaly: dict[str, Any], sample_size: int) -> list[dict[str, Any]]:
    today = date.today()
    params: dict[str, Any] = {
        "product": anomaly["product"],
        "issue": anomaly["issue"],
        "date_received_min": (today - timedelta(weeks=12)).isoformat(),
        "date_received_max": today.isoformat(),
        "has_narrative": "true",
        "no_aggs": "true",
        "sort": "created_date_desc",
        "size": sample_size,
        "format": "json",
    }
    state = anomaly.get("state")
    if state and state != "NATIONAL":
        params["state"] = state
    data = _get_with_retry(params)
    return _extract_hits(data)


def _upsert_complaints(client: Client, rows: list[dict[str, Any]]) -> int:
    upserted = 0
    for start in range(0, len(rows), UPSERT_BATCH_SIZE):
        batch = rows[start : start + UPSERT_BATCH_SIZE]
        try:
            client.table("cfpb_complaints").upsert(batch, on_conflict="id").execute()
        except APIError as exc:
            raise RuntimeError("cfpb_complaints upsert failed. Apply CFPB scam pipeline migration first.") from exc
        upserted += len(batch)
    return upserted


def _update_alert_company_fields(
    client: Client,
    anomaly: dict[str, Any],
    top_company: str | None,
    top_sub_issue: str | None,
) -> None:
    try:
        (
            client.table("cfpb_anomaly_alerts")
            .update({"top_company": top_company, "top_sub_issue": top_sub_issue})
            .eq("week_ending", anomaly["week_ending"])
            .eq("scam_type", anomaly["scam_type"])
            .eq("state", anomaly.get("state") or "NATIONAL")
            .eq("detection_level", anomaly["detection_level"])
            .execute()
        )
    except APIError as exc:
        print(f"  WARNING unable to update top company/sub-issue on alert: {exc}")


def fetch_complaints_for_anomaly(
    anomaly: dict[str, Any],
    client: Client | None = None,
    print_narratives: int = 0,
) -> dict[str, Any]:
    if client is None:
        client = get_supabase_client()
    sample_size = determine_sample_size(str(anomaly.get("alert_tier")), int(anomaly.get("current_count") or 0))
    narrative_expires_at = (datetime.now(timezone.utc) + timedelta(days=NARRATIVE_EXPIRY_DAYS)).isoformat()

    hits = _call_complaints_api(anomaly, sample_size)
    parsed = [row for hit in hits if (row := _parse_complaint(hit, narrative_expires_at))]
    _upsert_complaints(client, parsed)

    company_counts = Counter(row.get("company_name") for row in parsed if row.get("company_name"))
    sub_issue_counts = Counter(row.get("sub_issue") for row in parsed if row.get("sub_issue"))
    top_company = company_counts.most_common(1)[0][0] if company_counts else None
    top_sub_issue = sub_issue_counts.most_common(1)[0][0] if sub_issue_counts else None
    _update_alert_company_fields(client, anomaly, top_company, top_sub_issue)

    first_narrative = next((str(row.get("narrative", "")) for row in parsed if row.get("narrative")), "")
    preview = first_narrative[:100].replace("\n", " ") if first_narrative else ""
    print(
        f"{anomaly.get('scam_type')} | state={anomaly.get('state') or 'NATIONAL'} | "
        f"tier={anomaly.get('alert_tier')} | complaints_fetched={len(parsed)} | "
        f"top_company={top_company or 'N/A'} | top_sub_issue={top_sub_issue or 'N/A'} | "
        f"preview={preview}"
    )

    if print_narratives:
        for idx, row in enumerate([r for r in parsed if r.get("narrative")][:print_narratives], start=1):
            text = str(row["narrative"])[:200].replace("\n", " ")
            print(f"  narrative_{idx}: company={row.get('company_name') or 'N/A'} text={text}")

    time.sleep(REQUEST_DELAY_SECONDS)
    return {
        "complaints_fetched": len(parsed),
        "top_company": top_company,
        "top_sub_issue": top_sub_issue,
        "sample_size_requested": sample_size,
        "narratives": [row.get("narrative") for row in parsed if row.get("narrative")],
    }


def pull_top_anomalies(client: Client, limit: int = 3) -> list[dict[str, Any]]:
    response = (
        client.table("cfpb_anomaly_alerts")
        .select("week_ending,product,issue,scam_type,state,alert_tier,current_count,short_deviation,detection_level")
        .order("short_deviation", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data or []


def main() -> list[dict[str, Any]]:
    parser = argparse.ArgumentParser(description="Fetch CFPB complaint narratives for top anomaly alerts.")
    parser.add_argument("--limit", type=int, default=3)
    parser.add_argument("--narratives", type=int, default=3)
    args = parser.parse_args()
    client = get_supabase_client()
    anomalies = pull_top_anomalies(client, limit=args.limit)
    results: list[dict[str, Any]] = []
    if not anomalies:
        print("No CFPB anomalies found for complaint sampling.")
        return results
    for anomaly in anomalies:
        results.append(fetch_complaints_for_anomaly(anomaly, client=client, print_narratives=args.narratives))
    return results


if __name__ == "__main__":
    main()
