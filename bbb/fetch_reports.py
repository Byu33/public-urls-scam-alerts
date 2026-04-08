from __future__ import annotations

import json
import os
import random
import re
import time
import traceback
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from supabase import Client, create_client

BASE_URL = "https://www.bbb.org/scamtracker/lookupscam"
PAGE_SIZE = 50
REQUEST_TIMEOUT_SECONDS = 30
REQUEST_RETRY_LIMIT = 3
REQUEST_RETRY_WAIT_SECONDS = 15
PAGE_DELAY_SECONDS = 1


def _debug_enabled() -> bool:
    return os.getenv("BBB_DEBUG", "0") == "1"


def debug_print(message: str) -> None:
    if _debug_enabled():
        print(f"[DEBUG] {message}")


def _load_env() -> None:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()
    debug_print(f"env loaded from repo_root={repo_root}")


def _get_supabase_client() -> Client:
    _load_env()
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


def _extract_scam_result_payload(html: str) -> dict[str, Any]:
    soup = BeautifulSoup(html, "html.parser")

    for script in soup.find_all("script"):
        script_text = script.get_text() or ""
        if "self.__next_f.push" not in script_text or "scamResult" not in script_text:
            continue

        for match in re.finditer(r'self\.__next_f\.push\(\[\d+,"(.*?)"\]\);?', script_text, re.S):
            try:
                decoded_payload = json.loads(f'"{match.group(1)}"')
            except json.JSONDecodeError:
                continue

            start = decoded_payload.find('{"scamResult"')
            if start == -1:
                continue

            depth = 0
            end = -1
            for idx, ch in enumerate(decoded_payload[start:]):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = start + idx + 1
                        break

            if end == -1:
                continue

            try:
                return json.loads(decoded_payload[start:end])
            except json.JSONDecodeError:
                continue

    raise RuntimeError("Could not find BBB scam result payload in page HTML.")


def _request_with_retry(
    session: requests.Session,
    url: str,
    params: dict[str, Any] | None,
    request_kind: str,
    request_id: str,
    failures: list[str],
) -> requests.Response | None:
    for attempt in range(1, REQUEST_RETRY_LIMIT + 1):
        debug_print(
            f"request kind={request_kind} id={request_id} attempt={attempt} "
            f"url={url} params={params}"
        )
        try:
            response = session.get(url, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            msg = (
                f"{request_kind} failed id={request_id} attempt={attempt} "
                f"error={exc.__class__.__name__}: {exc}"
            )
            debug_print(msg)
            if attempt < REQUEST_RETRY_LIMIT:
                time.sleep(REQUEST_RETRY_WAIT_SECONDS)
                continue
            failures.append(msg)
            return None

        if response.status_code == 200:
            debug_print(
                f"request success kind={request_kind} id={request_id} "
                f"attempt={attempt} status={response.status_code}"
            )
            return response

        debug_print(
            f"request non-200 kind={request_kind} id={request_id} "
            f"attempt={attempt} status={response.status_code}"
        )
        if attempt < REQUEST_RETRY_LIMIT:
            time.sleep(REQUEST_RETRY_WAIT_SECONDS)
            continue

        failures.append(
            f"{request_kind} failed id={request_id} status={response.status_code} after retries"
        )
    return None


def _extract_payload_report(source: dict[str, Any]) -> dict[str, Any] | None:
    """Extract report from JSON payload (no detail page fetch needed)."""
    report_id = source.get("scam_id")
    if not report_id:
        return None

    return {
        "id": report_id,
        "reported_date": source.get("createdOn"),
        "scam_type": source.get("scam_type"),
        "scam_subtype": source.get("scam_name"),
        "state": source.get("target_state"),
        "zip": source.get("target_zip"),
        "dollar_amount": source.get("dollar_value"),
        "contact_method": source.get("definition"),
        "business_name": source.get("scammer_business_name"),
        "narrative": source.get("description"),  # ✅ Narrative from payload (no detail fetch!)
    }


def scrape_current_week_reports() -> dict[str, Any]:
    end_date = date.today()
    start_date = end_date - timedelta(days=7)
    narrative_expires_at = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; BBBScamScraper/2.0)"})

    offset = 0
    total_pages_fetched = 0
    all_records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    failures: list[str] = []

    while True:
        query = f"createdOn={start_date.isoformat()}TO{end_date.isoformat()}&from={offset}"
        print(f"Fetching page offset={offset} range={start_date.isoformat()}..{end_date.isoformat()}")
        debug_print(f"search page start offset={offset} query={query}")
        response = _request_with_retry(
            session=session,
            url=BASE_URL,
            params={"q": query},
            request_kind="search_page",
            request_id=str(offset),
            failures=failures,
        )

        if response is None:
            debug_print(f"search page skipped offset={offset} after retries")
            offset += PAGE_SIZE
            time.sleep(PAGE_DELAY_SECONDS)
            continue

        total_pages_fetched += 1
        debug_print(f"search page fetched offset={offset} total_pages_fetched={total_pages_fetched}")

        try:
            payload = _extract_scam_result_payload(response.text)
        except Exception as exc:
            failures.append(f"search_page parse failed offset={offset}: {exc}")
            debug_print(f"search page parse failed offset={offset} error={exc}")
            offset += PAGE_SIZE
            time.sleep(PAGE_DELAY_SECONDS)
            continue

        # Extract hits directly from payload (eliminates 50+ detail page fetches!)
        scam_result = payload.get("scamResult", {})
        hits = scam_result.get("hits", [])
        debug_print(f"search page parsed offset={offset} hits_found={len(hits)}")
        
        if not hits:
            debug_print(f"pagination stop: no hits at offset={offset}")
            break

        for hit in hits:
            source = hit.get("_source", {})
            if not source:
                continue

            report_id = source.get("scam_id")
            if not report_id or report_id in seen_ids:
                debug_print(f"record skip duplicate report_id={report_id}")
                continue
            
            seen_ids.add(report_id)
            record = _extract_payload_report(source)
            if record is None:
                continue

            record["narrative_expires_at"] = narrative_expires_at
            record["narrative_purged_at"] = None
            all_records.append(record)
            if len(all_records) % 10 == 0:
                print(f"Parsed {len(all_records)} records so far...")
            debug_print(
                f"record parsed report_id={report_id} total_records={len(all_records)} "
                f"state={record.get('state')} scam_type={record.get('scam_type')}"
            )

        if len(hits) < PAGE_SIZE:
            debug_print(
                f"pagination stop: page size {len(hits)} < configured PAGE_SIZE {PAGE_SIZE}"
            )
            break

        offset += PAGE_SIZE
        time.sleep(PAGE_DELAY_SECONDS)

    return {
        "records": all_records,
        "total_pages_fetched": total_pages_fetched,
        "failures": failures,
    }


def upsert_reports(records: list[dict[str, Any]]) -> int:
    if not records:
        debug_print("upsert skipped: no records")
        return 0

    debug_print(f"upsert starting for {len(records)} records")
    client = _get_supabase_client()
    client.table("bbb_scam_reports").upsert(
        records,
        on_conflict="id",
        ignore_duplicates=True,
    ).execute()
    debug_print(f"upsert completed for {len(records)} records")
    return len(records)


def _print_random_sample(records: list[dict[str, Any]], sample_size: int = 3) -> None:
    if not records:
        print("No sample records available.")
        return

    sample = random.sample(records, k=min(sample_size, len(records)))
    print("Sample records (narrative truncated to 150 chars):")
    for idx, row in enumerate(sample, start=1):
        narrative = row.get("narrative") or ""
        preview = narrative[:150]
        display = dict(row)
        display["narrative"] = preview
        print(f"  [{idx}] {display}")


def run_fetch_pipeline() -> dict[str, Any]:
    started_at = time.time()
    _load_env()
    print("Starting BBB fetch pipeline...")
    debug_print("run_fetch_pipeline started")
    result = {
        "total_pages_fetched": 0,
        "total_records_parsed": 0,
        "total_records_upserted": 0,
        "records": [],
        "failures": [],
        "elapsed_seconds": 0.0,
    }

    try:
        scrape_result = scrape_current_week_reports()
        records = scrape_result["records"]
        upserted = upsert_reports(records)

        result["total_pages_fetched"] = int(scrape_result["total_pages_fetched"])
        result["total_records_parsed"] = len(records)
        result["total_records_upserted"] = upserted
        result["records"] = records
        result["failures"] = list(scrape_result["failures"])

        print(f"total pages fetched: {result['total_pages_fetched']}")
        print(f"total records parsed: {result['total_records_parsed']}")
        print(f"total records upserted: {result['total_records_upserted']}")

        if result["failures"]:
            print("Skipped page/detail failures:")
            for failure in result["failures"]:
                print(f"- {failure}")

        _print_random_sample(records, sample_size=3)

    except Exception as exc:
        print(f"fetch_reports.py error: {exc}")
        raise
    finally:
        elapsed = time.time() - started_at
        result["elapsed_seconds"] = elapsed
        print(f"full run timing: {elapsed:.2f}s")

    return result


if __name__ == "__main__":
    try:
        run_fetch_pipeline()
    except Exception:
        print(traceback.format_exc())
