from __future__ import annotations

import gc
import json
import os
import re
import time
import traceback
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from postgrest.exceptions import APIError
from supabase import Client, create_client

BASE_URL = "https://www.bbb.org/scamtracker/lookupscam"
PAGE_SIZE = 50
REQUEST_TIMEOUT_SECONDS = 30
REQUEST_RETRY_LIMIT = 3
REQUEST_RETRY_WAIT_SECONDS = 30
PAGE_DELAY_SECONDS = float(os.getenv("BBB_PAGE_DELAY_SECONDS", "1"))
WEEK_DELAY_SECONDS = float(os.getenv("BBB_WEEK_DELAY_SECONDS", "5"))
UPSERT_BATCH_SIZE = 500
ERROR_LOG_FILE = "historical_errors.log"
TOTAL_WEEKS = 52
DEBUG = os.getenv("BBB_DEBUG", "0") == "1"


def debug_print(message: str) -> None:
    if DEBUG:
        print(f"[DEBUG] {message}")


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


def _extract_record(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "reported_date": source.get("createdOn"),
        "scam_type": source.get("scam_type"),
        "scam_subtype": source.get("scam_name"),
        "state": source.get("target_state"),
        "zip": source.get("target_zip"),
        "dollar_amount": source.get("dollar_value"),
        "contact_method": source.get("definition"),
        "business_name": source.get("scammer_business_name"),
        "narrative": None,
        "narrative_expires_at": None,
    }


def _request_page_with_retry(
    session: requests.Session, week_start: date, week_end: date, offset: int
) -> requests.Response | None:
    query = f"createdOn={week_start.isoformat()}TO{week_end.isoformat()}&from={offset}"

    for attempt in range(1, REQUEST_RETRY_LIMIT + 1):
        response = session.get(
            BASE_URL,
            params={"q": query},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        debug_print(
            f"request week={week_start}..{week_end} offset={offset} attempt={attempt} status={response.status_code}"
        )
        if response.status_code == 200:
            return response

        if attempt < REQUEST_RETRY_LIMIT:
            time.sleep(REQUEST_RETRY_WAIT_SECONDS)

    debug_print(f"page skipped after retries week={week_start}..{week_end} offset={offset}")
    return None


def scrape_week(session: requests.Session, week_start: date, week_end: date, page_size: int = PAGE_SIZE) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    offset = 0
    successful_pages = 0
    total_expected: int | None = None
    consecutive_skipped_pages = 0
    consecutive_parse_failures = 0

    while True:
        response = _request_page_with_retry(session, week_start, week_end, offset)
        if response is None:
            consecutive_skipped_pages += 1
            offset += page_size
            time.sleep(PAGE_DELAY_SECONDS)
            if successful_pages == 0 and consecutive_skipped_pages >= 1:
                raise RuntimeError(
                    f"All retries failed for the week starting page at offset {offset - page_size}"
                )
            # Skip failed page and continue scraping this week.
            continue

        consecutive_skipped_pages = 0
        successful_pages += 1
        try:
            payload = _extract_scam_result_payload(response.text)
        except Exception as exc:
            consecutive_parse_failures += 1
            debug_print(
                f"parse failed week={week_start}..{week_end} offset={offset} error={exc}"
            )
            offset += page_size
            time.sleep(PAGE_DELAY_SECONDS)
            if successful_pages == 0 and consecutive_parse_failures >= 1:
                raise RuntimeError(
                    f"Unable to parse first page payload for week {week_start} to {week_end}: {exc}"
                )
            if consecutive_parse_failures >= 3:
                debug_print(
                    f"stopping pagination after {consecutive_parse_failures} parse failures "
                    f"week={week_start}..{week_end}"
                )
                break
            continue

        consecutive_parse_failures = 0
        scam_result = payload.get("scamResult", {})
        hits = scam_result.get("hits", [])
        debug_print(f"parsed page week={week_start}..{week_end} offset={offset} hits={len(hits)}")

        if total_expected is None:
            total = scam_result.get("total", {})
            if isinstance(total, dict):
                total_value = total.get("value")
                if isinstance(total_value, int):
                    total_expected = total_value

        page_records: list[dict[str, Any]] = []
        for hit in hits:
            source = hit.get("_source", {})
            if source:
                page_records.append(_extract_record(source))

        records.extend(page_records)

        if len(page_records) < page_size:
            break

        offset += page_size
        if total_expected is not None and offset >= total_expected:
            break
        time.sleep(PAGE_DELAY_SECONDS)

    if successful_pages == 0:
        raise RuntimeError("No pages were successfully fetched for this week")

    return records


def _mode_or_none(series: pd.Series) -> Any:
    cleaned = series.dropna()
    if cleaned.empty:
        return None
    mode_values = cleaned.mode(dropna=True)
    if mode_values.empty:
        return None
    return mode_values.iloc[0]


def aggregate_week_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not records:
        return []

    df = pd.DataFrame(records)

    # Step 1: datetime conversion + week ending (Sunday)
    df["reported_date"] = pd.to_datetime(df["reported_date"], errors="coerce")
    df = df.dropna(subset=["reported_date"]).copy()
    if df.empty:
        del df
        gc.collect()
        return []

    df["week_ending"] = df["reported_date"] + pd.to_timedelta((6 - df["reported_date"].dt.weekday) % 7, unit="D")

    # Step 2: fill null dollar amounts
    df["dollar_amount"] = pd.to_numeric(df["dollar_amount"], errors="coerce")
    df["dollar_amount"] = df["dollar_amount"].fillna(0)

    # Step 3: group + aggregate (single agg call)
    grouped = (
        df.groupby(["week_ending", "scam_type", "state"], dropna=False)
        .agg(
            report_count=("reported_date", "size"),
            avg_dollar_amount=("dollar_amount", "mean"),
            dominant_subtype=("scam_subtype", _mode_or_none),
            dominant_contact_method=("contact_method", _mode_or_none),
        )
    )
    grouped["avg_dollar_amount"] = grouped["avg_dollar_amount"].round(2)

    # Step 4: reset index
    grouped = grouped.reset_index()

    # Normalize date field for storage compatibility
    grouped["week_ending"] = pd.to_datetime(grouped["week_ending"], errors="coerce").dt.strftime("%Y-%m-%d")

    # Supabase JSON payloads cannot contain NaN/NaT values.
    grouped = grouped.where(pd.notna(grouped), None)

    # Step 5: to_dict records
    aggregated_rows = grouped.to_dict(orient="records")

    del df
    del grouped
    gc.collect()

    return aggregated_rows


def upsert_trend_rows(client: Client, rows: list[dict[str, Any]], batch_size: int = UPSERT_BATCH_SIZE) -> int:
    if not rows:
        return 0

    total_upserted = 0
    for start_idx in range(0, len(rows), batch_size):
        batch = rows[start_idx : start_idx + batch_size]
        sanitized_batch: list[dict[str, Any]] = []
        for row in batch:
            sanitized_row: dict[str, Any] = {}
            for key, value in row.items():
                if pd.isna(value):
                    sanitized_row[key] = None
                else:
                    sanitized_row[key] = value
            sanitized_batch.append(sanitized_row)

        try:
            client.table("bbb_trends").upsert(
                sanitized_batch,
                on_conflict="week_ending,scam_type,state",
            ).execute()
        except APIError as exc:
            # Backward compatibility for existing schema that lacks dominant_* columns.
            message = str(exc)
            if "dominant_subtype" not in message and "dominant_contact_method" not in message:
                raise
            core_fields = [
                "week_ending",
                "scam_type",
                "state",
                "report_count",
                "avg_dollar_amount",
            ]
            reduced_batch = [{k: row.get(k) for k in core_fields} for row in sanitized_batch]
            client.table("bbb_trends").upsert(
                reduced_batch,
                on_conflict="week_ending,scam_type,state",
            ).execute()
        total_upserted += len(batch)

    return total_upserted


def log_week_error(week_start: date, week_end: date, error: Exception) -> None:
    timestamp = datetime.now().isoformat()
    tb = traceback.format_exc().strip()
    with open(ERROR_LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(
            f"{timestamp} | {week_start.isoformat()} to {week_end.isoformat()} | {error} | traceback={tb}\n"
        )


def get_supabase_client() -> Client:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent

    # Load env files explicitly so running from /bbb still picks up repo-level config.
    load_dotenv(repo_root / ".env.local")
    load_dotenv(repo_root / ".env")
    load_dotenv()

    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = (
        os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        or os.getenv("SUPABASE_KEY")
        or os.getenv("SUPABASE_ANON_KEY")
    )
    if not supabase_url or not supabase_key:
        raise ValueError(
            "Missing Supabase env vars. Expected SUPABASE_URL and one of "
            "SUPABASE_SERVICE_ROLE_KEY, SUPABASE_KEY, or SUPABASE_ANON_KEY."
        )
    return create_client(supabase_url, supabase_key)


def get_week_ranges(today: date | None = None) -> list[tuple[date, date]]:
    if today is None:
        today = date.today()

    # Most recently completed week ends on last Sunday prior to today.
    days_since_last_sunday = today.weekday() + 1
    most_recent_completed_week_end = today - timedelta(days=days_since_last_sunday)

    weeks_to_process = int(os.getenv("BBB_TOTAL_WEEKS", str(TOTAL_WEEKS)))
    first_week_end = most_recent_completed_week_end - timedelta(weeks=weeks_to_process - 1)
    ranges: list[tuple[date, date]] = []
    for idx in range(weeks_to_process):
        week_end = first_week_end + timedelta(weeks=idx)
        week_start = week_end - timedelta(days=6)
        ranges.append((week_start, week_end))
    return ranges


def fetch_all_trends(client: Client, page_size: int = 1000) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    start_idx = 0

    while True:
        end_idx = start_idx + page_size - 1
        try:
            response = (
                client.table("bbb_trends")
                .select(
                    "week_ending,scam_type,state,report_count,avg_dollar_amount,"
                    "dominant_subtype,dominant_contact_method"
                )
                .range(start_idx, end_idx)
                .execute()
            )
        except APIError as exc:
            message = str(exc)
            if "dominant_subtype" not in message and "dominant_contact_method" not in message:
                raise
            response = (
                client.table("bbb_trends")
                .select("week_ending,scam_type,state,report_count,avg_dollar_amount")
                .range(start_idx, end_idx)
                .execute()
            )
        page_rows = response.data or []
        if not page_rows:
            break

        rows.extend(page_rows)
        if len(page_rows) < page_size:
            break

        start_idx += page_size

    return pd.DataFrame(rows)


def run_historical_scrape() -> None:
    client = get_supabase_client()
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; BBBHistoricalScraper/1.0)"})

    week_ranges = get_week_ranges()
    successful_weeks = 0
    errored_weeks = 0

    total_weeks = len(week_ranges)
    for idx, (week_start, week_end) in enumerate(week_ranges, start=1):
        week_started_at = time.time()
        try:
            weekly_records = scrape_week(session, week_start, week_end)
            raw_count = len(weekly_records)
            weekly_trends = aggregate_week_records(weekly_records)
            upserted_count = upsert_trend_rows(client, weekly_trends)

            # Discard week-level structures before next iteration.
            del weekly_records
            del weekly_trends
            gc.collect()

            elapsed = time.time() - week_started_at
            successful_weeks += 1
            print(
                f"Week {idx}/{total_weeks} | {week_start.isoformat()} to {week_end.isoformat()} | "
                f"raw={raw_count} | upserted={upserted_count} | "
                f"elapsed={elapsed:.1f}s"
            )
        except Exception as exc:
            errored_weeks += 1
            log_week_error(week_start, week_end, exc)
            elapsed = time.time() - week_started_at
            print(
                f"Week {idx}/{total_weeks} | {week_start.isoformat()} to {week_end.isoformat()} | "
                f"raw=0 | upserted=0 | elapsed={elapsed:.1f}s | ERROR"
            )

        time.sleep(WEEK_DELAY_SECONDS)

    trends_df = fetch_all_trends(client)

    if trends_df.empty:
        print("Final Summary")
        print(f"- total weeks completed successfully: {successful_weeks}")
        print(f"- total weeks with errors logged: {errored_weeks}")
        print("- total trend rows in bbb_trends: 0")
        print("- full date range covered: N/A")
        print("- top 10 scam types by total report_count:\n  (no rows)")
        return

    trends_df["week_ending"] = pd.to_datetime(trends_df["week_ending"], errors="coerce")
    trends_df["report_count"] = pd.to_numeric(trends_df["report_count"], errors="coerce").fillna(0)

    min_week = trends_df["week_ending"].min()
    max_week = trends_df["week_ending"].max()

    top_scam_types = (
        trends_df.groupby("scam_type", dropna=False)["report_count"]
        .sum()
        .sort_values(ascending=False)
        .head(10)
        .reset_index(name="total_report_count")
    )

    print("Final Summary")
    print(f"- total weeks completed successfully: {successful_weeks}")
    print(f"- total weeks with errors logged: {errored_weeks}")
    print(f"- total trend rows in bbb_trends: {len(trends_df)}")
    print(
        "- full date range covered: "
        f"{min_week.date().isoformat() if pd.notna(min_week) else 'N/A'} to "
        f"{max_week.date().isoformat() if pd.notna(max_week) else 'N/A'}"
    )
    print("- top 10 scam types by total report_count:")
    if top_scam_types.empty:
        print("  (no rows)")
    else:
        print(top_scam_types.to_string(index=False))


if __name__ == "__main__":
    run_historical_scrape()
