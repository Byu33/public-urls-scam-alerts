from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import requests

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from local.scam_filters import (  # noqa: E402
    SCAM_EXCLUSION_KEYWORDS,
    SCAM_OFFENSE_TYPES_CHICAGO,
    exclusion_keywords_found,
    map_to_scam_category,
    normalize_text,
    parse_date,
)
from local.supabase_client import get_supabase_client, upsert_rows  # noqa: E402


API_DELAY_SECONDS = 0.5
LIMIT = 1000


def _socrata_get(url: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    for attempt in range(2):
        try:
            response = requests.get(url, params=params, timeout=20)
            if response.status_code == 429 and attempt == 0:
                print(f"429 from {url}; waiting 15 seconds before retry")
                time.sleep(15)
                continue
            response.raise_for_status()
            return response.json()
        except requests.RequestException as exc:
            print(f"WARNING: Socrata request failed for {url}: {exc}")
            return []
    return []


def _where_or_equals(field: str, values: list[str]) -> str:
    clauses = []
    for value in values:
        escaped = value.replace("'", "''")
        clauses.append(f"{field}='{escaped}'")
    return "(" + " OR ".join(clauses) + ")"


def _report_date(value: Any) -> str | None:
    parsed = parse_date(value)
    return parsed.date().isoformat() if parsed else None


def _num(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _rejects_as_non_scam(*parts: Any) -> bool:
    text = " ".join(normalize_text(part) for part in parts)
    return bool(exclusion_keywords_found(text))


def _dedupe(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    for row in rows:
        key = (row.get("source"), row.get("report_date"), row.get("latitude"), row.get("longitude"))
        deduped[key] = row
    return list(deduped.values())


def _print_city_summary(city: str, total: int, rows: list[dict[str, Any]], skipped: int) -> None:
    category_counts = Counter(row["scam_category"] for row in rows)
    print(f"\n{city} crime API summary")
    print(f"Total records returned from API: {total}")
    print(f"Records after scam filtering: {len(rows)}")
    print(f"Records skipped as non-scam: {skipped}")
    print(f"Breakdown by scam_category: {dict(category_counts)}")
    print("Sample 3 records:")
    for row in rows[:3]:
        print(f"- offense_type={row.get('offense_type')} | scam_category={row.get('scam_category')}")


def fetch_chicago() -> dict[str, Any]:
    since = (date.today() - timedelta(days=7)).isoformat()
    url = "https://data.cityofchicago.org/resource/ijzp-q8t2.json"
    where = f"{_where_or_equals('description', SCAM_OFFENSE_TYPES_CHICAGO)} AND date >= '{since}T00:00:00'"
    data = _socrata_get(url, {"$where": where, "$limit": LIMIT, "$order": "date DESC"})
    rows: list[dict[str, Any]] = []
    skipped = 0
    for record in data:
        description = normalize_text(record.get("description"))
        category = map_to_scam_category(description)
        if not category or _rejects_as_non_scam(description, record.get("location_description")):
            skipped += 1
            continue
        rows.append(
            {
                "source": "Chicago Police Department Socrata",
                "city": "Chicago",
                "report_date": _report_date(record.get("date")),
                "offense_type": description,
                "offense_category": normalize_text(record.get("primary_type")),
                "description": description,
                "location_description": normalize_text(record.get("location_description")),
                "community_area": normalize_text(record.get("community_area")),
                "borough": None,
                "division": None,
                "latitude": _num(record.get("latitude")),
                "longitude": _num(record.get("longitude")),
                "is_scam_confirmed": True,
                "scam_category": category,
            }
        )
    rows = _dedupe(rows)
    _print_city_summary("Chicago", len(data), rows, skipped)
    return {"city": "Chicago", "total": len(data), "rows": rows, "skipped": skipped}


def fetch_new_york() -> dict[str, Any]:
    since = (date.today() - timedelta(days=7)).isoformat()
    url = "https://data.cityofnewyork.us/resource/5uac-w243.json"
    where = (
        "(ofns_desc='FRAUDS' OR ofns_desc='IDENTITY THEFT 1' OR ofns_desc='IDENTITY THEFT 2' "
        "OR ofns_desc='IDENTITY THEFT 3' OR pd_desc LIKE '%CONFIDENCE GAME%' "
        "OR pd_desc LIKE '%LARCENY-TRICK%' OR pd_desc LIKE '%FRAUD%' "
        f"OR pd_desc LIKE '%IMPERSONATION%') AND cmplnt_fr_dt >= '{since}'"
    )
    data = _socrata_get(url, {"$where": where, "$limit": LIMIT, "$order": "cmplnt_fr_dt DESC"})
    rows: list[dict[str, Any]] = []
    skipped = 0
    for record in data:
        pd_desc = normalize_text(record.get("pd_desc"))
        offense = normalize_text(record.get("ofns_desc"))
        category = map_to_scam_category(pd_desc) or map_to_scam_category(offense)
        if not category or _rejects_as_non_scam(pd_desc, offense):
            skipped += 1
            continue
        rows.append(
            {
                "source": "NYPD Socrata",
                "city": "New York",
                "report_date": _report_date(record.get("cmplnt_fr_dt")),
                "offense_type": offense,
                "offense_category": normalize_text(record.get("law_cat_cd")),
                "description": pd_desc,
                "location_description": normalize_text(record.get("prem_typ_desc") or record.get("addr_pct_cd")),
                "community_area": None,
                "borough": normalize_text(record.get("boro_nm")),
                "division": normalize_text(record.get("addr_pct_cd")),
                "latitude": _num(record.get("latitude")),
                "longitude": _num(record.get("longitude")),
                "is_scam_confirmed": True,
                "scam_category": category,
            }
        )
    rows = _dedupe(rows)
    _print_city_summary("New York", len(data), rows, skipped)
    return {"city": "New York", "total": len(data), "rows": rows, "skipped": skipped}


def fetch_los_angeles() -> dict[str, Any]:
    since = (date.today() - timedelta(days=7)).isoformat()
    url = "https://data.lacity.org/resource/2nrs-mtv8.json"
    where = (
        "(crm_cd_desc LIKE '%BUNCO%' OR crm_cd_desc LIKE '%IDENTITY THEFT%' "
        "OR crm_cd_desc LIKE '%CREDIT CARDS, FRAUD%' OR crm_cd_desc LIKE '%DOCUMENT WORTHLESS%' "
        "OR crm_cd_desc LIKE '%COUNTERFEIT%' OR crm_cd_desc LIKE '%EXTORTION%') "
        f"AND date_occ >= '{since}T00:00:00'"
    )
    data = _socrata_get(url, {"$where": where, "$limit": LIMIT, "$order": "date_occ DESC"})
    rows: list[dict[str, Any]] = []
    skipped = 0
    for record in data:
        offense = normalize_text(record.get("crm_cd_desc"))
        category = map_to_scam_category(offense)
        if not category or _rejects_as_non_scam(offense, record.get("location")):
            skipped += 1
            continue
        rows.append(
            {
                "source": "LAPD Socrata",
                "city": "Los Angeles",
                "report_date": _report_date(record.get("date_occ")),
                "offense_type": offense,
                "offense_category": normalize_text(record.get("crm_cd")),
                "description": offense,
                "location_description": normalize_text(record.get("location")),
                "community_area": None,
                "borough": None,
                "division": normalize_text(record.get("area_name")),
                "latitude": _num(record.get("lat")),
                "longitude": _num(record.get("lon")),
                "is_scam_confirmed": True,
                "scam_category": category,
            }
        )
    rows = _dedupe(rows)
    _print_city_summary("Los Angeles", len(data), rows, skipped)
    return {"city": "Los Angeles", "total": len(data), "rows": rows, "skipped": skipped}


def run_fetch() -> dict[str, Any]:
    city_results = []
    all_rows: list[dict[str, Any]] = []
    for fetcher in (fetch_chicago, fetch_new_york, fetch_los_angeles):
        result = fetcher()
        city_results.append({key: value for key, value in result.items() if key != "rows"})
        all_rows.extend(result["rows"])
        time.sleep(API_DELAY_SECONDS)

    client = get_supabase_client()
    upserted = upsert_rows(
        client,
        "local_crime_reports",
        all_rows,
        on_conflict="source,report_date,latitude,longitude",
    )
    summary = {
        "total_api_records": sum(item["total"] for item in city_results),
        "records_after_scam_filtering": len(all_rows),
        "records_skipped_as_non_scam": sum(item["skipped"] for item in city_results),
        "records_upserted": upserted,
        "cities": city_results,
        "category_breakdown": dict(Counter(row["scam_category"] for row in all_rows)),
        "excluded_keywords": SCAM_EXCLUSION_KEYWORDS,
    }
    print("\nCrime API final summary")
    print(json.dumps(summary, indent=2, default=str))
    return summary


def main() -> dict[str, Any]:
    return run_fetch()


if __name__ == "__main__":
    main()
