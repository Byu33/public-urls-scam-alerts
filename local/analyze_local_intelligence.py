from __future__ import annotations

import json
import math
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from local.scam_filters import keyword_counter, matching_keywords, normalize_text, parse_date  # noqa: E402
from local.supabase_client import fetch_all, get_supabase_client  # noqa: E402


AGENTS_DIR = REPO_ROOT / "agents"
SUMMARY_PATH = AGENTS_DIR / "local_intelligence_summary.json"
CITIES = {
    "Chicago": {"states": ["IL", "Illinois"], "state_name": "Illinois"},
    "New York": {"states": ["NY", "New York"], "state_name": "New York"},
    "Los Angeles": {"states": ["CA", "California"], "state_name": "California"},
}

SIGNAL_PATTERNS = [
    {
        "scam_type": "Online Purchase",
        "bbb": ["online purchase"],
        "cfpb": ["unauthorized card charges", "credit card"],
        "local": ["bunco", "confidence game", "online purchase", "General Confidence Scam"],
    },
    {
        "scam_type": "Government Impersonation",
        "bbb": ["government agency", "government impersonation"],
        "cfpb": ["government impersonation"],
        "local": ["telephone threat", "wire fraud", "Government Impersonation"],
    },
    {
        "scam_type": "Identity Theft",
        "bbb": ["identity theft"],
        "cfpb": ["credit card identity theft", "identity theft"],
        "local": ["identity theft", "Identity Theft"],
    },
    {
        "scam_type": "Employment",
        "bbb": ["employment"],
        "cfpb": ["predatory service"],
        "local": ["confidence game", "Employment Scam", "General Confidence Scam"],
    },
    {
        "scam_type": "Romance",
        "bbb": ["romance"],
        "cfpb": ["payment transfer fraud"],
        "local": ["wire fraud", "Romance Scam", "Payment Fraud"],
    },
    {
        "scam_type": "Investment",
        "bbb": ["investment"],
        "cfpb": ["payment transfer fraud"],
        "local": ["wire fraud", "extortion", "Investment Fraud", "Payment Fraud"],
    },
]


def _dt(value: Any) -> datetime | None:
    return parse_date(value)


def _date(value: Any) -> date | None:
    parsed = _dt(value)
    return parsed.date() if parsed else None


def _week_start(day: date) -> date:
    return day - timedelta(days=day.weekday())


def _recent(rows: list[dict[str, Any]], field: str, days: int) -> list[dict[str, Any]]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    kept = []
    for row in rows:
        parsed = _dt(row.get(field))
        if parsed and parsed >= cutoff:
            kept.append(row)
    return kept


def _city_rows(rows: list[dict[str, Any]], city: str) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("city") == city]


def _stddev(values: list[float]) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((value - mean) ** 2 for value in values) / len(values))


def _crime_stats(rows_84d: list[dict[str, Any]]) -> dict[str, Any]:
    today = date.today()
    current_week = _week_start(today)
    week_buckets = [current_week - timedelta(weeks=offset) for offset in range(11, -1, -1)]
    counts_by_week = {week: 0 for week in week_buckets}
    category_week_counts: dict[str, Counter[date]] = defaultdict(Counter)

    for row in rows_84d:
        report_day = _date(row.get("report_date"))
        if not report_day:
            continue
        week = _week_start(report_day)
        if week in counts_by_week:
            counts_by_week[week] += 1
            category_week_counts[normalize_text(row.get("scam_category"))][week] += 1

    week_counts = [counts_by_week[week] for week in week_buckets]
    average = sum(week_counts) / len(week_counts) if week_counts else 0.0
    stddev = _stddev([float(value) for value in week_counts])
    current = counts_by_week[current_week]
    if stddev > 0:
        deviation = (current - average) / stddev
    elif average == 0 and current > 0:
        deviation = 2.0
    else:
        deviation = 0.0

    drivers = []
    for category, counter in category_week_counts.items():
        current_count = counter[current_week]
        prior_counts = [counter[week] for week in week_buckets if week != current_week]
        prior_avg = sum(prior_counts) / len(prior_counts) if prior_counts else 0.0
        if current_count > prior_avg and current_count > 0:
            drivers.append(category)

    return {
        "crime_12wk_average": round(average, 2),
        "crime_deviation": round(deviation, 2),
        "crime_spike": deviation > 1.5,
        "spike_driven_by": sorted(drivers),
    }


def _latest_bbb_alerts(client: Any) -> list[dict[str, Any]]:
    alerts = fetch_all(client, "anomaly_alerts")
    if not alerts:
        return []
    run_ids = [row.get("run_id") for row in alerts if row.get("run_id") is not None]
    if not run_ids:
        return alerts
    latest = max(int(run_id) for run_id in run_ids)
    return [row for row in alerts if row.get("run_id") == latest]


def _latest_cfpb_alerts(client: Any) -> list[dict[str, Any]]:
    alerts = fetch_all(client, "cfpb_anomaly_alerts")
    if not alerts:
        return []
    timestamps = sorted({row.get("run_timestamp") for row in alerts if row.get("run_timestamp")})
    if not timestamps:
        return alerts
    latest = timestamps[-1]
    return [row for row in alerts if row.get("run_timestamp") == latest]


def _state_filter(rows: list[dict[str, Any]], states: list[str]) -> list[dict[str, Any]]:
    state_lowers = {state.lower() for state in states}
    return [row for row in rows if normalize_text(row.get("state")).lower() in state_lowers]


def _bbb_payload(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "scam_type": row.get("scam_type"),
            "alert_tier": row.get("alert_tier"),
            "short_deviation": row.get("short_deviation"),
            "scope": row.get("scope"),
            "detection_level": row.get("detection_level"),
        }
        for row in rows
    ]


def _cfpb_scam_type(row: dict[str, Any]) -> str:
    issue = normalize_text(row.get("issue"))
    product = normalize_text(row.get("product"))
    return issue or product or "CFPB Alert"


def _cfpb_payload(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "scam_type": _cfpb_scam_type(row),
            "alert_tier": row.get("alert_tier"),
            "short_deviation": row.get("short_deviation"),
            "priority": row.get("priority") or row.get("detection_level"),
        }
        for row in rows
    ]


def _matches_any(values: list[str], terms: list[str]) -> bool:
    haystack = " | ".join(values).lower()
    return any(term.lower() in haystack for term in terms)


def _cross_source_matches(
    bbb_alerts: list[dict[str, Any]],
    cfpb_alerts: list[dict[str, Any]],
    crime_rows: list[dict[str, Any]],
    news_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    bbb_values = [normalize_text(row.get("scam_type")) for row in bbb_alerts]
    cfpb_values = [_cfpb_scam_type(row) for row in cfpb_alerts]
    local_values = [
        normalize_text(row.get("scam_category")) + " " + normalize_text(row.get("offense_type"))
        for row in crime_rows
    ]
    news_values = [normalize_text(row.get("scam_category")) for row in news_rows]

    matches = []
    for pattern in SIGNAL_PATTERNS:
        has_bbb = _matches_any(bbb_values, pattern["bbb"])
        has_cfpb = _matches_any(cfpb_values, pattern["cfpb"])
        crime_matches = [row for row in crime_rows if _matches_any([row.get("scam_category"), row.get("offense_type")], pattern["local"])]
        news_matches = [row for row in news_rows if _matches_any([row.get("scam_category")], pattern["local"])]
        has_local = bool(crime_matches or news_matches or _matches_any(local_values + news_values, pattern["local"]))
        source_count = sum([has_bbb, has_cfpb, has_local])
        if source_count < 2:
            continue

        bbb_tiers = [row.get("alert_tier") for row in bbb_alerts if _matches_any([row.get("scam_type")], pattern["bbb"])]
        cfpb_tiers = [row.get("alert_tier") for row in cfpb_alerts if _matches_any([_cfpb_scam_type(row)], pattern["cfpb"])]
        confidence = "HIGH" if source_count >= 3 else "MEDIUM"
        matches.append(
            {
                "scam_type": pattern["scam_type"],
                "sources": {
                    "bbb": has_bbb,
                    "cfpb": has_cfpb,
                    "local": has_local,
                },
                "source_count": source_count,
                "bbb_tier": bbb_tiers[0] if bbb_tiers else None,
                "cfpb_tier": cfpb_tiers[0] if cfpb_tiers else None,
                "local_crime_count": len(crime_matches),
                "local_news_count": len(news_matches),
                "confidence_level": confidence,
                "description": f"{pattern['scam_type']} appears in {source_count} scam-intelligence source groups.",
            }
        )
    return matches


def _risk(
    bbb_alerts: list[dict[str, Any]],
    cfpb_alerts: list[dict[str, Any]],
    crime_spike: bool,
    crime_deviation: float,
    news_warnings: int,
    news_arrests: int,
    matches: list[dict[str, Any]],
) -> tuple[str, str]:
    bbb_critical = any(row.get("alert_tier") == "CRITICAL" for row in bbb_alerts)
    cfpb_critical = any(row.get("alert_tier") == "CRITICAL" for row in cfpb_alerts)
    bbb_alert = any(row.get("alert_tier") in {"ALERT", "CRITICAL"} for row in bbb_alerts)
    three_source = any(match.get("source_count", 0) >= 3 for match in matches)
    two_source = any(match.get("source_count", 0) >= 2 for match in matches)

    if bbb_critical and crime_spike and news_warnings > 0:
        return "HIGH", "BBB CRITICAL alert aligns with a local crime spike and local warning coverage."
    if three_source:
        return "HIGH", "The same scam type appears across BBB, CFPB, and local intelligence."
    if bbb_critical and cfpb_critical:
        return "HIGH", "BBB and CFPB both show CRITICAL scam alerts in the same state."
    if crime_deviation > 2.0 and news_warnings > 0:
        return "HIGH", "Local scam crime is more than 2.0 standard deviations above baseline with warning coverage."

    if bbb_alert and (crime_spike or news_warnings > 0):
        return "MEDIUM", "BBB alert activity aligns with either local crime elevation or warning coverage."
    if two_source:
        return "MEDIUM", "Two scam-intelligence source groups show the same or related scam type."
    if 1.5 <= crime_deviation <= 2.0 and news_warnings == 0:
        return "MEDIUM", "Local scam crime is elevated above baseline without matching news coverage."
    if news_arrests > 2:
        return "MEDIUM", "Local scam-related arrests exceed two recent news mentions."

    return "LOW", "Only isolated scam signals are present with no cross-source match or crime spike."


def analyze() -> dict[str, Any]:
    client = get_supabase_client()
    crime_rows = fetch_all(client, "local_crime_reports")
    news_rows = fetch_all(client, "local_news_mentions")
    bbb_alert_rows = _latest_bbb_alerts(client)
    cfpb_alert_rows = _latest_cfpb_alerts(client)

    cities: dict[str, Any] = {}
    national_signals: list[dict[str, Any]] = []

    for city, state_info in CITIES.items():
        city_crime = _city_rows(crime_rows, city)
        crime_7d = _recent(city_crime, "report_date", 7)
        crime_84d = _recent(city_crime, "report_date", 84)
        city_news = _recent(_city_rows(news_rows, city), "published_at", 14)
        bbb_city = _state_filter(bbb_alert_rows, state_info["states"])
        cfpb_city = _state_filter(cfpb_alert_rows, state_info["states"])

        crime_by_category = Counter(normalize_text(row.get("scam_category")) for row in crime_7d if row.get("scam_category"))
        crime_stats = _crime_stats(crime_84d)
        sentiment_counts = Counter(normalize_text(row.get("sentiment")) for row in city_news)
        news_keyword_counts = keyword_counter([row.get("scam_keywords_found", "") for row in city_news])
        news_categories = sorted({normalize_text(row.get("scam_category")) for row in city_news if row.get("scam_category")})
        crime_text = " | ".join(normalize_text(row.get("offense_type")) for row in crime_7d)
        overlap = sorted(keyword for keyword in news_keyword_counts if keyword.lower() in crime_text.lower())

        matches = _cross_source_matches(bbb_city, cfpb_city, crime_7d, city_news)
        risk_level, risk_reason = _risk(
            bbb_city,
            cfpb_city,
            crime_stats["crime_spike"],
            crime_stats["crime_deviation"],
            int(sentiment_counts.get("warning", 0)),
            int(sentiment_counts.get("arrest", 0)),
            matches,
        )

        matrix = {
            "bbb": [row.get("scam_type") for row in bbb_city],
            "cfpb": [_cfpb_scam_type(row) for row in cfpb_city],
            "local_crime": sorted(crime_by_category.keys()),
            "local_news": news_categories,
        }
        print(f"\nSignal matrix for {city}")
        print(json.dumps(matrix, indent=2))

        cities[city] = {
            "crime_records_7days": len(crime_7d),
            "crime_by_scam_category": dict(crime_by_category),
            "crime_12wk_average": crime_stats["crime_12wk_average"],
            "crime_deviation": crime_stats["crime_deviation"],
            "crime_spike": crime_stats["crime_spike"],
            "spike_driven_by": crime_stats["spike_driven_by"],
            "news_warnings": int(sentiment_counts.get("warning", 0)),
            "news_arrests": int(sentiment_counts.get("arrest", 0)),
            "news_advisories": int(sentiment_counts.get("advisory", 0)),
            "news_reports": int(sentiment_counts.get("report", 0)),
            "top_keywords": [keyword for keyword, _ in news_keyword_counts.most_common(5)],
            "keyword_overlap_crime_news": overlap,
            "bbb_alerts": _bbb_payload(bbb_city),
            "cfpb_alerts": _cfpb_payload(cfpb_city),
            "cross_source_matches": matches,
            "combined_risk": risk_level,
            "risk_reason": risk_reason,
        }

        for match in matches:
            if match["sources"].get("bbb") and match["sources"].get("cfpb") and match["sources"].get("local"):
                national_signals.append({"city": city, **match})

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cities": cities,
        "high_risk_cities": [city for city, data in cities.items() if data["combined_risk"] == "HIGH"],
        "national_cross_source_signals": national_signals,
    }

    AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    SUMMARY_PATH.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    print("\nLOCAL SCAM INTELLIGENCE BRIEF")
    for city, data in cities.items():
        print("=" * 72)
        print(f"{city}: {data['combined_risk']}")
        print(f"Crime spike: {data['crime_spike']} (deviation={data['crime_deviation']})")
        print(f"Top scam categories from crime data: {data['crime_by_scam_category']}")
        print(
            "News coverage: "
            f"warnings={data['news_warnings']} arrests={data['news_arrests']} "
            f"advisories={data['news_advisories']} reports={data['news_reports']}"
        )
        print(f"Cross source matches found: {data['cross_source_matches']}")
        print(f"Risk reason: {data['risk_reason']}")

    print("\nHIGHEST CONFIDENCE NATIONAL CROSS SOURCE SIGNALS")
    if national_signals:
        print(json.dumps(national_signals, indent=2, default=str))
    else:
        print("(none)")

    print(f"\nWrote {SUMMARY_PATH.relative_to(REPO_ROOT)}")
    return summary


def main() -> dict[str, Any]:
    return analyze()


if __name__ == "__main__":
    main()
