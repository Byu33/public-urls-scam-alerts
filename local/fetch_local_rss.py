from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import feedparser
from bs4 import BeautifulSoup

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from local.scam_filters import (  # noqa: E402
    NEWS_MINIMUM_ARTICLE_LENGTH,
    NEWS_MINIMUM_KEYWORD_MATCHES,
    determine_sentiment,
    exclusion_keywords_found,
    has_high_confidence_indicator,
    is_within_days,
    keyword_counter,
    map_to_scam_category,
    matching_keywords,
    normalize_text,
    parse_date,
)
from local.supabase_client import get_supabase_client, upsert_rows  # noqa: E402


RSS_FEEDS = {
    "Chicago": [
        {"name": "Chicago Tribune Crime", "url": "https://www.chicagotribune.com/arcio/rss/category/crime/", "city": "Chicago"},
        {"name": "WGN TV", "url": "https://wgntv.com/feed/", "city": "Chicago"},
        {"name": "ABC7 Chicago", "url": "https://abc7chicago.com/feed/", "city": "Chicago"},
        {"name": "NBC5 Chicago", "url": "https://www.nbcchicago.com/feed/", "city": "Chicago"},
    ],
    "New York": [
        {"name": "NY Daily News", "url": "https://www.nydailynews.com/arcio/rss/", "city": "New York"},
        {"name": "NY Post", "url": "https://nypost.com/feed/", "city": "New York"},
        {"name": "WABC New York", "url": "https://abc7ny.com/feed/", "city": "New York"},
        {"name": "NBC New York", "url": "https://www.nbcnewyork.com/feed/", "city": "New York"},
    ],
    "Los Angeles": [
        {"name": "LA Times Crime", "url": "https://www.latimes.com/rss2/crime-courts", "city": "Los Angeles"},
        {"name": "KTLA", "url": "https://ktla.com/feed/", "city": "Los Angeles"},
        {"name": "ABC7 LA", "url": "https://abc7.com/feed/", "city": "Los Angeles"},
        {"name": "NBC LA", "url": "https://www.nbclosangeles.com/feed/", "city": "Los Angeles"},
    ],
}


def _plain_text(value: Any) -> str:
    text = normalize_text(value)
    if "<" in text and ">" in text:
        return normalize_text(BeautifulSoup(text, "html.parser").get_text(" ", strip=True))
    return text


def _entry_date(entry: Any) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, key, None) or entry.get(key)
        if parsed:
            dt = parse_date(parsed)
            if dt:
                return dt
    for key in ("published", "updated"):
        raw = getattr(entry, key, None) or entry.get(key)
        if raw:
            dt = parse_date(raw)
            if dt:
                return dt
    return None


def _entry_summary(entry: Any) -> str:
    return _plain_text(entry.get("summary") or entry.get("description") or "")[:500]


def _row(feed: dict[str, str], entry: Any, keywords: list[str], published_at: datetime) -> dict[str, Any]:
    title = normalize_text(entry.get("title"))
    summary = _entry_summary(entry)
    combined = f"{title} {summary}"
    return {
        "source": feed["name"],
        "city": feed["city"],
        "published_at": published_at.astimezone(timezone.utc).isoformat(),
        "headline": title,
        "summary": summary,
        "url": entry.get("link"),
        "scam_keywords_found": ", ".join(keywords),
        "keyword_match_count": len(keywords),
        "sentiment": determine_sentiment(combined),
        "scam_category": map_to_scam_category(combined),
        "is_scam_specific": True,
    }


def fetch_feed(feed: dict[str, str]) -> dict[str, Any]:
    try:
        parsed = feedparser.parse(feed["url"])
    except Exception as exc:
        print(f"WARNING: parse error for {feed['name']}: {exc}")
        return {"feed": feed["name"], "city": feed["city"], "total": 0, "stored": 0, "rejections": {"parse": 1}, "rows": []}

    if getattr(parsed, "bozo", False):
        print(f"WARNING: feedparser reported a parse issue for {feed['name']}: {getattr(parsed, 'bozo_exception', '')}")

    rows: list[dict[str, Any]] = []
    rejections: Counter[str] = Counter()
    entries = list(parsed.entries or [])

    for entry in entries:
        title = normalize_text(entry.get("title"))
        summary = _entry_summary(entry)
        combined = f"{title} {summary}".strip()

        keywords = matching_keywords(combined)
        if len(keywords) < NEWS_MINIMUM_KEYWORD_MATCHES:
            rejections["quick_keyword"] += 1
            continue

        if len(exclusion_keywords_found(combined)) >= 3:
            rejections["exclusion"] += 1
            continue

        if len(combined) < NEWS_MINIMUM_ARTICLE_LENGTH:
            rejections["length"] += 1
            continue

        if not has_high_confidence_indicator(combined):
            rejections["indicator"] += 1
            continue

        published_at = _entry_date(entry)
        if not is_within_days(published_at, 14):
            rejections["date"] += 1
            continue

        if not entry.get("link"):
            rejections["missing_url"] += 1
            continue

        if map_to_scam_category(combined) is None:
            rejections["category"] += 1
            continue

        rows.append(_row(feed, entry, keywords, published_at))

    category_counts = Counter(row["scam_category"] for row in rows)
    print(f"\n{feed['name']} ({feed['city']})")
    print(f"Total entries in feed: {len(entries)}")
    print(f"Entries passing all 5 filters: {len(rows)}")
    print(f"Entries rejected at each filter step: {dict(rejections)}")
    print(f"Scam categories found: {dict(category_counts)}")
    print("Sample stored headlines:")
    for row in rows[:5]:
        print(f"- {row['headline']}")

    return {
        "feed": feed["name"],
        "city": feed["city"],
        "total": len(entries),
        "stored": len(rows),
        "rejections": dict(rejections),
        "category_breakdown": dict(category_counts),
        "rows": rows,
    }


def run_fetch() -> dict[str, Any]:
    feed_summaries: list[dict[str, Any]] = []
    all_rows: list[dict[str, Any]] = []
    for feeds in RSS_FEEDS.values():
        for feed in feeds:
            result = fetch_feed(feed)
            all_rows.extend(result.pop("rows"))
            feed_summaries.append(result)
            time.sleep(1)

    client = get_supabase_client()
    upserted = upsert_rows(client, "local_news_mentions", all_rows, on_conflict="url")

    by_city: dict[str, dict[str, Any]] = defaultdict(lambda: {"stored": 0, "categories": Counter(), "sentiments": Counter(), "keywords": Counter()})
    for row in all_rows:
        city_summary = by_city[row["city"]]
        city_summary["stored"] += 1
        city_summary["categories"][row["scam_category"]] += 1
        city_summary["sentiments"][row["sentiment"]] += 1
        city_summary["keywords"].update(keyword_counter([row["scam_keywords_found"]]))

    final_by_city = {
        city: {
            "total_articles_stored": values["stored"],
            "breakdown_by_scam_category": dict(values["categories"]),
            "breakdown_by_sentiment": dict(values["sentiments"]),
            "top_5_keywords": values["keywords"].most_common(5),
        }
        for city, values in by_city.items()
    }

    rejection_totals: defaultdict[str, int] = defaultdict(int)
    for item in feed_summaries:
        for reason, count in item.get("rejections", {}).items():
            rejection_totals[reason] += int(count)

    summary = {
        "total_entries": sum(item["total"] for item in feed_summaries),
        "entries_stored": len(all_rows),
        "records_upserted": upserted,
        "rejection_breakdown": dict(rejection_totals),
        "feeds": feed_summaries,
        "cities": final_by_city,
    }
    print("\nRSS final summary per city")
    print(json.dumps(final_by_city, indent=2, default=str))
    print("\nRSS final summary")
    print(json.dumps(summary, indent=2, default=str))
    return summary


def main() -> dict[str, Any]:
    return run_fetch()


if __name__ == "__main__":
    main()
