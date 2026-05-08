from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests
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
    map_to_scam_category,
    matching_keywords,
    normalize_text,
    parse_date,
)
from local.supabase_client import get_supabase_client, upsert_rows  # noqa: E402


USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
REQUEST_DELAY_SECONDS = 2


@dataclass(frozen=True)
class NewsSource:
    name: str
    city: str
    url: str
    minimum_keyword_matches: int = NEWS_MINIMUM_KEYWORD_MATCHES
    required_terms: tuple[str, ...] = ()


SOURCES = [
    NewsSource("Chicago Police newsroom", "Chicago", "https://home.chicagopolice.org/news/"),
    NewsSource("Cook County Sheriff", "Chicago", "https://www.cookcountysheriff.org/news/"),
    NewsSource(
        "Illinois AG consumer alerts",
        "Chicago",
        "https://illinoisattorneygeneral.gov/consumers/consumeralerts.html",
        minimum_keyword_matches=1,
    ),
    NewsSource("Illinois AG press releases", "Chicago", "https://illinoisattorneygeneral.gov/press-releases/"),
    NewsSource("NYPD newsroom", "New York", "https://www.nyc.gov/site/nypd/news/news.page"),
    NewsSource(
        "Manhattan DA",
        "New York",
        "https://www.manhattanda.org/press-releases/",
        required_terms=("financial", "fraud", "elder", "identity", "scam"),
    ),
    NewsSource(
        "NY Attorney General",
        "New York",
        "https://ag.ny.gov/press-releases",
        minimum_keyword_matches=1,
    ),
    NewsSource(
        "NYC Department of Consumer Affairs alerts",
        "New York",
        "https://www.nyc.gov/site/dca/consumers/consumer-alert.page",
        minimum_keyword_matches=1,
    ),
    NewsSource("LAPD newsroom", "Los Angeles", "https://www.lapdonline.org/newsroom/"),
    NewsSource(
        "LA County DA consumer protection",
        "Los Angeles",
        "https://da.lacounty.gov/media/news",
        required_terms=("consumer", "fraud", "elder", "scam", "identity"),
    ),
    NewsSource(
        "California DOJ consumer alerts",
        "Los Angeles",
        "https://oag.ca.gov/news/press-releases",
        minimum_keyword_matches=1,
    ),
]


def _fetch_html(source: NewsSource) -> str | None:
    try:
        response = requests.get(source.url, headers={"User-Agent": USER_AGENT}, timeout=10)
        if response.status_code in {403, 404}:
            print(f"WARNING: {source.name} returned {response.status_code}: {source.url}")
            return None
        response.raise_for_status()
        return response.text
    except requests.Timeout:
        print(f"WARNING: timeout fetching {source.name}: {source.url}")
    except requests.RequestException as exc:
        print(f"WARNING: connection error fetching {source.name}: {exc}")
    return None


def _candidate_date(container: Any) -> datetime | None:
    time_el = container.find("time") if hasattr(container, "find") else None
    if time_el:
        parsed = parse_date(time_el.get("datetime") or time_el.get_text(" ", strip=True))
        if parsed:
            return parsed

    for selector in (".date", ".entry-date", ".post-date", ".posted-on", ".views-field-created"):
        found = container.select_one(selector) if hasattr(container, "select_one") else None
        if found:
            parsed = parse_date(found.get_text(" ", strip=True))
            if parsed:
                return parsed

    text = container.get_text(" ", strip=True) if hasattr(container, "get_text") else ""
    return parse_date(text)


def _extract_candidates(source: NewsSource, html: str) -> list[dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for container in soup.select("article, li, div"):
        headline_el = container.find(["h2", "h3", "h4"]) or container.find("a")
        if not headline_el:
            continue
        headline = normalize_text(headline_el.get_text(" ", strip=True))
        if len(headline) < 8:
            continue

        link_el = headline_el if headline_el.name == "a" else headline_el.find("a") or container.find("a", href=True)
        href = link_el.get("href") if link_el else None
        url = urljoin(source.url, href) if href else ""

        paragraphs = [normalize_text(p.get_text(" ", strip=True)) for p in container.find_all("p")]
        summary = normalize_text(" ".join(paragraphs[:2]))
        if not summary:
            text = normalize_text(container.get_text(" ", strip=True))
            summary = text.replace(headline, "", 1).strip()[:700]

        key = (url, headline)
        if key in seen:
            continue
        seen.add(key)

        candidates.append(
            {
                "headline": headline,
                "summary": summary[:1000],
                "url": url,
                "published_at": _candidate_date(container),
            }
        )

    return candidates


def _passes_filter(source: NewsSource, candidate: dict[str, Any]) -> tuple[bool, str, list[str]]:
    headline = normalize_text(candidate.get("headline"))
    summary = normalize_text(candidate.get("summary"))
    combined = f"{headline} {summary}".strip()
    keywords = matching_keywords(combined)
    storage_keyword_minimum = max(source.minimum_keyword_matches, NEWS_MINIMUM_KEYWORD_MATCHES)

    if not candidate.get("url"):
        return False, "missing_url", keywords
    if len(keywords) < storage_keyword_minimum:
        return False, "keyword", keywords
    if source.required_terms and not any(term in combined.lower() for term in source.required_terms):
        return False, "source_category", keywords
    if len(exclusion_keywords_found(combined)) >= 3:
        return False, "exclusion", keywords
    if len(combined) < NEWS_MINIMUM_ARTICLE_LENGTH:
        return False, "length", keywords
    if not is_within_days(candidate.get("published_at"), 30):
        return False, "date", keywords
    if not has_high_confidence_indicator(combined):
        return False, "indicator", keywords
    if map_to_scam_category(combined) is None:
        return False, "category", keywords
    return True, "stored", keywords


def _row(source: NewsSource, candidate: dict[str, Any], keywords: list[str]) -> dict[str, Any]:
    combined = f"{candidate.get('headline', '')} {candidate.get('summary', '')}"
    published_at = candidate.get("published_at")
    if isinstance(published_at, datetime):
        published = published_at.astimezone(timezone.utc).isoformat()
    else:
        published = None
    return {
        "source": source.name,
        "city": source.city,
        "published_at": published,
        "headline": normalize_text(candidate.get("headline")),
        "summary": normalize_text(candidate.get("summary"))[:500],
        "url": candidate.get("url"),
        "scam_keywords_found": ", ".join(keywords),
        "keyword_match_count": len(keywords),
        "sentiment": determine_sentiment(combined),
        "scam_category": map_to_scam_category(combined),
        "is_scam_specific": True,
    }


def fetch_source(source: NewsSource) -> dict[str, Any]:
    html = _fetch_html(source)
    if not html:
        return {"source": source.name, "city": source.city, "total": 0, "stored": 0, "rejections": {"fetch": 1}, "rows": []}

    candidates = _extract_candidates(source, html)
    rows: list[dict[str, Any]] = []
    rejections: Counter[str] = Counter()
    for candidate in candidates:
        passed, reason, keywords = _passes_filter(source, candidate)
        if not passed:
            rejections[reason] += 1
            continue
        rows.append(_row(source, candidate, keywords))

    category_counts = Counter(row["scam_category"] for row in rows)
    print(f"\n{source.name} ({source.city})")
    print(f"Total articles found on page: {len(candidates)}")
    print(f"Articles passing scam filter: {len(rows)}")
    print(f"Articles rejected with reason summary: {dict(rejections)}")
    print(f"Scam category breakdown of stored articles: {dict(category_counts)}")
    print("Sample stored headlines:")
    for row in rows[:3]:
        print(f"- {row['headline']}")

    return {
        "source": source.name,
        "city": source.city,
        "total": len(candidates),
        "stored": len(rows),
        "rejections": dict(rejections),
        "category_breakdown": dict(category_counts),
        "rows": rows,
    }


def run_fetch() -> dict[str, Any]:
    all_rows: list[dict[str, Any]] = []
    source_summaries: list[dict[str, Any]] = []
    for source in SOURCES:
        result = fetch_source(source)
        all_rows.extend(result.pop("rows"))
        source_summaries.append(result)
        time.sleep(REQUEST_DELAY_SECONDS)

    client = get_supabase_client()
    upserted = upsert_rows(client, "local_news_mentions", all_rows, on_conflict="url")
    totals_by_source = {item["source"]: item["stored"] for item in source_summaries}
    rejection_totals: defaultdict[str, int] = defaultdict(int)
    for item in source_summaries:
        for reason, count in item.get("rejections", {}).items():
            rejection_totals[reason] += int(count)

    summary = {
        "total_articles_found": sum(item["total"] for item in source_summaries),
        "articles_passing_scam_filter": len(all_rows),
        "records_upserted": upserted,
        "stored_by_source": totals_by_source,
        "rejection_reason_breakdown": dict(rejection_totals),
        "category_breakdown": dict(Counter(row["scam_category"] for row in all_rows)),
    }
    print("\nLaw enforcement news final summary")
    print(json.dumps(summary, indent=2, default=str))
    return summary


def main() -> dict[str, Any]:
    return run_fetch()


if __name__ == "__main__":
    main()
