from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urldefrag

import requests
from bs4 import BeautifulSoup


REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "sharepoint_output"
OUTPUT_PATH = OUTPUT_DIR / "Local_Scam_News_Weekly.txt"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
TIMEOUT_SECONDS = 15
URL_DELAY_SECONDS = 2

ARTICLE_SELECTORS = [
    "article",
    "div.article-item",
    "div.post",
    "div.story",
    "div.search-result",
    "li.story-item",
]

# These site-specific fallbacks are tried only after the requested selector order.
FALLBACK_ARTICLE_SELECTORS = [
    "li.story-card",
    "div.headline-list-item",
    "div.PagePromoB",
    "div.PagePromo",
]

SCAM_KEYWORDS = [
    "scam",
    "fraud",
    "impersonat",
    "phishing",
    "smishing",
    "identity theft",
    "gift card",
    "wire transfer",
    "elder fraud",
    "romance scam",
    "crypto scam",
    "bitcoin scam",
    "Zelle",
    "Cash App",
    "robocall",
    "IRS scam",
    "Social Security scam",
    "Medicare scam",
    "lottery scam",
    "investment fraud",
    "ponzi",
    "fake check",
    "advance fee",
    "job scam",
    "employment scam",
    "tech support scam",
    "grandparent scam",
    "confidence game",
    "counterfeit",
    "fake store",
    "online purchase scam",
    "pig butchering",
    "deepfake scam",
    "AI scam",
    "money mule",
    "reshipping scam",
]

EXCLUSION_TOPICS = [
    "billing dispute",
    "insurance claim",
    "contract dispute",
    "shoplifting",
    "retail theft",
    "employee theft",
    "sports",
    "entertainment",
    "weather",
    "traffic",
    "real estate",
]

CATEGORY_KEYWORDS = {
    "Government Impersonation": [
        "IRS",
        "SSA",
        "Social Security",
        "Medicare",
        "federal agent",
        "DEA",
        "FBI",
        "warrant scam",
        "immigration scam",
        "arrest threat",
        "deportation scam",
        "police impersonat",
    ],
    "Investment Fraud": [
        "investment fraud",
        "crypto scam",
        "bitcoin scam",
        "ponzi",
        "pyramid",
        "pig butchering",
        "fake trading",
    ],
    "Romance Scam": [
        "romance scam",
        "dating scam",
        "pig butchering",
        "online relationship scam",
        "sweetheart scam",
    ],
    "Tech Support Scam": [
        "tech support",
        "Microsoft scam",
        "Apple scam",
        "computer fraud",
        "remote access scam",
        "pop-up scam",
    ],
    "Elder Fraud": [
        "elder fraud",
        "grandparent scam",
        "senior scam",
        "elderly victim",
        "family emergency scam",
    ],
    "Identity Theft": [
        "identity theft",
        "account takeover",
        "account opened without",
        "personal info stolen",
    ],
    "Online Purchase Scam": [
        "fake store",
        "non-delivery",
        "counterfeit goods",
        "marketplace scam",
        "Facebook marketplace scam",
        "fake website",
        "fake online shop",
        "package scam",
    ],
    "Employment Scam": [
        "job scam",
        "work from home scam",
        "fake job",
        "hiring scam",
        "reshipping scam",
    ],
    "Payment Fraud": [
        "Zelle",
        "Cash App",
        "gift card scam",
        "wire transfer scam",
        "advance fee",
        "fake check",
        "money mule",
    ],
    "General Confidence Scam": [
        "confidence game",
        "bunco",
        "lottery scam",
        "sweepstakes scam",
        "too good to be true",
        "prize scam",
        "deceptive practice",
    ],
}

SENTIMENT_KEYWORDS = {
    "arrest": [
        "arrested",
        "charged",
        "convicted",
        "sentenced",
        "guilty",
        "indicted",
        "pleaded",
    ],
    "warning": [
        "warning",
        "alert",
        "caution",
        "beware",
        "scam alert",
        "watch out",
        "be aware",
    ],
    "advisory": [
        "tips",
        "protect",
        "avoid",
        "how to",
        "never give",
        "steps to",
        "prevent",
        "what to do",
    ],
    "report": [
        "reports",
        "increase",
        "surge",
        "rise",
        "growing",
        "more victims",
        "spike",
        "trend",
    ],
}

SOURCES = {
    "Los Angeles": [
        {
            "name": "NBC Los Angeles Search",
            "publication": "NBC Los Angeles",
            "url": "https://www.nbclosangeles.com/?s=scam",
        },
        {
            "name": "NBC Los Angeles Scams Tag",
            "publication": "NBC Los Angeles",
            "url": "https://www.nbclosangeles.com/tag/scams/",
        },
        {
            "name": "ABC7 Los Angeles Scam Tag",
            "publication": "ABC7 Los Angeles",
            "url": "https://abc7.com/tag/scam/",
        },
        {
            "name": "ABC7 Los Angeles Fraud Tag",
            "publication": "ABC7 Los Angeles",
            "url": "https://abc7.com/tag/fraud/",
        },
        {
            "name": "KTLA Search",
            "publication": "KTLA",
            "url": "https://ktla.com/?s=scam",
        },
        {
            "name": "FOX 11 Los Angeles Search",
            "publication": "FOX 11 Los Angeles",
            "url": "https://www.foxla.com/search?q=scam",
        },
        {
            "name": "CBS News Los Angeles Search",
            "publication": "CBS News Los Angeles",
            "url": "https://www.cbsnews.com/losangeles/search/?q=scam",
        },
        {
            "name": "LAist Scams Tag",
            "publication": "LAist",
            "url": "https://laist.com/tags/scams",
        },
        {
            "name": "Los Angeles Daily News Search",
            "publication": "Los Angeles Daily News",
            "url": "https://www.dailynews.com/?s=scam",
        },
    ],
    "Chicago": [
        {
            "name": "NBC Chicago Search",
            "publication": "NBC Chicago",
            "url": "https://www.nbcchicago.com/?s=scam",
        },
        {
            "name": "ABC7 Chicago Search",
            "publication": "ABC7 Chicago",
            "url": "https://abc7chicago.com/?s=scam",
        },
        {
            "name": "WGN-TV Search",
            "publication": "WGN-TV",
            "url": "https://wgntv.com/?s=scam",
        },
        {
            "name": "Chicago Sun-Times Search",
            "publication": "Chicago Sun-Times",
            "url": "https://chicago.suntimes.com/search?q=scam",
        },
        {
            "name": "Chicago Tribune Search",
            "publication": "Chicago Tribune",
            "url": "https://www.chicagotribune.com/search?q=scam",
        },
        {
            "name": "FOX 32 Chicago Search",
            "publication": "FOX 32 Chicago",
            "url": "https://www.fox32chicago.com/search?q=scam",
        },
        {
            "name": "CBS News Chicago Search",
            "publication": "CBS News Chicago",
            "url": "https://www.cbsnews.com/chicago/search/?q=scam",
        },
    ],
}


@dataclass(frozen=True)
class Article:
    city: str
    publication: str
    source_url: str
    headline: str
    url: str
    summary: str
    published_at: date
    category: str
    sentiment: str


@dataclass
class SourceDiagnostics:
    city: str
    source_name: str
    source_url: str
    publication: str
    status_code: int | None = None
    articles_found: int = 0
    articles_passing: int = 0
    rejected_reasons: Counter[str] | None = None
    passing_headlines: list[str] | None = None
    zero_result_reason: str | None = None
    raw_html_sample: str = ""

    def __post_init__(self) -> None:
        if self.rejected_reasons is None:
            self.rejected_reasons = Counter()
        if self.passing_headlines is None:
            self.passing_headlines = []


def _contains_any(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(keyword.lower() in text_lower for keyword in keywords)


def _count_keyword_hits(text: str, keywords: list[str]) -> int:
    text_lower = text.lower()
    return sum(1 for keyword in keywords if keyword.lower() in text_lower)


def _clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _truncate(value: str, max_chars: int) -> str:
    value = _clean_text(value)
    if len(value) <= max_chars:
        return value
    return value[: max_chars - 3].rstrip() + "..."


def _make_absolute_url(base_url: str, href: str) -> str:
    absolute = urljoin(base_url, href)
    return urldefrag(absolute).url


def _parse_date(value: str, today: date) -> date | None:
    value = _clean_text(value)
    if not value:
        return None

    relative_match = re.search(
        r"\b(\d+)\s+(minute|hour|day|week|month|year)s?\s+ago\b",
        value,
        flags=re.IGNORECASE,
    )
    if relative_match:
        amount = int(relative_match.group(1))
        unit = relative_match.group(2).lower()
        if unit in {"minute", "hour"}:
            return today
        if unit == "day":
            return today - timedelta(days=amount)
        if unit == "week":
            return today - timedelta(weeks=amount)
        if unit == "month":
            return today - timedelta(days=30 * amount)
        if unit == "year":
            return today - timedelta(days=365 * amount)

    try:
        parsed_email_date = parsedate_to_datetime(value)
        if parsed_email_date:
            return parsed_email_date.date()
    except (TypeError, ValueError, IndexError, OverflowError):
        pass

    normalized = re.sub(r"(\d+)(st|nd|rd|th)", r"\1", value, flags=re.IGNORECASE)
    normalized = normalized.replace("Sept.", "Sep.").replace("Sept ", "Sep ")
    date_patterns = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%B %d, %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%b %d %Y",
        "%m/%d/%Y",
        "%m/%d/%y",
    ]
    for pattern in date_patterns:
        try:
            if pattern.endswith("Z") and normalized.endswith("Z"):
                parsed = datetime.strptime(normalized, pattern).replace(tzinfo=timezone.utc)
            else:
                parsed = datetime.strptime(normalized, pattern)
            return parsed.date()
        except ValueError:
            continue

    embedded = re.search(
        r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|"
        r"Dec(?:ember)?)\.?\s+\d{1,2},?\s+\d{4}\b",
        normalized,
        flags=re.IGNORECASE,
    )
    if embedded:
        return _parse_date(embedded.group(0).replace(".", ""), today)

    embedded_without_year = re.search(
        r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|"
        r"Dec(?:ember)?)\.?\s+\d{1,2}\b",
        normalized,
        flags=re.IGNORECASE,
    )
    if embedded_without_year:
        parsed = _parse_date(
            f"{embedded_without_year.group(0).replace('.', '')}, {today.year}",
            today,
        )
        if parsed and parsed > today + timedelta(days=30):
            parsed = date(parsed.year - 1, parsed.month, parsed.day)
        return parsed

    return None


def _published_date_from_article(article: Any, today: date) -> date:
    time_tag = article.find("time")
    if time_tag:
        # Some local sites reuse card datetime attributes for refresh timestamps;
        # visible time text is the safer publication date when both are present.
        parsed = _parse_date(time_tag.get_text(" ", strip=True), today)
        if parsed:
            return parsed
        datetime_attr = time_tag.get("datetime")
        parsed = _parse_date(str(datetime_attr or ""), today)
        if parsed:
            return parsed
    date_like_elements = article.select(
        "[class*='date' i], [class*='time' i], [class*='meta' i], [datetime]"
    )
    for element in date_like_elements:
        parsed = _parse_date(element.get_text(" ", strip=True), today)
        if parsed:
            return parsed
    parsed = _parse_date(article.get_text(" ", strip=True), today)
    if parsed:
        return parsed
    return today


def _is_exclusion_dominated(text: str) -> bool:
    exclusion_hits = _count_keyword_hits(text, EXCLUSION_TOPICS)
    if not exclusion_hits:
        return False
    scam_hits = _count_keyword_hits(text, SCAM_KEYWORDS)
    return exclusion_hits >= scam_hits


def _category_for(text: str) -> str:
    for category, keywords in CATEGORY_KEYWORDS.items():
        if _contains_any(text, keywords):
            return category
    return "General Scam Warning"


def _sentiment_for(text: str) -> str:
    for sentiment in ["arrest", "warning", "advisory", "report"]:
        if _contains_any(text, SENTIMENT_KEYWORDS[sentiment]):
            return sentiment
    return "report"


def _first_text_from_selectors(article_element: Any, selectors: list[str]) -> str:
    for selector in selectors:
        element = article_element.select_one(selector)
        if element:
            text = _clean_text(element.get_text(" ", strip=True))
            if text:
                return text
    return ""


def _headline_from_article(article_element: Any) -> str:
    headline_tag = article_element.find(["h1", "h2", "h3"])
    if headline_tag:
        text = _clean_text(headline_tag.get_text(" ", strip=True))
        if text:
            return text

    text = _first_text_from_selectors(
        article_element,
        [".headline", ".PagePromo-title", ".entry-title", "[data-testid*='headline' i]"],
    )
    if text:
        return text

    for link_tag in article_element.find_all("a", href=True):
        text = _clean_text(link_tag.get_text(" ", strip=True))
        if text and text.lower() not in {"share", "tweet", "email", "next"}:
            return text
        aria_label = _clean_text(str(link_tag.get("aria-label") or ""))
        if aria_label:
            return aria_label
    return ""


def _summary_from_article(article_element: Any) -> str:
    summary_tag = article_element.find("p")
    if summary_tag:
        summary = _clean_text(summary_tag.get_text(" ", strip=True))
        if summary:
            return _truncate(summary, 400)

    summary = _first_text_from_selectors(
        article_element,
        [".callout", ".PagePromo-description", ".PagePromo-excerpt", ".story-card__excerpt"],
    )
    if summary:
        return _truncate(summary, 400)

    for selector in ["[data-imgalt]", "img[alt]", "a[aria-label]"]:
        element = article_element.select_one(selector)
        if not element:
            continue
        attr_name = "data-imgalt" if element.has_attr("data-imgalt") else "alt"
        if element.name == "a":
            attr_name = "aria-label"
        summary = _clean_text(str(element.get(attr_name) or ""))
        if summary and summary.lower() not in {"share", "tweet", "email"}:
            return _truncate(summary, 400)
    return ""


def _extract_article(
    article_element: Any,
    *,
    city: str,
    publication: str,
    source_url: str,
    today: date,
) -> dict[str, Any] | None:
    link_tag = article_element.find("a", href=True)
    if not link_tag:
        return None

    headline = _headline_from_article(article_element)
    href = str(link_tag.get("href", ""))
    if not headline or not href:
        return None

    summary = _summary_from_article(article_element)
    published_at = _published_date_from_article(article_element, today)

    return {
        "city": city,
        "publication": publication,
        "source_url": source_url,
        "headline": headline,
        "url": _make_absolute_url(source_url, href),
        "summary": summary,
        "published_at": published_at,
    }


def _filter_article(
    raw_article: dict[str, Any],
    *,
    seen_urls: set[str],
    cutoff_date: date,
) -> tuple[Article | None, str | None]:
    if raw_article["published_at"] < cutoff_date:
        return None, "older than 7 days"

    combined = _clean_text(f"{raw_article['headline']} {raw_article['summary']}")
    if not _contains_any(combined, SCAM_KEYWORDS):
        return None, "missing scam keyword"

    if _is_exclusion_dominated(combined):
        return None, "excluded non-scam topic"

    if len(combined) < 80:
        return None, "under 80 characters"

    if raw_article["url"] in seen_urls:
        return None, "duplicate URL"

    category = _category_for(combined)
    sentiment = _sentiment_for(combined)
    article = Article(
        city=raw_article["city"],
        publication=raw_article["publication"],
        source_url=raw_article["source_url"],
        headline=raw_article["headline"],
        url=raw_article["url"],
        summary=raw_article["summary"],
        published_at=raw_article["published_at"],
        category=category,
        sentiment=sentiment,
    )
    return article, None


def _find_article_elements(soup: BeautifulSoup) -> list[Any]:
    for selector in ARTICLE_SELECTORS:
        elements = soup.select(selector)
        if elements:
            return elements
    for selector in FALLBACK_ARTICLE_SELECTORS:
        elements = soup.select(selector)
        if elements:
            return elements
    return []


def _fetch_source(
    source: dict[str, str],
    city: str,
    *,
    seen_urls: set[str],
    today: date,
) -> tuple[list[Article], SourceDiagnostics]:
    diagnostics = SourceDiagnostics(
        city=city,
        source_name=source["name"],
        source_url=source["url"],
        publication=source["publication"],
    )

    try:
        response = requests.get(
            source["url"],
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        diagnostics.zero_result_reason = f"fetch failed: {exc.__class__.__name__}"
        diagnostics.raw_html_sample = ""
        return [], diagnostics

    diagnostics.status_code = response.status_code
    diagnostics.raw_html_sample = response.text[:1000]
    if response.status_code == 403 or not response.ok:
        diagnostics.zero_result_reason = "fetch failed"
        return [], diagnostics

    soup = BeautifulSoup(response.text, "html.parser")
    article_elements = _find_article_elements(soup)
    diagnostics.articles_found = len(article_elements)
    if not article_elements:
        diagnostics.zero_result_reason = "no articles found"
        return [], diagnostics

    collected: list[Article] = []
    cutoff_date = today - timedelta(days=7)
    for element in article_elements:
        raw_article = _extract_article(
            element,
            city=city,
            publication=source["publication"],
            source_url=source["url"],
            today=today,
        )
        if not raw_article:
            diagnostics.rejected_reasons["missing headline or URL"] += 1
            continue

        article, rejection_reason = _filter_article(
            raw_article,
            seen_urls=seen_urls,
            cutoff_date=cutoff_date,
        )
        if not article:
            diagnostics.rejected_reasons[rejection_reason or "filtered"] += 1
            continue

        seen_urls.add(article.url)
        collected.append(article)
        if len(diagnostics.passing_headlines) < 2:
            diagnostics.passing_headlines.append(article.headline)

    diagnostics.articles_passing = len(collected)
    if not collected:
        diagnostics.zero_result_reason = "all articles filtered out"
    return collected, diagnostics


def scrape_sources() -> tuple[list[Article], list[SourceDiagnostics]]:
    today = date.today()
    seen_urls: set[str] = set()
    all_articles: list[Article] = []
    all_diagnostics: list[SourceDiagnostics] = []

    for city, sources in SOURCES.items():
        print(f"\nStep {'1' if city == 'Los Angeles' else '2'}: Scrape all {city} sources.")
        for source_index, source in enumerate(sources):
            articles, diagnostics = _fetch_source(source, city, seen_urls=seen_urls, today=today)
            all_articles.extend(articles)
            all_diagnostics.append(diagnostics)
            _print_source_diagnostics(diagnostics)
            if diagnostics.zero_result_reason:
                sample = diagnostics.raw_html_sample or "[raw HTML unavailable due to fetch failure]"
                print("Raw HTML first 1000 characters:")
                print(sample)
            if source_index < len(sources) - 1 or city != list(SOURCES.keys())[-1]:
                time.sleep(URL_DELAY_SECONDS)

    return all_articles, all_diagnostics


def _print_source_diagnostics(diagnostics: SourceDiagnostics) -> None:
    print(f"\nSOURCE: {diagnostics.publication} ({diagnostics.source_url})")
    print(f"HTTP status code: {diagnostics.status_code if diagnostics.status_code else 'fetch failed'}")
    print(f"Articles found on page: {diagnostics.articles_found}")
    print(f"Articles passing all filters: {diagnostics.articles_passing}")
    if diagnostics.rejected_reasons:
        reason_text = ", ".join(
            f"{reason}: {count}" for reason, count in diagnostics.rejected_reasons.most_common()
        )
    else:
        reason_text = "none"
    print(f"Articles rejected with primary reason: {reason_text}")
    if diagnostics.passing_headlines:
        print("First 2 passing headlines:")
        for headline in diagnostics.passing_headlines[:2]:
            print(f"  - {headline}")
    else:
        print("First 2 passing headlines: none")


def _format_article(article: Article) -> str:
    summary = article.summary or "No summary available."
    return "\n".join(
        [
            f"SOURCE: {article.publication}",
            f"DATE: {article.published_at.isoformat()}",
            f"HEADLINE: {article.headline}",
            f"SUMMARY: {summary}",
            f"CATEGORY: {article.category}",
            f"URL: {article.url}",
        ]
    )


def _articles_for_section(articles: list[Article], city: str, sentiments: set[str]) -> list[Article]:
    return sorted(
        [article for article in articles if article.city == city and article.sentiment in sentiments],
        key=lambda article: (article.published_at, article.publication, article.headline),
        reverse=True,
    )


def _section(title: str, articles: list[Article], empty_message: str) -> str:
    lines = [
        "────────────────────────────────────────────────",
        title,
        "────────────────────────────────────────────────",
    ]
    if not articles:
        lines.append(empty_message)
    else:
        for index, article in enumerate(articles):
            if index:
                lines.append("")
            lines.append(_format_article(article))
    return "\n".join(lines)


def _week_bounds(today: date) -> tuple[date, date]:
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)
    return monday, sunday


def build_report(articles: list[Article], diagnostics: list[SourceDiagnostics]) -> str:
    today = date.today()
    monday, sunday = _week_bounds(today)
    city_articles = {city: [article for article in articles if article.city == city] for city in SOURCES}
    city_sources = {
        city: {article.source_url for article in city_articles[city]}
        for city in SOURCES
    }
    category_counts_by_city = {
        city: Counter(article.category for article in city_articles[city])
        for city in SOURCES
    }
    top_categories = Counter(article.category for article in articles).most_common(5)
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    lines = [
        "════════════════════════════════════════════════",
        "LOCAL SCAM INTELLIGENCE DIGEST",
        f"Week of {monday.isoformat()} through {sunday.isoformat()}",
        f"Generated: {generated}",
        "════════════════════════════════════════════════",
        "",
        "OVERVIEW",
        f"Total articles collected: {len(articles)}",
        (
            f"Los Angeles: {len(city_articles['Los Angeles'])} articles "
            f"from {len(city_sources['Los Angeles'])} sources"
        ),
        (
            f"Chicago: {len(city_articles['Chicago'])} articles "
            f"from {len(city_sources['Chicago'])} sources"
        ),
        "",
        "LOS ANGELES breakdown by category:",
    ]

    lines.extend(_category_breakdown_lines(category_counts_by_city["Los Angeles"]))
    lines.append("Chicago breakdown by category:")
    lines.extend(_category_breakdown_lines(category_counts_by_city["Chicago"]))
    lines.append("")
    lines.append("Most covered scam types this week:")
    if top_categories:
        lines.extend(f"  {rank}. {category}: {count} articles" for rank, (category, count) in enumerate(top_categories, 1))
    else:
        lines.append("  No scam articles collected this week")
    lines.append("")

    lines.append(
        _section(
            "LOS ANGELES — ARRESTS AND CHARGES",
            _articles_for_section(articles, "Los Angeles", {"arrest"}),
            "No arrest stories this week",
        )
    )
    lines.append("")
    lines.append(
        _section(
            "LOS ANGELES — WARNINGS AND ADVISORIES",
            _articles_for_section(articles, "Los Angeles", {"warning", "advisory"}),
            "No warnings or advisories this week",
        )
    )
    lines.append("")
    lines.append(
        _section(
            "LOS ANGELES — REPORTED TRENDS",
            _articles_for_section(articles, "Los Angeles", {"report"}),
            "No trend reports this week",
        )
    )
    lines.append("")
    lines.append(
        _section(
            "CHICAGO — ARRESTS AND CHARGES",
            _articles_for_section(articles, "Chicago", {"arrest"}),
            "No arrest stories this week",
        )
    )
    lines.append("")
    lines.append(
        _section(
            "CHICAGO — WARNINGS AND ADVISORIES",
            _articles_for_section(articles, "Chicago", {"warning", "advisory"}),
            "No warnings or advisories this week",
        )
    )
    lines.append("")
    lines.append(
        _section(
            "CHICAGO — REPORTED TRENDS",
            _articles_for_section(articles, "Chicago", {"report"}),
            "No trend reports this week",
        )
    )
    lines.append("")
    lines.extend(
        [
            "────────────────────────────────────────────────",
            "SOURCES THAT RETURNED NO RESULTS THIS WEEK",
            "────────────────────────────────────────────────",
        ]
    )
    zero_sources = [diagnostic for diagnostic in diagnostics if diagnostic.zero_result_reason]
    if zero_sources:
        for diagnostic in zero_sources:
            lines.append(f"{diagnostic.source_url} — {diagnostic.zero_result_reason}")
    else:
        lines.append("All sources returned at least one article after filtering")
    lines.extend(
        [
            "",
            "════════════════════════════════════════════════",
            "END OF LOCAL SCAM INTELLIGENCE DIGEST",
            "════════════════════════════════════════════════",
        ]
    )
    return "\n".join(lines) + "\n"


def _category_breakdown_lines(counter: Counter[str]) -> list[str]:
    if not counter:
        return ["  No scam articles collected this week"]
    return [f"  {category}: {count} articles" for category, count in counter.most_common()]


def write_report(articles: list[Article], diagnostics: list[SourceDiagnostics]) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    report = build_report(articles, diagnostics)
    OUTPUT_PATH.write_text(report, encoding="utf-8")
    return OUTPUT_PATH


def _print_final_summary(
    articles: list[Article],
    diagnostics: list[SourceDiagnostics],
    output_path: Path,
) -> None:
    print("\nStep 3: Write the txt file to sharepoint_output/Local_Scam_News_Weekly.txt")
    size_kb = output_path.stat().st_size / 1024
    print("\nStep 4: Output summary")
    print(f"File path: {output_path.relative_to(REPO_ROOT)}")
    print(f"File size: {size_kb:.1f} KB")
    print(f"Total articles in file: {len(articles)}")
    print("Breakdown by city and sentiment:")
    sentiment_counts: dict[str, Counter[str]] = defaultdict(Counter)
    for article in articles:
        sentiment_counts[article.city][article.sentiment] += 1
    for city in SOURCES:
        if sentiment_counts[city]:
            formatted = ", ".join(
                f"{sentiment}: {count}" for sentiment, count in sentiment_counts[city].most_common()
            )
        else:
            formatted = "none"
        print(f"  {city}: {formatted}")
    zero_sources = [diagnostic for diagnostic in diagnostics if diagnostic.zero_result_reason]
    print("Any sources that returned zero results:")
    if zero_sources:
        for diagnostic in zero_sources:
            print(f"  - {diagnostic.source_url} — {diagnostic.zero_result_reason}")
    else:
        print("  none")

    print("\nStep 5: First 50 lines of generated txt file")
    report_lines = output_path.read_text(encoding="utf-8").splitlines()
    for line in report_lines[:50]:
        print(line)


def main() -> dict[str, Any]:
    articles, diagnostics = scrape_sources()
    output_path = write_report(articles, diagnostics)
    _print_final_summary(articles, diagnostics, output_path)
    return {
        "status": "PASS",
        "output_path": str(output_path.relative_to(REPO_ROOT)),
        "articles": len(articles),
        "zero_result_sources": sum(1 for diagnostic in diagnostics if diagnostic.zero_result_reason),
    }


if __name__ == "__main__":
    main()
