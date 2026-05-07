from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from time import struct_time
from typing import Any


SCAM_OFFENSE_TYPES_CHICAGO = [
    "CONFIDENCE GAME",
    "FRAUD OR CONFIDENCE GAME",
    "THEFT BY DECEPTION",
    "IDENTITY THEFT",
    "FINANCIAL IDENTITY THEFT OVER $300",
    "FINANCIAL IDENTITY THEFT $300 AND UNDER",
    "AGGRAVATED IDENTITY THEFT",
    "COUNTERFEIT CHECK",
    "ILLEGAL USE OF DEBIT OR CREDIT CARD",
    "INTERNET FRAUD",
    "WIRE FRAUD",
    "ELDER FINANCIAL EXPLOITATION",
    "TELEPHONE THREAT OR HARASSMENT",
    "DECEPTIVE PRACTICE",
]

SCAM_OFFENSE_TYPES_NYC = [
    "FRAUDS",
    "FRAUD - IMPERSONATION",
    "FRAUD - WIRE TRANSFER",
    "FRAUD - COMPUTER",
    "FRAUD - CREDIT CARD",
    "FRAUD - CHECK",
    "IDENTITY THEFT 1",
    "IDENTITY THEFT 2",
    "IDENTITY THEFT 3",
    "GRAND LARCENY - CONFIDENCE GAME",
    "LARCENY - TRICK",
    "GRAND LARCENY - ELDERLY VICTIM",
    "THEFT OF SERVICES - DECEPTION",
]

SCAM_OFFENSE_TYPES_LA = [
    "BUNCO, GRAND THEFT",
    "BUNCO, PETTY THEFT",
    "BUNCO, ATTEMPT",
    "DOCUMENT WORTHLESS ($200 & UNDER)",
    "DOCUMENT WORTHLESS ($200.01 & OVER)",
    "THEFT, PERSON",
    "CREDIT CARDS, FRAUD USE ($950 & UNDER",
    "CREDIT CARDS, FRAUD USE ($950.01 & OVER)",
    "IDENTITY THEFT",
    "COUNTERFEIT",
    "BRIBERY",
    "EMBEZZLEMENT, GRAND THEFT ($950.01 & OVER)",
    "EXTORTION",
]

SCAM_KEYWORDS = [
    "scam",
    "fraud",
    "impersonat",
    "phishing",
    "smishing",
    "vishing",
    "identity theft",
    "gift card",
    "wire transfer",
    "elder fraud",
    "elder financial",
    "romance scam",
    "cryptocurrency scam",
    "crypto scam",
    "bitcoin scam",
    "Zelle",
    "Cash App",
    "Venmo fraud",
    "robocall",
    "government impersonat",
    "IRS scam",
    "Social Security scam",
    "SSA scam",
    "Medicare scam",
    "lottery scam",
    "sweepstakes scam",
    "investment fraud",
    "pig butchering",
    "ponzi",
    "pyramid scheme",
    "phantom debt",
    "fake check",
    "advance fee",
    "work from home scam",
    "job scam",
    "employment scam",
    "tech support scam",
    "grandparent scam",
    "family emergency scam",
    "utility scam",
    "contractor scam",
    "online purchase scam",
    "fake store",
    "counterfeit",
    "confidence game",
    "confidence scheme",
    "con artist",
    "deceptive practice",
]

SCAM_EXCLUSION_KEYWORDS = [
    "billing dispute",
    "business dispute",
    "insurance claim",
    "warranty",
    "contract dispute",
    "landlord",
    "tenant",
    "employer",
    "employee",
    "divorce",
    "custody",
    "civil matter",
    "shoplifting",
    "retail theft",
    "employee theft",
    "embezzlement by employee",
]

NEWS_MINIMUM_KEYWORD_MATCHES = 2
NEWS_MINIMUM_ARTICLE_LENGTH = 100

HIGH_CONFIDENCE_SCAM_INDICATORS = [
    "victim",
    "lost money",
    "lost",
    "dollars",
    "thousand",
    "arrested",
    "charged",
    "warned",
    "alert",
    "do not send",
    "never pay",
    "protect yourself",
    "report to",
    "call police",
    "if you receive",
    "do not",
    "never",
    "protect",
    "report",
    "police",
    "received a call",
    "received a text",
    "do not click",
]

SENTIMENT_TRIGGERS = {
    "arrest": ["arrested", "charged", "convicted", "sentenced", "guilty", "indicted", "pleaded"],
    "warning": ["warning", "alert", "caution", "beware", "watch out", "be aware", "scam alert"],
    "advisory": ["tips", "protect", "avoid", "prevent", "how to", "steps to", "what to do if", "never give"],
    "report": ["reports", "increase", "surge", "rise", "growing", "more victims", "spike", "trend"],
}

CATEGORY_TRIGGERS = [
    (
        "Government Impersonation",
        [
            "IRS",
            "SSA",
            "Social Security",
            "Medicare",
            "government impersonat",
            "federal agent",
            "DEA",
            "FBI",
            "sheriff",
            "warrant",
            "arrest threat",
            "immigration",
            "deport",
        ],
    ),
    (
        "Romance Scam",
        ["romance scam", "dating", "online relationship", "love interest", "meet online", "pig butchering"],
    ),
    (
        "Investment Fraud",
        [
            "investment fraud",
            "crypto scam",
            "bitcoin scam",
            "ponzi",
            "pyramid",
            "pig butchering",
            "fake trading",
            "binary option",
        ],
    ),
    (
        "Tech Support Scam",
        ["tech support", "Microsoft scam", "Apple scam", "computer fraud", "remote access", "pop-up scam"],
    ),
    (
        "Elder Fraud",
        ["elder fraud", "elder financial", "grandparent scam", "senior victim", "elderly victim", "family emergency scam"],
    ),
    (
        "Identity Theft",
        ["identity theft", "account takeover", "account opened without", "card opened without", "synthetic identity"],
    ),
    (
        "Online Purchase Scam",
        [
            "online purchase",
            "fake store",
            "non-delivery",
            "counterfeit goods",
            "marketplace scam",
            "Facebook marketplace",
            "social media store",
        ],
    ),
    (
        "Employment Scam",
        ["job scam", "work from home scam", "employment scam", "fake job", "hiring scam", "reshipping scam"],
    ),
    (
        "Payment Fraud",
        [
            "Zelle",
            "Cash App",
            "Venmo",
            "wire transfer",
            "gift card",
            "money transfer",
            "wire fraud",
            "advance fee",
            "fake check",
            "counterfeit check",
            "credit card",
            "debit card",
            "CREDIT CARDS, FRAUD",
            "DOCUMENT WORTHLESS",
        ],
    ),
    (
        "Debt Collection Scam",
        ["phantom debt", "fake debt collector", "debt not owed", "fake law firm", "legal threat scam"],
    ),
    (
        "Utility Contractor Scam",
        ["utility scam", "contractor scam", "home improvement scam", "fake contractor", "overcharge scam"],
    ),
    (
        "General Confidence Scam",
        ["confidence game", "con artist", "bunco", "deceptive practice", "confidence scheme"],
    ),
]


def normalize_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _contains(text_lower: str, needle: str) -> bool:
    needle_lower = needle.lower()
    if needle_lower in {"irs", "ssa", "dea", "fbi"}:
        return re.search(rf"\b{re.escape(needle_lower)}\b", text_lower) is not None
    return needle_lower in text_lower


def matching_keywords(text: str, keywords: list[str] | None = None) -> list[str]:
    text_lower = normalize_text(text).lower()
    seen: list[str] = []
    for keyword in keywords or SCAM_KEYWORDS:
        if _contains(text_lower, keyword):
            seen.append(keyword)
    return seen


def keyword_counter(values: list[str]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for value in values:
        for keyword in [part.strip() for part in str(value or "").split(",") if part.strip()]:
            counter[keyword] += 1
    return counter


def exclusion_keywords_found(text: str) -> list[str]:
    return matching_keywords(text, SCAM_EXCLUSION_KEYWORDS)


def has_any_exclusion(text: str) -> bool:
    return bool(exclusion_keywords_found(text))


def map_to_scam_category(text: str | None) -> str | None:
    normalized = normalize_text(text)
    if not normalized:
        return None

    text_lower = normalized.lower()
    for category, triggers in CATEGORY_TRIGGERS:
        if any(_contains(text_lower, trigger) for trigger in triggers):
            return category

    if matching_keywords(normalized):
        return "General Confidence Scam"
    return None


def determine_sentiment(text: str) -> str:
    text_lower = normalize_text(text).lower()
    for sentiment in ("arrest", "warning", "advisory", "report"):
        if any(trigger in text_lower for trigger in SENTIMENT_TRIGGERS[sentiment]):
            return sentiment
    return "report"


def has_high_confidence_indicator(text: str) -> bool:
    text_lower = normalize_text(text).lower()
    return any(indicator.lower() in text_lower for indicator in HIGH_CONFIDENCE_SCAM_INDICATORS)


def parse_date(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, struct_time):
        dt = datetime(*value[:6], tzinfo=timezone.utc)
    else:
        raw = normalize_text(value)
        if not raw:
            return None
        iso_raw = raw.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(iso_raw)
        except ValueError:
            dt = None
        if dt is None:
            try:
                dt = parsedate_to_datetime(raw)
            except (TypeError, ValueError):
                dt = None
        if dt is None:
            cleaned = re.sub(r"(?i)\b(posted|updated|released|on)\b[:\s]*", "", raw).strip()
            cleaned = re.sub(r"\s+", " ", cleaned)
            for pattern in (
                "%B %d, %Y",
                "%b %d, %Y",
                "%m/%d/%Y",
                "%Y-%m-%d",
                "%A, %B %d, %Y",
                "%B %d %Y",
            ):
                try:
                    dt = datetime.strptime(cleaned, pattern)
                    break
                except ValueError:
                    continue
        if dt is None:
            match = re.search(
                r"([A-Z][a-z]+\.?\s+\d{1,2},\s+\d{4}|\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})",
                raw,
            )
            if match:
                return parse_date(match.group(1).replace(".", ""))
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_within_days(dt: datetime | None, days: int) -> bool:
    if dt is None:
        return False
    return dt >= datetime.now(timezone.utc) - timedelta(days=days)
