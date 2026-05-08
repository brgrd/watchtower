"""Breach data ingestion — separate path from CVE findings.

Breaches use a different action verb (rotate / close) than CVEs (patch / monitor),
so they live in a dedicated strip above the matrix rather than commingling with
finding cells.

Sources:
  - HIBP breach catalog (free, no API key required for the catalog endpoint).
    Endpoint: https://haveibeenpwned.com/api/v3/breaches
  - Re-tagging of bleepingcomputer / DataBreaches.net items already polled by
    ingest.py (regex match on title).  Implemented by ``classify_news_breaches``.

Output shape per breach::

    {
        "id":             "hibp:cloudflare-2026-05-06",
        "name":           "Cloudflare",
        "title":          "Cloudflare credential dump",
        "date":           "2026-05-06",
        "added":          "2026-05-07",
        "affected_count": 2_100_000,
        "data_classes":   ["email", "password_hash", "api_token"],
        "source_url":     "https://...",
        "summary":        "...",
        "action":         "rotate",          # rotate | close | monitor
        "is_recent":      True,              # within RECENT_WINDOW_DAYS
    }
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(__file__))
CACHE_FILE = os.path.join(ROOT, "state", "breach_cache.json")

HIBP_CATALOG_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_USER_AGENT = "Watchtower/2.0 (https://github.com/) infosec-briefing"
CACHE_TTL_HOURS = 6
RECENT_WINDOW_DAYS = 30
DISPLAY_LIMIT = 8

_BREACH_TITLE_RE = re.compile(
    r"\b("
    r"data\s+breach|database\s+(?:exposed|leaked|hacked)|breach\s+(?:notification|disclosed)"
    r"|credential\s+(?:dump|leak|stuffing)|password\s+leak"
    r"|customer\s+data\s+(?:exposed|leaked|stolen)|account[s]?\s+(?:exposed|leaked|hacked)"
    r"|ransomware\s+leak|users?\s+impacted"
    r")\b",
    re.IGNORECASE,
)


def _load_cache() -> dict:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(payload: dict) -> None:
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except OSError as exc:
        print(f"[WARN] breach cache write failed: {exc}")


def _cache_is_fresh(cache: dict) -> bool:
    fetched = cache.get("fetched_at")
    if not fetched:
        return False
    try:
        dt = datetime.fromisoformat(fetched)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return (datetime.now(timezone.utc) - dt) < timedelta(hours=CACHE_TTL_HOURS)


def _normalize_hibp_breach(b: dict) -> dict:
    name = b.get("Name", "") or b.get("Title", "Unnamed")
    title = b.get("Title", name)
    breach_date = (b.get("BreachDate") or "")[:10]
    added_date = (b.get("AddedDate") or "")[:10]
    pwn_count = int(b.get("PwnCount", 0) or 0)
    data_classes = b.get("DataClasses", []) or []
    description = (b.get("Description", "") or "").strip()
    # Strip HTML tags from description for plain-text rendering
    description = re.sub(r"<[^>]+>", "", description)
    description = re.sub(r"\s+", " ", description).strip()

    # Action selection: credential or password class → rotate; sensitive identity
    # data exposure → close (or rotate); otherwise → monitor.
    dc_lower = [c.lower() for c in data_classes]
    has_credentials = any(
        ("password" in c) or ("token" in c) or ("api key" in c) or ("auth" in c)
        for c in dc_lower
    )
    has_sensitive = any(
        ("ssn" in c) or ("social security" in c) or ("financial" in c) or ("payment" in c)
        for c in dc_lower
    )
    if has_credentials:
        action = "rotate"
    elif has_sensitive:
        action = "close"
    else:
        action = "monitor"

    return {
        "id": f"hibp:{name.lower()}-{breach_date}",
        "name": name,
        "title": title,
        "date": breach_date,
        "added": added_date,
        "affected_count": pwn_count,
        "data_classes": data_classes,
        "source_url": f"https://haveibeenpwned.com/PwnedWebsites#{name}",
        "summary": description[:400],
        "action": action,
    }


def fetch_breach_catalog(force: bool = False) -> list:
    """Return the HIBP breach catalog, normalized.  Cached on disk."""
    cache = _load_cache()
    if not force and _cache_is_fresh(cache):
        return cache.get("breaches", [])

    headers = {
        "User-Agent": HIBP_USER_AGENT,
        "Accept": "application/json",
    }
    try:
        res = requests.get(HIBP_CATALOG_URL, headers=headers, timeout=15)
        res.raise_for_status()
        raw = res.json()
        if not isinstance(raw, list):
            raise ValueError("HIBP catalog response was not a list")
    except (requests.RequestException, ValueError) as exc:
        print(f"[WARN] HIBP catalog fetch failed: {exc}")
        # Stale cache is better than nothing
        return cache.get("breaches", [])

    breaches = [_normalize_hibp_breach(b) for b in raw if isinstance(b, dict)]
    _save_cache(
        {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "source": "hibp",
            "breaches": breaches,
        }
    )
    return breaches


def recent_breaches(
    breaches: list | None = None,
    *,
    window_days: int = RECENT_WINDOW_DAYS,
    limit: int = DISPLAY_LIMIT,
    now: datetime | None = None,
) -> list:
    """Return breaches added within ``window_days``, newest first, capped at ``limit``."""
    if breaches is None:
        breaches = fetch_breach_catalog()
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=window_days)).date()

    def _key(b: dict) -> str:
        return b.get("added") or b.get("date") or "0000-00-00"

    recent = []
    for b in breaches:
        date_str = _key(b)
        try:
            d = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            continue
        b = {**b, "is_recent": d >= cutoff}
        if d >= cutoff:
            recent.append(b)

    recent.sort(key=_key, reverse=True)
    return recent[:limit]


def is_breach_news_item(item: dict) -> bool:
    """True if a polled news item smells like a breach announcement.

    Used to re-tag generic news feed entries (e.g. BleepingComputer) that the
    matrix would otherwise classify as misconfig/data_disclosure.
    """
    if not isinstance(item, dict):
        return False
    text = (item.get("title", "") + " " + item.get("summary", "")).strip()
    return bool(_BREACH_TITLE_RE.search(text))


def format_count(n: int) -> str:
    """Pretty-print an affected_count with K/M/B suffix."""
    if n is None or n <= 0:
        return ""
    if n >= 1_000_000_000:
        return f"{n/1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)
