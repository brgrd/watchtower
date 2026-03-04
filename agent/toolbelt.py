"""Toolbelt: implementations for planner-dispatched actions."""
import re
from urllib.parse import urlparse

import feedparser

ALLOWED_CATEGORIES = {"vulns", "advisories", "blog", "supply_chain", "cloud", "osint"}
URL_RE = re.compile(r"^https://[\w./\-?=&%+#:@]+$")


def tool_add_feed(url: str, category: str, feeds_cfg: list, max_new: int) -> tuple:
    if not URL_RE.match(url):
        return False, f"Invalid URL format: {url[:80]}"
    if urlparse(url).scheme != "https":
        return False, "Non-HTTPS rejected"
    if category not in ALLOWED_CATEGORIES:
        return False, f"Unknown category '{category}'"
    if any(f["url"] == url for f in feeds_cfg):
        return False, "Feed already registered"

    new_count = sum(1 for f in feeds_cfg if f.get("_dynamic"))
    if new_count >= max_new:
        return False, f"max_new_feeds budget ({max_new}) exhausted"

    try:
        fp = feedparser.parse(url)
        if fp.bozo and not fp.entries:
            return False, "URL is not a valid RSS/Atom feed"
    except Exception as exc:
        return False, f"Feed parse error: {exc}"

    feeds_cfg.append(
        {
            "id": f"dynamic_{len(feeds_cfg)}",
            "url": url,
            "category": category,
            "type": "rss",
            "enabled": True,
            "_dynamic": True,
        }
    )
    return True, "Feed added"


def tool_select_sources(cluster_id: str, cards: list, ignore: dict, fetch_url_fn, add_ignore_fn) -> list:
    for card in cards:
        if card.get("id") != cluster_id:
            continue
        primary_urls = {s["url"] for s in card.get("sources", {}).get("primary", [])}
        secondary = []
        for s in card.get("sources", {}).get("secondary_candidates", []):
            url = s.get("url", "")
            if not url or url in primary_urls:
                continue
            try:
                fetch_url_fn(url)
                secondary.append({"title": s.get("title", url[:80]), "url": url})
                if len(secondary) >= 3:
                    break
            except Exception as exc:
                if "Executable content-type" in str(exc):
                    host = urlparse(url).hostname or ""
                    add_ignore_fn(ignore, "domain", host, 90)
        card.setdefault("sources", {})["secondary"] = secondary
        break
    return cards
