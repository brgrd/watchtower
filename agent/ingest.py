"""Feed ingestion and URL safety helpers for Watchtower."""

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup

ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG = yaml.safe_load(
    open(os.path.join(ROOT, "agent", "config.yaml"), "r", encoding="utf-8")
)

# ---------------------------------------------------------------------------
# Keyword lists used by _enrich_item_flags() to set patch/exploit status
# on every polled item before it reaches Groq or _findings_to_cards().
# ---------------------------------------------------------------------------

# Phrases that confirm a patch/fix is available
_PATCH_PHRASES = (
    "patch available",
    "security update",
    "fixed in",
    "upgrade to",
    "hotfix",
    "has been patched",
    "update available",
    "released a fix",
    "released a patch",
    "apply the update",
    "version addresses",
    "addresses the vulnerability",
    "update your",
    "users should update",
    "users are urged to update",
)

# Phrases that confirm a workaround/mitigation exists (but not a full patch)
_WORKAROUND_PHRASES = (
    "workaround available",
    "mitigation available",
    "can be mitigated",
    "temporary fix",
    "apply mitigation",
    "disable the feature",
    "recommended workaround",
)

# Phrases that explicitly state no fix exists — distinct from "unknown"
_NO_FIX_PHRASES = (
    "no patch available",
    "no fix available",
    "no available patch",
    "no available fix",
    "unpatched",
    "no patch has been",
    "vendor has not released",
    "no mitigation available",
    "currently no fix",
    "fix is not yet available",
    "no official fix",
    "awaiting a patch",
)

# Phrases that indicate active exploitation (beyond CISA KEV source check)
_EXPLOIT_PHRASES = (
    "exploited in the wild",
    "actively exploited",
    "in-the-wild",
    "zero-day",
    "0-day",
    "observed exploitation",
    "under active attack",
    "being exploited",
    "exploitation detected",
)

PRIVATE_PREFIXES = ("10.", "192.168.", "172.", "127.", "169.254.")
BLOCKED_CT_PREFIXES = (
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/octet-stream",
    "application/x-7z-compressed",
    "application/zip",
    "application/x-tar",
    "application/gzip",
)


def placeholder_mode() -> bool:
    val = os.getenv("WATCHTOWER_PLACEHOLDER_MODE")
    if val is None:
        return bool(CONFIG.get("runtime", {}).get("placeholder_mode_default", True))
    return val.strip().lower() in {"1", "true", "yes", "on"}


def is_private_host(url: str) -> bool:
    host = requests.utils.urlparse(url).hostname or ""
    host_l = host.lower()
    if host_l == "localhost" or host_l.endswith(".localhost"):
        return True
    if host.endswith(".local") or host.endswith(".lan"):
        return True
    try:
        ip = ip_address(host)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def fetch_url(url: str, timeout=10, max_redirects=5) -> str:
    if placeholder_mode():
        return "placeholder content"

    if not url.lower().startswith("https://"):
        raise ValueError("Non-HTTPS blocked by policy")
    if is_private_host(url):
        raise ValueError("Private network host blocked")

    session = requests.Session()
    session.max_redirects = max_redirects
    r = session.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "Watchtower/1.0"},
    )

    ct = (r.headers.get("content-type") or "").split(";")[0].strip().lower()
    if any(ct.startswith(prefix) for prefix in BLOCKED_CT_PREFIXES):
        raise ValueError(f"Executable content-type blocked: {ct}")

    html = r.text
    if len(html.encode("utf-8")) > 2_000_000:
        raise ValueError("Document too large")

    text = " ".join(BeautifulSoup(html, "html.parser").get_text(" ").split())
    if len(text) < 200:
        raise ValueError("Insufficient text extracted")

    return text[:200_000]


def add_ignore(ignore: dict, typ: str, key: str, ttl_days: int):
    bucket = f"ignore_{typ}"
    ttl = (datetime.now(timezone.utc) + timedelta(days=ttl_days)).date().isoformat()
    ignore.setdefault(bucket, {})
    ignore[bucket][key] = ttl


def is_ignored(ignore: dict, url: str) -> bool:
    host = requests.utils.urlparse(url).hostname or ""
    prefix_hits = any(url.startswith(p) for p in ignore.get("ignore_url_prefix", {}))
    return (
        prefix_hits
        or host in ignore.get("ignore_domain", {})
        or url in ignore.get("ignore_url", {})
    )


def _sample_items() -> list:
    return [
        {
            "title": "CVE-2026-12345 in OpenSSL exploited in the wild",
            "url": "https://example.org/advisory/openssl-cve-2026-12345",
            "summary": "Exploit activity observed; patch available for OpenSSL package users.",
            "source": "placeholder",
        },
        {
            "title": "Malicious npm package typosquat campaign",
            "url": "https://example.org/research/npm-typosquat",
            "summary": "Dependency confusion and typosquat package names detected in npm ecosystem.",
            "source": "placeholder",
        },
        {
            "title": "Kubernetes ingress privilege escalation advisory",
            "url": "https://example.org/advisory/k8s-ingress-lpe",
            "summary": "Container and RBAC misconfiguration allows privilege escalation in certain clusters.",
            "source": "placeholder",
        },
    ]


def _poll_rss(url: str, since_hours: int, ignore: dict) -> list:
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Watchtower/1.0"},
            timeout=15,
        )
        resp.raise_for_status()
        fp = feedparser.parse(resp.content)
    except Exception as exc:
        print(f"[WARN] RSS fetch failed for {url}: {exc}")
        return []
    items = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    for e in fp.entries:
        link = getattr(e, "link", None) or getattr(e, "id", None)
        if not link or is_ignored(ignore, link):
            continue
        published = None
        for k in ("published_parsed", "updated_parsed"):
            val = getattr(e, k, None)
            if val:
                published = datetime(*val[:6], tzinfo=timezone.utc)
                break
        if published and published < cutoff:
            continue
        published_iso = published.isoformat() if published else ""
        items.append(
            {
                "title": getattr(e, "title", "")[:200],
                "url": link,
                "summary": getattr(e, "summary", "")[:500],
                "source": url,
                "published_at": published_iso,
            }
        )
    return items


def _poll_nvd_api(url: str, since_hours: int, ignore: dict) -> list:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    params = {
        "pubStartDate": cutoff.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
        "startIndex": 0,
    }
    headers = {"User-Agent": "Watchtower/1.0"}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.getenv("NVD_API_KEY")

    items = []
    rate_limit_retries = 0
    while True:
        r = requests.get(url, params=params, headers=headers, timeout=30)
        if r.status_code == 429:
            rate_limit_retries += 1
            if rate_limit_retries > 3:
                print("[WARN] NVD API rate-limited repeatedly; stopping pagination")
                break
            time.sleep(30)
            continue
        rate_limit_retries = 0
        r.raise_for_status()
        data = r.json()

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            if is_ignored(ignore, detail_url):
                continue
            desc = next(
                (
                    d.get("value", "")
                    for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                "",
            )
            refs = cve.get("references", [])
            items.append(
                {
                    "title": cve_id,
                    "url": detail_url,
                    "summary": desc[:500],
                    "source": url,
                    "published_at": cve.get("published", ""),
                    "nvd_vuln_status": cve.get("vulnStatus", ""),
                    "nvd_patch_refs": sum(
                        1 for r in refs if "Patch" in (r.get("tags") or [])
                    ),
                    "nvd_exploit_refs": sum(
                        1 for r in refs if "Exploit" in (r.get("tags") or [])
                    ),
                    "nvd_mitigation_refs": sum(
                        1 for r in refs if "Mitigation" in (r.get("tags") or [])
                    ),
                }
            )

        total = data.get("totalResults", 0)
        params["startIndex"] += data.get("resultsPerPage", 100)
        if params["startIndex"] >= total or params["startIndex"] >= 500:
            break
        time.sleep(6)
    return items


def _poll_cisa_kev(url: str, ignore: dict, since_hours: int = 24) -> list:
    r = requests.get(url, headers={"User-Agent": "Watchtower/1.0"}, timeout=30)
    r.raise_for_status()
    data = r.json()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).date()
    items = []
    for v in data.get("vulnerabilities", []):
        date_added = v.get("dateAdded", "")
        try:
            if date_added and datetime.strptime(date_added, "%Y-%m-%d").date() < cutoff:
                continue
        except ValueError:
            pass
        cve_id = v.get("cveID", "")
        detail_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if is_ignored(ignore, detail_url):
            continue
        notes = v.get("notes", "") or ""
        required_action = v.get("requiredAction", "") or ""
        # KEV required_action field often states "Apply updates" or describes
        # mitigations — use it as a richer patch signal alongside notes.
        patch_hint = (notes + " " + required_action).lower()
        kev_patch = any(p in patch_hint for p in _PATCH_PHRASES)
        kev_workaround = any(p in patch_hint for p in _WORKAROUND_PHRASES)
        items.append(
            {
                "title": f"{cve_id} — {v.get('vulnerabilityName', '')[:120]}",
                "url": detail_url,
                "summary": v.get("shortDescription", "")[:500],
                "source": url,
                "published_at": date_added,
                "kev_due_date": v.get("dueDate", ""),
                "kev_patch_hint": kev_patch,
                "kev_workaround_hint": kev_workaround,
            }
        )
    return items


_NEGATION_PREFIXES = ("no ", "not ", "without ", "currently no ", "no available ")


def _contains_positive(blob: str, phrases: tuple) -> bool:
    """Return True if a phrase appears in blob and is NOT immediately preceded
    by a negation word (no, not, without, currently no).  Prevents 'no patch
    available' from triggering the 'patch available' positive phrase."""
    low = blob.lower()
    for phrase in phrases:
        start = 0
        while True:
            idx = low.find(phrase, start)
            if idx == -1:
                break
            prefix = low[max(0, idx - 16) : idx]
            if not any(prefix.endswith(neg) or prefix.endswith(neg.rstrip()) for neg in _NEGATION_PREFIXES):
                return True
            start = idx + 1
    return False


def _enrich_item_flags(item: dict) -> None:
    """Set patch/exploit status flags on a polled item in-place.

    Combines three signal sources in priority order:
    1. NVD-provided vulnStatus and reference tags (highest confidence).
    2. CISA KEV source indicator (always exploited).
    3. Keyword scanning of title + summary text (lowest confidence, broadest coverage).

    Sets four boolean fields: ``patch_available``, ``workaround_available``,
    ``exploited_in_wild``, ``no_fix_explicit``.  ``no_fix_explicit`` is a
    distinct signal from ``exploited_in_wild`` — it means a source
    explicitly stated no fix exists, which lets _findings_to_cards() emit
    ``"no_fix"`` even for CVEs not yet in CISA KEV.
    """
    blob = (
        (item.get("title", "") or "") + " " + (item.get("summary", "") or "")
    ).lower()

    # --- Signal 1: NVD reference tags (set by _poll_nvd_api) ---
    nvd_patch = item.get("nvd_patch_refs", 0) > 0
    nvd_exploit = item.get("nvd_exploit_refs", 0) > 0
    nvd_mitigation = item.get("nvd_mitigation_refs", 0) > 0

    # --- Signal 2: CISA KEV source and action hints ---
    kev_source = (
        item.get("source_id") == "cisa_kev"
        or "known_exploited" in (item.get("source", "") or "")
    )
    kev_patch = item.get("kev_patch_hint", False)
    kev_workaround = item.get("kev_workaround_hint", False)

    # --- Signal 3: keyword scanning ---
    kw_patch = _contains_positive(blob, _PATCH_PHRASES)
    kw_workaround = _contains_positive(blob, _WORKAROUND_PHRASES)
    kw_no_fix = any(p in blob for p in _NO_FIX_PHRASES)
    kw_exploit = any(p in blob for p in _EXPLOIT_PHRASES)

    item["patch_available"] = nvd_patch or kev_patch or kw_patch
    item["workaround_available"] = nvd_mitigation or kev_workaround or kw_workaround
    item["exploited_in_wild"] = kev_source or nvd_exploit or kw_exploit
    item["no_fix_explicit"] = kw_no_fix


def poll_feed(feed_cfg: dict, since_hours: int, ignore: dict) -> list:
    if placeholder_mode():
        return _sample_items()

    url = feed_cfg["url"]
    feed_type = feed_cfg.get("type", "rss")
    items: list = []
    try:
        if feed_type == "json_api":
            if "nvd.nist.gov" in url or "services.nvd.nist.gov" in url:
                items = _poll_nvd_api(url, since_hours, ignore)
            elif "cisa.gov" in url and "known_exploited" in url:
                items = _poll_cisa_kev(url, ignore, since_hours)
            else:
                r = requests.get(
                    url, headers={"User-Agent": "Watchtower/1.0"}, timeout=30
                )
                r.raise_for_status()
                raw = r.json()
                entries = (
                    raw
                    if isinstance(raw, list)
                    else raw.get("items", raw.get("entries", []))
                )
                items = []
                for e in entries:
                    link = str(e.get("url", e.get("link", "")))
                    if not link:
                        continue
                    items.append(
                        {
                            "title": str(e.get("title", ""))[:200],
                            "url": link,
                            "summary": str(e.get("summary", e.get("description", "")))[
                                :500
                            ],
                            "source": url,
                        }
                    )
        else:
            items = _poll_rss(url, since_hours, ignore)
    except Exception as exc:
        print(f"[WARN] poll_feed failed for {url}: {exc}")
        return []
    country = feed_cfg.get("country", "")
    for it in items:
        it["source_id"] = feed_cfg.get("id", "")
        it["source_type"] = feed_cfg.get("type", "rss")
        it["source_category"] = feed_cfg.get("category", "")
        it["source_country"] = country
        if country:
            it["country"] = country
        _enrich_item_flags(it)
    return items


# -----------------------------
# CVE-anchored deduplication
# -----------------------------
_CVE_DEDUP_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _merge_by_cve(items: list) -> list:
    """Merge feed items that share at least one CVE ID into a single enriched item.

    Items with no extractable CVE ID pass through unchanged.  Merged items carry
    the union of all CVE IDs, the longest available text, and a ``_merged_urls``
    list of secondary source URLs.  This prevents duplicate Groq findings when
    multiple feeds cover the same vulnerability.
    """
    if not items:
        return items

    def _item_cves(item: dict) -> frozenset:
        text = (
            item.get("title", "")
            + " "
            + item.get("summary", "")
            + " "
            + item.get("extracted_text", "")
        )
        return frozenset(m.group(0).upper() for m in _CVE_DEDUP_RE.finditer(text))

    # Separate items with CVEs from those without
    cve_items: list = []  # (item, frozenset_of_cves)
    no_cve: list = []
    for item in items:
        cves = _item_cves(item)
        if cves:
            cve_items.append((item, cves))
        else:
            no_cve.append(item)

    if not cve_items:
        return items

    # Union-find grouping — items sharing any CVE end up in the same group
    n = len(cve_items)
    parent = list(range(n))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    cve_to_idx: dict = {}  # first item index that introduced this CVE
    for idx, (_, cves) in enumerate(cve_items):
        for cve in cves:
            if cve in cve_to_idx:
                rx, ri = _find(cve_to_idx[cve]), _find(idx)
                if rx != ri:
                    parent[rx] = ri
            else:
                cve_to_idx[cve] = idx

    # Collect groups by root
    from collections import defaultdict

    groups: dict = defaultdict(list)
    for idx in range(n):
        groups[_find(idx)].append(idx)

    merged: list = []
    for indices in groups.values():
        group_items = [cve_items[i][0] for i in indices]
        if len(group_items) == 1:
            merged.append(group_items[0])
            continue

        # Use the item with the most text as primary
        primary = max(
            group_items,
            key=lambda x: len(x.get("extracted_text", "") + x.get("summary", "")),
        )
        all_cves = sorted({c for i in indices for c in cve_items[i][1]})

        # Combine text from all group members for richer Groq context
        texts = [
            g.get("extracted_text", "") or g.get("summary", "") for g in group_items
        ]
        combined = " ".join(t for t in texts if t)[:1500]

        result = dict(primary)
        result["_merged_cves"] = all_cves
        result["_merge_count"] = len(group_items)
        result["_merged_urls"] = [
            g["url"]
            for g in group_items
            if g.get("url") and g["url"] != primary.get("url")
        ]
        if len(combined) > len(result.get("extracted_text", "")):
            result["extracted_text"] = combined
        merged.append(result)

        titles = [g.get("title", "")[:50] for g in group_items]
        print(
            f"[INFO] CVE dedup: merged {len(group_items)} items "
            f"for {all_cves[:3]} — {titles[0]!r}"
        )

    return merged + no_cve


# ──────────────────────────────────────────────
# EPSS enrichment (FIRST.org, free, no API key)
# ──────────────────────────────────────────────

_EPSS_API = "https://api.first.org/data/v1/epss"
_EPSS_TTL_HOURS = 24


def _enrich_epss(cards: list, cache_file: str) -> None:
    """Fetch EPSS exploitation probability scores and set card['epss_score'].

    For each card, epss_score is the highest EPSS value (0–1) across all CVEs
    extracted from its title/summary/enrichment.  Scores are cached in
    cache_file for 24 hours to avoid redundant API calls.  Skipped entirely
    in placeholder mode or if the API call fails.
    """
    if placeholder_mode():
        return

    from agent.scoring import _extract_cves  # local import avoids circular dep

    # Load existing cache
    cache: dict = {}
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as fh:
                cache = json.load(fh)
        except (json.JSONDecodeError, OSError):
            cache = {}

    now_utc = datetime.now(timezone.utc)
    cutoff = now_utc - timedelta(hours=_EPSS_TTL_HOURS)

    def _cached_at(entry: dict) -> datetime:
        try:
            return datetime.fromisoformat(
                entry.get("cached_at", "2000-01-01T00:00:00+00:00")
            )
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)

    # Collect CVEs per card
    card_cves: list[list] = []
    for card in cards:
        cves = (card.get("enrichment") or {}).get("cves") or _extract_cves(
            card.get("title", "") + " " + card.get("summary", "")
        )
        card_cves.append(cves)

    all_cves = {c for cves in card_cves for c in cves}

    # Determine which CVEs need a fresh fetch
    to_fetch = [
        cve
        for cve in all_cves
        if cve not in cache or _cached_at(cache[cve]) < cutoff
    ]

    # Batch-fetch in groups of 100 (API supports multi-CVE queries)
    now_iso = now_utc.isoformat()
    if to_fetch:
        for i in range(0, len(to_fetch), 100):
            batch = to_fetch[i : i + 100]
            try:
                resp = requests.get(
                    _EPSS_API,
                    params={"cve": ",".join(batch)},
                    timeout=15,
                    headers={"User-Agent": "Watchtower/1.0"},
                )
                resp.raise_for_status()
                for entry in resp.json().get("data", []):
                    cve_id = entry.get("cve", "")
                    if cve_id:
                        cache[cve_id] = {
                            "epss": float(entry.get("epss", 0.0)),
                            "percentile": float(entry.get("percentile", 0.0)),
                            "cached_at": now_iso,
                        }
                # Mark CVEs absent from the API response so they are not refetched
                for cve in batch:
                    if cve not in cache:
                        cache[cve] = {"epss": None, "percentile": None, "cached_at": now_iso}
            except Exception as exc:
                print(f"[WARN] EPSS batch fetch failed: {exc}")

        # Persist updated cache
        try:
            os.makedirs(os.path.dirname(os.path.abspath(cache_file)), exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as fh:
                json.dump(cache, fh, ensure_ascii=False)
        except OSError as exc:
            print(f"[WARN] EPSS cache write failed: {exc}")

    # Apply scores to cards
    for card, cves in zip(cards, card_cves):
        scores = [
            cache[c]["epss"]
            for c in cves
            if c in cache and cache[c].get("epss") is not None
        ]
        card["epss_score"] = max(scores) if scores else None
