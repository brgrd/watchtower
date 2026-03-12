"""Feed ingestion and URL safety helpers for Watchtower."""

import os
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
        published_iso = (
            published.isoformat() if published else ""
        )
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
            items.append(
                {
                    "title": cve_id,
                    "url": detail_url,
                    "summary": desc[:500],
                    "source": url,
                    "published_at": cve.get("published", ""),
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
        items.append(
            {
                "title": f"{cve_id} — {v.get('vulnerabilityName', '')[:120]}",
                "url": detail_url,
                "summary": v.get("shortDescription", "")[:500],
                "source": url,
                "published_at": date_added,
            }
        )
    return items


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
    return items
