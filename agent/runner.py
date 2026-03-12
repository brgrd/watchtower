#!/usr/bin/env python3
"""Watchtower agent: plan -> act -> observe with secure defaults.

Local-safe mode:
- WATCHTOWER_PLACEHOLDER_MODE=true (default) avoids external APIs and uses embedded sample items.
- Set WATCHTOWER_PLACEHOLDER_MODE=false in CI to use real feeds + Groq planner.
"""

import hashlib
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import feedparser
import requests
import tldextract
import yaml
from bs4 import BeautifulSoup

from agent import analysis as analysis_mod
from agent import rendering as rendering_mod
from agent import html_builder as html_builder_mod
from agent import scoring as scoring_mod
from agent import state as state_mod
from agent.ingest import _merge_by_cve

ROOT = os.path.dirname(os.path.dirname(__file__))


def load_user_env_file(path: str):
    """Load KEY=VALUE lines from a local .env file into process env.

    Existing environment variables are not overwritten.
    """
    if not os.path.exists(path):
        return

    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue

            if (value.startswith('"') and value.endswith('"')) or (
                value.startswith("'") and value.endswith("'")
            ):
                value = value[1:-1]

            os.environ.setdefault(key, value)


ENV_FILE = os.getenv("WATCHTOWER_ENV_FILE", os.path.join(ROOT, ".env"))
load_user_env_file(ENV_FILE)

REPORTS_DIR = os.path.join(ROOT, "reports")
STATE_DIR = os.path.join(ROOT, "state")
IGNORE_FILE = os.path.join(STATE_DIR, "ignore_registry.json")
LEDGER_FILE = os.path.join(STATE_DIR, "ledger.jsonl")
SEEN_FILE = os.path.join(STATE_DIR, "seen_hashes.json")
LAST_RUN_CARDS_FILE = os.path.join(STATE_DIR, "last_run_cards.json")
WEEKLY_AGGREGATE_FILE = os.path.join(STATE_DIR, "weekly_aggregate.json")
FEED_HEALTH_FILE = os.path.join(STATE_DIR, "feed_health.json")
FINDING_SHELF_FILE = os.path.join(STATE_DIR, "finding_shelf.json")
IOC_LEDGER_FILE = os.path.join(STATE_DIR, "ioc_ledger.json")
CONFIG = yaml.safe_load(
    open(os.path.join(ROOT, "agent", "config.yaml"), "r", encoding="utf-8")
)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_BASE = "https://api.groq.com/openai/v1"


def placeholder_mode() -> bool:
    val = os.getenv("WATCHTOWER_PLACEHOLDER_MODE")
    if val is None:
        return bool(CONFIG.get("runtime", {}).get("placeholder_mode_default", True))
    return val.strip().lower() in {"1", "true", "yes", "on"}


# -----------------------------
# Utilities
# -----------------------------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return default


def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def append_jsonl(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


# -----------------------------
# Safety
# -----------------------------
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


# -----------------------------
# Feed polling
# -----------------------------
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
    # Pre-fetch with requests so we get a real socket timeout.
    # feedparser.parse(url) uses urllib with no timeout and can hang indefinitely.
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
        # dateAdded is "YYYY-MM-DD"; skip entries older than the lookback window
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


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _compact_text(s: str) -> str:
    return " ".join((s or "").split()).strip()


def _extract_cves(s: str) -> list:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(s or "")})


def _contains_any(txt: str, terms: tuple) -> bool:
    low = (txt or "").lower()
    return any(t in low for t in terms)


def _build_corroboration_map(items: list) -> dict:
    counts: dict = {}
    for it in items:
        key = sha256(_compact_text(it.get("title", "")).lower())[:16]
        counts[key] = counts.get(key, 0) + 1
    return counts


def _infer_vendor_product(item: dict) -> tuple:
    title = _compact_text(item.get("title", ""))
    dom = tldextract.extract(item.get("url", "")).registered_domain or ""
    if dom:
        root = dom.split(".")[0]
        return root, title[:80]
    return "unknown", title[:80]


def _infer_control_plane_impact(domains: list) -> str:
    if any(d in domains for d in ("identity", "cloud_iam", "supply_chain")):
        return "high"
    if any(d in domains for d in ("container", "web_framework", "os_kernel")):
        return "limited"
    return "none"


def _build_groq_item_package(idx: int, item: dict, corroboration: dict) -> dict:
    title = _compact_text(item.get("title", ""))
    summary = _compact_text(item.get("summary", ""))
    blob = f"{title} {summary}"
    cves = _extract_cves(blob)
    domains = classify_domains(item)
    vendor, product = _infer_vendor_product(item)
    key = sha256(title.lower())[:16]

    exploited = "known_exploited" in (item.get("source", "") or "") or _contains_any(
        blob,
        (
            "exploited in the wild",
            "actively exploited",
            "in-the-wild",
            "zero-day",
        ),
    )
    patch_available = _contains_any(
        blob,
        ("patch available", "security update", "fixed in", "upgrade to", "hotfix"),
    )
    workaround_available = _contains_any(
        blob,
        (
            "mitigation",
            "workaround",
            "temporary fix",
            "block",
            "disable",
        ),
    )
    internet_exposed = (
        "high"
        if _contains_any(
            blob,
            (
                "vpn",
                "gateway",
                "edge",
                "internet-facing",
                "appliance",
                "publicly exposed",
            ),
        )
        else (
            "medium"
            if _contains_any(blob, ("remote", "http", "https", "web", "api"))
            else "low"
        )
    )

    confidence = 0.7
    if item.get("source_type") == "json_api":
        confidence = 0.9
    elif item.get("source_category") in {"advisories", "vulns"}:
        confidence = 0.8

    return {
        "item_id": f"wt-{idx:03d}-{sha256(item.get('url', '') + title)[:10]}",
        "source_id": item.get("source_id", ""),
        "source_type": item.get("source_type", "rss"),
        "source_category": item.get("source_category", ""),
        "source_country": item.get("source_country", item.get("country", "")),
        "published_at": item.get("published_at", ""),
        "first_seen_at": item.get("first_seen_at", ""),
        "url": item.get("url", ""),
        "title": title[:200],
        "summary": summary[:600],
        "vendor": vendor,
        "product": product,
        "technology_domain": domains,
        "cves": cves,
        "cvss_base": None,
        "cwe": [],
        "kev_listed": "known_exploited" in (item.get("source", "") or ""),
        "epss_score": None,
        "exploited_in_wild": exploited,
        "patch_available": patch_available,
        "workaround_available": workaround_available,
        "internet_exposed_likelihood": internet_exposed,
        "control_plane_impact": _infer_control_plane_impact(domains),
        "confidence": confidence,
        "dedupe_hash": sha256(item.get("url", "") + title),
        "corroboration_count": corroboration.get(key, 1),
    }


# -----------------------------
# Planner
# -----------------------------
def groq_chat(messages, model, temperature=0.2, max_tokens=1200):
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY environment variable is not set")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }

    for attempt in range(5):
        res = requests.post(
            f"{GROQ_BASE}/chat/completions", headers=headers, json=payload, timeout=60
        )
        if res.status_code == 429:
            retry = int(res.headers.get("retry-after") or "2")
            time.sleep(min(30, retry + attempt))
            continue
        res.raise_for_status()
        data = res.json()
        return data["choices"][0]["message"]["content"], {
            "rpd_rem": res.headers.get("x-ratelimit-remaining-requests"),
            "tpm_rem": res.headers.get("x-ratelimit-remaining-tokens"),
        }

    raise RuntimeError("Groq rate limited repeatedly")


def groq_analyze_briefing(kev_items: list, nvd_items: list, news_items: list) -> tuple:
    """Single Groq call: analyze KEV entries, NVD CVEs, and news articles together.

    Returns (executive_summary: str, findings: list, status: str).
    Each finding: {title, summary, risk_score, domains, references: [{title, url}]}
    References point back to URLs from news_items so Top Findings are citable.
    """
    if placeholder_mode():
        print("[INFO] Groq skipped: placeholder mode is on")
        return "", [], "placeholder"
    if not GROQ_API_KEY:
        print(
            "[WARN] Groq skipped: GROQ_API_KEY is not set — check GitHub repo secrets"
        )
        return "", [], "no_api_key"

    # Build a 3-month reporting window label (current month + 2 prior)
    _now = datetime.now(timezone.utc)
    _months = [
        (_now.replace(day=1) - timedelta(days=30 * i)).strftime("%B %Y")
        for i in range(3)
    ]
    reporting_window = f"{_months[2]} – {_months[0]}"

    all_items = (kev_items or []) + (nvd_items or []) + (news_items or [])
    corroboration = _build_corroboration_map(all_items)
    # Caps kept tight to stay within Groq free-tier request size (~3k input tokens).
    # The successful baseline was 2525 tokens for 30 items; 413s occur at 72+ items.
    kev_block = [
        {
            "cve": it["title"].split("\u2014")[0].strip(),
            "description": it.get("summary", "")[:120],
            "patch_available": it.get("patch_available", False),
            "workaround_available": it.get("workaround_available", False),
            "exploited_in_wild": it.get("exploited_in_wild", True),
        }
        for it in kev_items[:6]
    ]
    nvd_block = [
        {
            "cve": it["title"],
            "description": it.get("summary", "")[:80],
            "patch_available": it.get("patch_available", False),
            "workaround_available": it.get("workaround_available", False),
            "exploited_in_wild": it.get("exploited_in_wild", False),
        }
        for it in nvd_items[:10]
    ]
    article_block = [
        {
            "headline": it["title"][:100],
            "source": tldextract.extract(it.get("url", "")).registered_domain
            or "unknown",
            "snippet": (it.get("extracted_text", "") or it.get("summary", ""))[:200],
            "url": it.get("url", ""),
        }
        for it in news_items[:12]
    ]
    domain_keys = ", ".join(_TAXONOMY.keys())
    prompt = {
        "task": "infrasec_briefing",
        "schema_version": "watchtower.groq.package.v1",
        "reporting_window": reporting_window,
        "exploited_vulnerabilities": kev_block,
        "recent_cves": nvd_block,
        "news_articles": article_block,
        "instructions": (
            "You are a senior threat intelligence analyst writing a concise daily briefing "
            f"for the 24-hour period ending now ({reporting_window}). "
            "Review all inputs: exploited vulnerabilities (CISA KEV), recent CVEs (NVD), "
            "and news articles. Produce: "
            "(1) executive_summary: exactly 3 sentences grounded in the data provided. "
            "Sentence 1 — name the 2-3 specific CVE IDs, software products, or vendor platforms "
            "that represent the highest-risk items this period (e.g. 'CVE-2026-XXXX in Palo Alto PAN-OS' "
            "or 'Apache Tomcat RCE'). "
            "Sentence 2 — identify which specific infrastructure resources or system types are most "
            "exposed right now and why (e.g. internet-facing firewalls, container orchestration nodes, "
            "VPN appliances), referencing patch or exploitation status from the data. "
            "Sentence 3 — state the single most time-sensitive action: be specific about what to patch, "
            "isolate, or monitor, name the affected product/version, and state whether a patch is "
            "currently available or not. "
            "Do NOT use vague language like 'various systems' or 'multiple vendors' — always name names. "
            "Keep the summary anchored to the reporting window and only reference items present in the input data. "
            "(2) findings: JSON array of up to 12 distinct threat or vulnerability findings. "
            "For each finding: title (under 100 chars), summary (1-2 sentence analyst note "
            "on what is affected, exploit/patch status, urgency), risk_score (integer 0-100: "
            "base 40 for known CVE, +30 if actively exploited in the wild, +15 if PoC exists, "
            "+15 if critical infrastructure), domains (array of matching keys from: "
            + domain_keys
            + "), references (array of {title, url} — cite urls from any of the three input "
            "blocks: exploited_vulnerabilities, recent_cves, or news_articles; "
            "1-3 most relevant per finding), priority (P1|P2|P3), "
            "why_now (short sentence), recommended_actions_24h (array up to 4), "
            "recommended_actions_7d (array up to 4), confidence (0..1). "
            'Output ONLY strict JSON, no markdown fences: {"executive_summary":"...",'
            '"findings":[{"title":"...","summary":"...","risk_score":0,"domains":[],'
            '"references":[{"title":"...","url":"..."}],"priority":"P2",'
            '"why_now":"...","recommended_actions_24h":[],"recommended_actions_7d":[],"confidence":0.6}]}'
        ),
    }

    try:
        user_content = json.dumps(prompt)
        print(f"[INFO] Groq payload: {len(user_content):,} chars")
        if len(user_content) > 20_000:
            print(
                f"[WARN] Groq prompt too large ({len(user_content)} chars), skipping to avoid 413"
            )
            return "", [], "payload_too_large"
        content, _ = groq_chat(
            [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Output strict JSON only. No markdown fences.",
                },
                {"role": "user", "content": user_content},
            ],
            model=CONFIG["model"]["name"],
            temperature=0.2,
            max_tokens=2000,
        )
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```[a-z]*\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())
        data = json.loads(content)
        return data.get("executive_summary", ""), data.get("findings", []), "ok"
    except Exception as exc:
        print(f"[WARN] Groq analysis failed: {exc}")
        return "", [], f"error: {exc}"


# -----------------------------
# Taxonomy / scoring / clustering
# -----------------------------
_TAXONOMY = CONFIG.get("domain_taxonomy", {})


# Buckets checked first before the broad os_kernel catch-all fires on generic signals
_DOMAIN_PRIORITY_FIRST = [
    "ai_threat",
    "ca_trust",
    "browser_ext",
    "pkg_npm",
    "pkg_pypi",
    "pkg_maven",
    "pkg_nuget",
    "pkg_gem",
    "container",
    "cloud_iam",
    "supply_chain",
    "identity",
    "crypto_lib",
    "web_framework",
]


def classify_domains(item: dict) -> list:
    txt = (item.get("title", "") + " " + item.get("summary", "")).lower()
    matched = []
    # Check priority-ordered buckets first, then remaining taxonomy keys
    ordered = _DOMAIN_PRIORITY_FIRST + [
        k for k in _TAXONOMY if k not in _DOMAIN_PRIORITY_FIRST
    ]
    for bucket in ordered:
        cfg = _TAXONOMY.get(bucket, {})
        if any(sig.lower() in txt for sig in cfg.get("signals", [])):
            matched.append(bucket)
    return matched or ["uncategorised"]


def build_domain_heatmap(cards: list) -> dict:
    heat = {
        k: {"label": v["label"], "max_score": 0, "count": 0}
        for k, v in _TAXONOMY.items()
    }
    heat["uncategorised"] = {"label": "Other", "max_score": 0, "count": 0}
    for c in cards:
        for bucket in c.get("domains", ["uncategorised"]):
            if bucket not in heat:
                continue
            heat[bucket]["count"] += 1
            heat[bucket]["max_score"] = max(heat[bucket]["max_score"], c["risk_score"])
    return heat


def normalize_item_text(item):
    return " ".join([item.get("title", ""), item.get("summary", "")])


def cluster_items(items):
    clusters = {}
    cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
    for it in items:
        txt = normalize_item_text(it)
        match = cve_re.search(txt)
        if match:
            key = f"CLUSTER:CVE:{match.group(0).upper()}"
        else:
            dom = tldextract.extract(it["url"]).registered_domain or "unknown"
            key = f"CLUSTER:{dom}:{sha256(it.get('title', ''))[:10]}"
        clusters.setdefault(key, []).append(it)
    return clusters


def score_cluster(key, items):
    score = 0
    text = " ".join(normalize_item_text(i) for i in items).lower()
    if key.startswith("CLUSTER:CVE:"):
        score += 40
    if "exploit" in text or "in the wild" in text:
        score += 30
    if "poc" in text:
        score += 15
    if any(w in text for w in ("supply chain", "dependency", "package")):
        score += 20
    if any(w in text for w in ("kubernetes", "nginx", "openssl", "linux kernel")):
        score += 15
    return max(0, min(100, score))


def to_cluster_card(key, items):
    domains = []
    for it in items:
        for d in classify_domains(it):
            if d not in domains:
                domains.append(d)
    countries = list({it["country"] for it in items if it.get("country")})
    return {
        "id": sha256(key)[:12],
        "risk_score": score_cluster(key, items),
        "domains": domains,
        "countries": countries,
        "title": items[0]["title"][:140] if items else key,
        "summary": "",
        "sources": {
            "primary": [
                {"title": it["title"][:120], "url": it["url"]} for it in items[:5]
            ],
            "secondary": [],
        },
    }


_VALID_DOMAIN_KEYS = set(_TAXONOMY.keys()) | {"uncategorised"}

_HIGH_PROFILE_TARGETS: list = CONFIG.get("high_profile_targets", [])
_HP_LOWER: list = [t.lower() for t in _HIGH_PROFILE_TARGETS]


def _match_high_profile(text: str) -> list:
    """Return list of high-profile target names found in *text* (case-insensitive).

    Only targets that appear in the text are returned, so the output list is
    empty for niche/obscure findings and non-empty only when a well-known
    platform or package is explicitly mentioned.
    """
    tl = text.lower()
    return [_HIGH_PROFILE_TARGETS[i] for i, lw in enumerate(_HP_LOWER) if lw in tl]


def _findings_to_cards(findings: list, all_items: list = None) -> list:
    """Convert Groq findings into cluster-card dicts compatible with _write_index_html.

    Each finding's `references` list maps to `sources.primary` so the rendered
    Top Findings section shows cited article links beneath each Groq-authored note.

    all_items is used to:
    - Propagate country codes from the original feed items onto each finding
      (matched via the reference URLs Groq cited).
    - That in turn populates the Geography heatmap and world map.
    """
    # Build URL → country and registered-domain → country lookups from polled items.
    # Domain-based matching is the primary strategy because Groq's cited reference URLs
    # rarely match polled item URLs byte-for-byte (trailing slashes, query params, etc.).
    url_to_country: dict = {}
    domain_to_country: dict = {}
    # Also build CVE → patch/exploit status from polled items so we can annotate cards.
    cve_to_status: dict = {}
    if all_items:
        for it in all_items:
            cc = it.get("country", "")
            url = it.get("url", "")
            if cc and url:
                url_to_country[url] = cc
                dom = tldextract.extract(url).registered_domain
                if dom and dom not in domain_to_country:
                    domain_to_country[dom] = cc
            # Index patch/exploit status keyed by CVE ID extracted from item title
            for cve_id in _extract_cves(
                it.get("title", "") + " " + it.get("summary", "")
            ):
                existing = cve_to_status.get(cve_id, {})
                cve_to_status[cve_id] = {
                    "patch_available": existing.get("patch_available")
                    or it.get("patch_available", False),
                    "workaround_available": existing.get("workaround_available")
                    or it.get("workaround_available", False),
                    "exploited_in_wild": existing.get("exploited_in_wild")
                    or it.get("exploited_in_wild", False),
                }

    cards = []
    for f in findings:
        try:
            score = max(0, min(100, int(f.get("risk_score", 40))))
        except (ValueError, TypeError):
            score = 40

        # Validate Groq's domain keys — reject any key not in the taxonomy
        raw_domains = f.get("domains", [])
        domains = [d for d in raw_domains if d in _VALID_DOMAIN_KEYS]
        if not domains:
            domains = ["uncategorised"]

        refs = f.get("references", [])
        why_now = f.get("why_now", "")
        pri = f.get("priority", "")
        confidence = f.get("confidence", None)
        summary = f.get("summary", "")
        if why_now:
            summary = f"{summary} Why now: {why_now}".strip()
        if pri:
            summary = f"[{pri}] {summary}".strip()
        if isinstance(confidence, (int, float)):
            summary = f"{summary} (confidence: {max(0.0, min(1.0, float(confidence))):.2f})".strip()

        # Derive countries: try exact URL match first, fall back to registered domain.
        countries = list(
            {
                url_to_country.get(r["url"])
                or domain_to_country.get(
                    tldextract.extract(r.get("url", "")).registered_domain
                )
                for r in refs
                if r.get("url")
            }
            - {None}
        )

        # Derive patch_status from polled item data keyed on CVEs in the finding title.
        finding_cves = _extract_cves(f.get("title", "") + " " + f.get("summary", ""))
        patch_available = False
        workaround_available = False
        exploited_in_wild = False
        for cve_id in finding_cves:
            st = cve_to_status.get(cve_id, {})
            patch_available = patch_available or st.get("patch_available", False)
            workaround_available = workaround_available or st.get(
                "workaround_available", False
            )
            exploited_in_wild = exploited_in_wild or st.get("exploited_in_wild", False)
        if patch_available:
            patch_status = "patched"
        elif workaround_available:
            patch_status = "workaround"
        elif exploited_in_wild:
            patch_status = "no_fix"
        else:
            patch_status = "unknown"

        matched_targets = _match_high_profile(
            f.get("title", "") + " " + f.get("summary", "")
        )

        cards.append(
            {
                "id": sha256(f.get("title", str(len(cards))))[:12],
                "risk_score": score,
                "priority": f.get("priority", ""),
                "confidence": (
                    max(0.0, min(1.0, float(f.get("confidence", 0.0))))
                    if isinstance(f.get("confidence", None), (int, float))
                    else None
                ),
                "why_now": why_now,
                "recommended_actions_24h": f.get("recommended_actions_24h", []),
                "recommended_actions_7d": f.get("recommended_actions_7d", []),
                "domains": domains,
                "countries": countries,
                "title": f.get("title", "")[:140],
                "summary": summary,
                "patch_status": patch_status,
                "matched_targets": matched_targets,
                "sources": {
                    "primary": [
                        {
                            "title": r.get("title", r.get("url", ""))[:120],
                            "url": r.get("url", ""),
                        }
                        for r in refs
                        if r.get("url")
                    ],
                    "secondary": [],
                },
            }
        )
    return sorted(cards, key=lambda c: c["risk_score"], reverse=True)


# -----------------------------
# Delta comparison
# -----------------------------
def _compute_delta(current_cards: list, last_cards: list) -> dict:
    """Compare current run cards against previous run by CVE IDs in titles/summaries.
    Returns {"new": [...], "elevated": [...], "resolved": [...]}.
    Elevated cards carry an extra "_score_delta" key.
    On first run (empty last_cards) all current cards are classified as new.
    """

    def _cves(card: dict) -> set:
        raw = card.get("title", "") + " " + card.get("summary", "")
        return set(_extract_cves(raw))

    last_by_cve: dict = {}
    for c in last_cards:
        for cve in _cves(c):
            last_by_cve[cve] = c

    current_by_cve: dict = {}
    for c in current_cards:
        for cve in _cves(c):
            current_by_cve[cve] = c

    new_cards: list = []
    elevated_cards: list = []
    seen_titles: set = set()
    for c in current_cards:
        cvs = _cves(c)
        if not cvs:
            continue
        matched = next((last_by_cve[cv] for cv in cvs if cv in last_by_cve), None)
        title = c.get("title", "")
        if title in seen_titles:
            continue
        seen_titles.add(title)
        if matched is None:
            new_cards.append(c)
        else:
            diff = int(c.get("risk_score", 0)) - int(matched.get("risk_score", 0))
            if diff >= 10:
                elevated_cards.append({**c, "_score_delta": diff})

    resolved_cards: list = []
    seen_resolved: set = set()
    for cv, card in last_by_cve.items():
        if cv not in current_by_cve:
            title = card.get("title", "")
            if title not in seen_resolved:
                seen_resolved.add(title)
                resolved_cards.append(card)

    return {"new": new_cards, "elevated": elevated_cards, "resolved": resolved_cards}


# -----------------------------
# Dedup
# -----------------------------
def load_seen() -> set:
    d = load_json(SEEN_FILE, {"hashes": []})
    return set(d.get("hashes", []))


def _purge_seen_ttl(seen: set, ttl_days: int = 7) -> set:
    """Seen hashes carry no timestamp, so this caps the set at a rolling
    50 000-item window every run; a configurable hard cap acts as the TTL proxy."""
    ttl_cap = CONFIG.get("budgets", {}).get("seen_ttl_days", ttl_days)
    max_size = ttl_cap * 2000  # ~2 k items/day estimate; never grows forever
    if len(seen) > max_size:
        # keep only the most-recent slice (list ordering preserves insertion)
        return set(list(seen)[-max_size:])
    return seen


def save_seen(seen: set):
    seen = _purge_seen_ttl(seen)
    save_json(SEEN_FILE, {"hashes": list(seen)[-50_000:]})


def item_hash(item: dict) -> str:
    return sha256(item.get("url", "") + item.get("title", ""))


def deduplicate(items: list, seen: set):
    fresh = []
    for it in items:
        h = item_hash(it)
        if h in seen:
            continue
        seen.add(h)
        fresh.append(it)
    return fresh, seen


# -----------------------------
# Output rendering
# -----------------------------
def _heatmap_cell_color(max_score: int, count: int):
    if count == 0:
        return "#ebedf0", "#57606a"
    if max_score < 30:
        return "#c6e48b", "#24292e"
    if max_score < 60:
        return "#f9c74f", "#24292e"
    if max_score < 80:
        return "#f77f00", "#fff"
    return "#d62828", "#fff"


def _read_ledger_history(n: int = 20) -> list:
    """Return last N successful run entries from ledger.jsonl."""
    if not os.path.exists(LEDGER_FILE):
        return []
    entries = []
    with open(LEDGER_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
                if "error" not in obj and "counts" in obj:
                    entries.append(obj)
            except Exception:
                pass
    return entries[-n:]


# ──────────────────────────────────────────────
# Threat constellation map — Python-rendered SVG
# ──────────────────────────────────────────────


def _is_exploitish(c: dict) -> bool:
    """Return True if a card's text signals active exploitation."""
    t = f"{c.get('title', '')} {c.get('summary', '')}".lower()
    return any(
        k in t
        for k in (
            "exploit",
            "in the wild",
            "actively exploited",
            "known exploited",
            "zero-day",
        )
    )


def _derive_priority(card: dict) -> str:
    """Map an explicit priority tag or risk score to P1/P2/P3."""
    p = str(card.get("priority", "") or "").upper()
    if p in {"P1", "P2", "P3"}:
        return p
    rs = int(card.get("risk_score", 0))
    if rs >= 85:
        return "P1"
    if rs >= 60:
        return "P2"
    return "P3"


def _update_shelf(cards: list) -> None:
    """Update finding_shelf.json with persistence tracking and apply score boosts.

    Each finding is keyed by a 16-char hash of its title. For every card present
    in this run: first_seen is set if new, run_count incremented, last_seen updated.
    A score boost of +5 per run_count beyond 1 is applied, capped at +20, so a
    finding seen across 5 consecutive runs has its risk_score raised by 20 points.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    shelf: dict = load_json(FINDING_SHELF_FILE, {})
    current_ids: set = set()
    for card in cards:
        if not isinstance(card, dict):
            continue
        fid = card.get("id", sha256(card.get("title", ""))[:16])
        current_ids.add(fid)
        entry = shelf.get(fid)
        if entry is None:
            shelf[fid] = {
                "first_seen": today,
                "last_seen": today,
                "run_count": 1,
                "title": card.get("title", "")[:120],
            }
        else:
            # Only increment run_count once per calendar day
            if entry.get("last_seen") != today:
                entry["run_count"] = entry.get("run_count", 1) + 1
            entry["last_seen"] = today
            shelf[fid] = entry
        # Compute shelf_days and apply score boost in-place
        try:
            first_dt = datetime.strptime(shelf[fid]["first_seen"], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            shelf_days = max(0, (datetime.now(timezone.utc) - first_dt).days)
        except (ValueError, KeyError):
            shelf_days = 0
        run_count = shelf[fid].get("run_count", 1)
        boost = min(20, max(0, (run_count - 1) * 5))
        card["risk_score"] = min(100, int(card.get("risk_score", 0)) + boost)
        card["shelf_days"] = shelf_days
        card["run_count"] = run_count
    # Prune entries not seen in the last 30 days
    cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    shelf = {k: v for k, v in shelf.items() if v.get("last_seen", today) >= cutoff}
    save_json(FINDING_SHELF_FILE, shelf)


def _prune_old_briefings(reports_dir: str, keep_days: int = 10) -> None:
    """Delete briefing_*.jsonl and briefing_*.md files older than keep_days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    if not os.path.isdir(reports_dir):
        return
    for fname in os.listdir(reports_dir):
        if not fname.startswith("briefing_"):
            continue
        if not (fname.endswith(".jsonl") or fname.endswith(".md")):
            continue
        ext = ".jsonl" if fname.endswith(".jsonl") else ".md"
        stem = fname[len("briefing_") : -len(ext)]
        try:
            dt = datetime.strptime(stem, "%Y-%m-%d_%H-%M").replace(tzinfo=timezone.utc)
            if dt < cutoff:
                os.remove(os.path.join(reports_dir, fname))
        except Exception:
            pass


def _load_history_days(reports_dir: str, n: int = 7) -> list:
    """Scan briefing_*.jsonl files, group by ET date (UTC-5), return up to n days
    sorted newest-first.  Each entry: {date_str, ts_str, cards: [...]}.
    """
    ET_OFFSET = timedelta(hours=5)
    runs: list = []
    if not os.path.isdir(reports_dir):
        return []
    for fname in os.listdir(reports_dir):
        if not (fname.startswith("briefing_") and fname.endswith(".jsonl")):
            continue
        stem = fname[len("briefing_") : -len(".jsonl")]
        try:
            dt = datetime.strptime(stem, "%Y-%m-%d_%H-%M").replace(tzinfo=timezone.utc)
            runs.append((dt, os.path.join(reports_dir, fname)))
        except Exception:
            pass
    days_map: dict = {}
    for dt, fp in runs:
        et_date = (dt - ET_OFFSET).strftime("%Y-%m-%d")
        existing = days_map.get(et_date)
        if existing is None or dt > existing[0]:
            days_map[et_date] = (dt, fp)
    sorted_dates = sorted(days_map.keys(), reverse=True)[:n]
    result = []
    for date_str in sorted_dates:
        dt, fp = days_map[date_str]
        cards: list = []
        try:
            with open(fp, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        cards.append(json.loads(line.strip()))
                    except Exception:
                        pass
        except Exception:
            pass
        result.append(
            {
                "date_str": date_str,
                "ts_str": dt.strftime("%Y-%m-%d %H:%M UTC"),
                "cards": cards,
            }
        )
    return result


# -----------------------------
# P4: weekly aggregate helpers
# -----------------------------
def _rebuild_weekly_aggregate(reports_dir: str, days: list = None) -> dict:
    """Scan last 7 days of briefing JSONLs and build aggregate statistics."""
    if days is None:
        days = _load_history_days(reports_dir, n=7)
    cve_counts: dict = {}
    domain_set: set = set()
    total_cards = 0
    day_counts: dict = {}
    for day in days:
        date_str = day["date_str"]
        cards = day["cards"]
        total_cards += len(cards)
        day_counts[date_str] = len(cards)
        for c in cards:
            raw = c.get("title", "") + " " + c.get("summary", "")
            for cve in _extract_cves(raw):
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
            for d in c.get("domains", []):
                if d and d != "uncategorised":
                    domain_set.add(d)
    top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    most_active_day = max(day_counts, key=lambda k: day_counts[k]) if day_counts else ""
    existing = load_json(WEEKLY_AGGREGATE_FILE, {})
    return {
        "rebuilt_at": now_utc_iso(),
        "window_days": len(days),
        "total_cards": total_cards,
        "unique_cves": len(cve_counts),
        "active_domains": sorted(domain_set),
        "most_active_day": most_active_day,
        "day_counts": day_counts,
        "top_cves": [{"cve": k, "count": v} for k, v in top_cves],
        "weekly_summary": existing.get("weekly_summary", ""),
        "weekly_summary_ts": existing.get("weekly_summary_ts", ""),
    }


def groq_weekly_review(aggregate: dict) -> str:
    """Return a week-in-review paragraph, caching once per UTC day."""
    today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if aggregate.get("weekly_summary_ts") == today_utc and aggregate.get(
        "weekly_summary"
    ):
        return aggregate["weekly_summary"]
    if placeholder_mode() or not GROQ_API_KEY:
        return aggregate.get("weekly_summary", "")
    top_cves_txt = (
        ", ".join(
            f"{item['cve']} (\u00d7{item['count']})"
            for item in aggregate.get("top_cves", [])[:10]
        )
        or "none"
    )
    domains_txt = (
        ", ".join(
            _TAXONOMY.get(d, {}).get("label", d)
            for d in aggregate.get("active_domains", [])[:8]
        )
        or "none"
    )
    prompt = (
        "You are a senior infrastructure security analyst. "
        f"Write a single cohesive paragraph (90-130 words) summarising the security "
        f"landscape for the past {aggregate.get('window_days', 7)} days. "
        "Base your summary strictly on the data below — do not fabricate CVE IDs or events.\n\n"
        "Data:\n"
        f"- Total findings: {aggregate.get('total_cards', 0)}\n"
        f"- Unique CVEs tracked: {aggregate.get('unique_cves', 0)}\n"
        f"- Most frequently seen CVEs: {top_cves_txt}\n"
        f"- Active security domains: {domains_txt}\n"
        f"- Most active day: {aggregate.get('most_active_day', 'unknown')}\n\n"
        "Write professional, concise prose suitable for a CISO briefing. No bullet points. No headings. No preamble."
    )
    try:
        content, _ = groq_chat(
            [{"role": "user", "content": prompt}],
            CONFIG["model"]["name"],
            temperature=0.3,
            max_tokens=250,
        )
        print("[INFO] Weekly Groq review generated")
        return content.strip()
    except Exception as exc:
        print(f"[WARN] Weekly Groq review failed: {exc}")
        return aggregate.get("weekly_summary", "")


# -----------------------------
# Split-module bindings (prod path)
# -----------------------------
now_utc_iso = state_mod.now_utc_iso
sha256 = state_mod.sha256
load_json = state_mod.load_json
save_json = state_mod.save_json
append_jsonl = state_mod.append_jsonl
load_seen = lambda: state_mod.load_seen(SEEN_FILE)
save_seen = lambda seen: state_mod.save_seen(SEEN_FILE, seen)
bootstrap_seen = lambda: state_mod.bootstrap_seen_from_reports(REPORTS_DIR, SEEN_FILE)
item_hash = state_mod.item_hash
deduplicate = state_mod.deduplicate
_purge_seen_ttl = state_mod._purge_seen_ttl
_read_ledger_history = lambda n=20: state_mod._read_ledger_history(LEDGER_FILE, n)
_prune_old_briefings = state_mod._prune_old_briefings
_load_history_days = state_mod._load_history_days
_rebuild_weekly_aggregate = (
    lambda reports_dir, days=None: state_mod._rebuild_weekly_aggregate(
        reports_dir, WEEKLY_AGGREGATE_FILE, days=days
    )
)
_update_ioc_ledger = state_mod._update_ioc_ledger

_extract_cves = scoring_mod._extract_cves
_compact_text = scoring_mod._compact_text
_contains_any = scoring_mod._contains_any
classify_domains = scoring_mod.classify_domains
build_domain_heatmap = scoring_mod.build_domain_heatmap
cluster_items = scoring_mod.cluster_items
score_cluster = scoring_mod.score_cluster
to_cluster_card = scoring_mod.to_cluster_card
_heatmap_cell_color = scoring_mod._heatmap_cell_color
_is_exploitish = scoring_mod._is_exploitish
_derive_priority = scoring_mod._derive_priority

groq_chat = analysis_mod.groq_chat
groq_analyze_briefing = analysis_mod.groq_analyze_briefing
_findings_to_cards = analysis_mod._findings_to_cards
_compute_delta = analysis_mod._compute_delta
groq_weekly_review = analysis_mod.groq_weekly_review


_sparkline_svg = html_builder_mod._sparkline_svg
_TM_NODES = html_builder_mod._TM_NODES
_TM_EDGES = html_builder_mod._TM_EDGES
_build_threat_map_svg = html_builder_mod._build_threat_map_svg
_compute_velocity = html_builder_mod._compute_velocity
_build_domain_rank_html = html_builder_mod._build_domain_rank_html
_build_calendar_html = html_builder_mod._build_calendar_html
_build_history_accordion = html_builder_mod._build_history_accordion
_build_weekly_section = html_builder_mod._build_weekly_section
_build_enrichment_html = html_builder_mod._build_enrichment_html
_write_index_html = html_builder_mod._write_index_html
_build_forensics_html = html_builder_mod._build_forensics_html

# -----------------------------
# Run helpers
# -----------------------------
_CARD_REQUIRED_KEYS = {"id", "title", "risk_score", "domains", "sources"}


def _validate_cards(cards: list) -> int:
    """Warn for cards missing required schema fields. Returns failure count."""
    failures = 0
    for i, c in enumerate(cards):
        if not isinstance(c, dict):
            print(f"[WARN] Schema: card {i} is {type(c).__name__}, not dict")
            failures += 1
            continue
        missing = _CARD_REQUIRED_KEYS - set(c.keys())
        if missing:
            print(
                f"[WARN] Schema: card {i} ({str(c.get('title','?'))[:40]!r}) missing {missing}"
            )
            failures += 1
    if failures:
        print(f"[WARN] Schema validation: {failures}/{len(cards)} cards had issues")
    return failures


def _update_feed_health(health: dict, feed_id: str, ok: bool) -> None:
    """Update cumulative feed health counters in-place."""
    e = health.setdefault(
        feed_id,
        {
            "consecutive_ok": 0,
            "consecutive_fail": 0,
            "total_ok": 0,
            "total_calls": 0,
            "last_ok": None,
            "last_fail": None,
        },
    )
    e["total_calls"] = e.get("total_calls", 0) + 1
    if ok:
        e["consecutive_ok"] = e.get("consecutive_ok", 0) + 1
        e["consecutive_fail"] = 0
        e["total_ok"] = e.get("total_ok", 0) + 1
        e["last_ok"] = now_utc_iso()
    else:
        e["consecutive_fail"] = e.get("consecutive_fail", 0) + 1
        e["consecutive_ok"] = 0
        e["last_fail"] = now_utc_iso()


# -----------------------------
# Main
# -----------------------------
def _run():
    run_start = time.monotonic()
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)

    last_run_data = load_json(LAST_RUN_CARDS_FILE, {"ts": "", "cards": []})
    last_run_cards = last_run_data.get("cards", [])

    ignore = load_json(
        IGNORE_FILE, {"ignore_url": {}, "ignore_domain": {}, "ignore_url_prefix": {}}
    )
    n_bootstrapped = bootstrap_seen()
    if n_bootstrapped:
        print(
            f"[bootstrap] Reconstructed {n_bootstrapped} seen hashes from briefing history"
        )
    seen = load_seen()

    budgets = CONFIG["budgets"]
    since_hours = budgets.get("since_hours", 6)
    feeds_cfg = [f for f in CONFIG["feeds"] if f.get("enabled", True)]
    run_deadline = time.monotonic() + budgets["max_runtime_seconds"]

    feed_health = load_json(FEED_HEALTH_FILE, {})
    feed_run_metrics: dict = {}

    polled = []
    feed_workers = budgets.get("max_fetch_workers", 6)
    feeds_to_poll = feeds_cfg[: budgets["max_feeds_polled"]]

    def _poll_one(fcfg):
        fid = fcfg.get("id", fcfg.get("url", "?"))
        if time.monotonic() > run_deadline:
            return [], fid, 0
        t0 = time.monotonic()
        items = poll_feed(fcfg, since_hours, ignore)
        return items, fid, int((time.monotonic() - t0) * 1000)

    with ThreadPoolExecutor(max_workers=feed_workers) as pool:
        futs = [pool.submit(_poll_one, fcfg) for fcfg in feeds_to_poll]
        for fut in as_completed(futs):
            if time.monotonic() > run_deadline:
                print("[WARN] Runtime budget reached during feed polling")
                break
            try:
                items, feed_id, elapsed_ms = fut.result()
                polled.extend(items)
                ok = len(items) > 0 or placeholder_mode()
                feed_run_metrics[feed_id] = {
                    "ok": ok,
                    "count": len(items),
                    "elapsed_ms": elapsed_ms,
                }
                _update_feed_health(feed_health, feed_id, ok)
            except Exception as exc:
                print(f"[WARN] Feed poll task failed: {exc}")
    save_json(FEED_HEALTH_FILE, feed_health)

    polled, seen = deduplicate(polled, seen)
    polled = _merge_by_cve(polled)  # collapse same-CVE articles before Groq
    save_seen(seen)

    first_seen = now_utc_iso()
    for it in polled:
        it.setdefault("first_seen_at", first_seen)

    # Planner indirection removed: keep runtime path direct until model-driven
    # planning is introduced with explicit tests and contracts.

    enriched = []
    candidates = [it for it in polled if not is_ignored(ignore, it["url"])][
        : budgets["max_url_fetches"]
    ]

    def _enrich(item):
        if time.monotonic() > run_deadline:
            return None, None, None
        url = item["url"]
        try:
            text = fetch_url(url)
            item["extracted_text"] = text[:1500]
            item["extracted_text_hash"] = sha256(
                (item.get("title", "") + item.get("summary", ""))[:5000]
            )
            return item, None, None
        except Exception as ex:
            host = requests.utils.urlparse(url).hostname or ""
            url_ign = ("url", url) if "Non-HTTPS" in str(ex) else None
            dom_ign = ("domain", host) if "Executable content-type" in str(ex) else None
            return None, url_ign, dom_ign

    with ThreadPoolExecutor(max_workers=budgets.get("max_fetch_workers", 6)) as pool:
        futs = {pool.submit(_enrich, it): it for it in candidates}
        for fut in as_completed(futs):
            item, url_ign, dom_ign = fut.result()
            if item:
                enriched.append(item)
            if url_ign:
                add_ignore(ignore, url_ign[0], url_ign[1], 30)
            if dom_ign:
                add_ignore(ignore, dom_ign[0], dom_ign[1], 90)

    save_json(IGNORE_FILE, ignore)

    clusters = cluster_items(enriched or polled)
    cards = [to_cluster_card(k, v) for k, v in clusters.items()]
    cards = sorted(cards, key=lambda c: c["risk_score"], reverse=True)[
        : budgets["max_clusters_output"]
    ]

    # Groq: analyze KEV entries, NVD CVEs, and news articles as distinct inputs
    all_items = enriched or polled
    kev_items = [it for it in all_items if "known_exploited" in it.get("source", "")]
    nvd_items = [
        it for it in all_items if "services.nvd.nist.gov" in it.get("source", "")
    ]
    news_items = [
        it
        for it in all_items
        if "known_exploited" not in it.get("source", "")
        and "services.nvd.nist.gov" not in it.get("source", "")
    ]
    executive, findings, groq_status = groq_analyze_briefing(
        kev_items, nvd_items, news_items
    )
    print(
        f"[INFO] Groq status: {groq_status} | executive={'yes' if executive else 'no'} | findings={len(findings)}"
    )
    if findings:
        # Groq returned structured findings with cited article references
        cards = _findings_to_cards(findings, all_items=all_items)[
            : budgets["max_clusters_output"]
        ]
    else:
        # Fallback: use cluster cards with basic summaries (placeholder mode or Groq failure)
        for c in cards:
            if not c["summary"]:
                c["summary"] = f"{len(c['sources']['primary'])} related updates."

    delta = _compute_delta(cards, last_run_cards)
    print(
        f"[INFO] Delta: +{len(delta['new'])} new  "
        f"^{len(delta['elevated'])} elevated  "
        f"+{len(delta['resolved'])} resolved"
    )

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M")
    out_md = os.path.join(REPORTS_DIR, f"briefing_{ts}.md")
    out_jsonl = os.path.join(REPORTS_DIR, f"briefing_{ts}.jsonl")
    latest_md = os.path.join(REPORTS_DIR, "latest.md")
    index_html = os.path.join(REPORTS_DIR, "index.html")

    lines = [
        "---",
        f"generated_at: {now_utc_iso()}",
        f"model: {CONFIG['model']['name']}",
        "project: Watchtower",
        "---",
        "# Watchtower — Infrastructure Security Briefing",
        "",
    ]
    if executive:
        lines += ["## Analyst Summary", "", executive, ""]
    for c in cards:
        lines.append(f"## {c['title']} (risk: {c['risk_score']})")
        lines.append(c["summary"])
        lines.append("")
        for s in c["sources"]["primary"][: CONFIG["report"]["links_per_cluster_limit"]]:
            lines.append(f"- [{s['title']}]({s['url']})")
        lines.append("")

    md = "\n".join(lines)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(md)
    with open(latest_md, "w", encoding="utf-8") as f:
        f.write(md)
    _validate_cards(cards)
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for c in cards:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    run_metrics = {
        "elapsed_s": round(time.monotonic() - run_start, 1),
        "feeds_total": len(feeds_to_poll),
        "feeds_ok": sum(1 for m in feed_run_metrics.values() if m.get("ok")),
        "feeds_fail": sum(1 for m in feed_run_metrics.values() if not m.get("ok")),
        "items_polled": len(polled),
        "items_enriched": len(enriched),
        "groq_status": groq_status,
        "findings_count": len(findings),
        "cards_out": len(cards),
    }
    print(f"[INFO] Run metrics: {run_metrics}")

    heatmap = build_domain_heatmap(cards)

    hot_domains = [k for k, v in heatmap.items() if v["max_score"] >= 60]
    append_jsonl(
        LEDGER_FILE,
        {
            "ts": now_utc_iso(),
            "counts": {
                "feeds": len(feeds_cfg),
                "polled": len(polled),
                "enriched": len(enriched),
                "clusters": len(cards),
            },
            "hot_domains": hot_domains,
            "placeholder_mode": placeholder_mode(),
            "run_metrics": run_metrics,
        },
    )

    _update_shelf(cards)
    ioc_ledger = _update_ioc_ledger(cards, IOC_LEDGER_FILE)
    history = _read_ledger_history()
    _prune_old_briefings(REPORTS_DIR)
    history_days = _load_history_days(REPORTS_DIR)
    velocity = _compute_velocity(history_days)
    aggregate = _rebuild_weekly_aggregate(REPORTS_DIR, days=history_days)
    weekly_summary = groq_weekly_review(aggregate)
    _today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if weekly_summary and (
        weekly_summary != aggregate.get("weekly_summary")
        or aggregate.get("weekly_summary_ts") != _today_utc
    ):
        aggregate["weekly_summary"] = weekly_summary
        aggregate["weekly_summary_ts"] = _today_utc
        save_json(WEEKLY_AGGREGATE_FILE, aggregate)
    weekly_html = _build_weekly_section(aggregate)
    _write_index_html(
        index_html,
        cards,
        heatmap,
        ts,
        executive,
        history,
        since_hours=since_hours,
        groq_status=groq_status,
        delta=delta,
        history_days=history_days,
        weekly_html=weekly_html,
        feed_health=feed_health,
        run_metrics=run_metrics,
        feed_run_metrics=feed_run_metrics,
        velocity=velocity,
        ioc_ledger=ioc_ledger,
    )

    save_json(
        LAST_RUN_CARDS_FILE,
        {
            "ts": now_utc_iso(),
            "cards": [
                {
                    "title": c.get("title", "") if isinstance(c, dict) else str(c)[:50],
                    "risk_score": (
                        int(c.get("risk_score", 0)) if isinstance(c, dict) else 0
                    ),
                    "summary": (
                        c.get("summary", "")[:300] if isinstance(c, dict) else ""
                    ),
                    "cves": list(
                        _extract_cves(
                            (c.get("title", "") if isinstance(c, dict) else "")
                            + " "
                            + (c.get("summary", "") if isinstance(c, dict) else "")
                        )
                    ),
                }
                for c in cards
            ],
        },
    )

    print("### Watchtower run")
    print(f"UTC: {now_utc_iso()}")
    print(
        f"Feeds: {len(feeds_cfg)} Fresh: {len(polled)} Enriched: {len(enriched)} Clusters: {len(cards)}"
    )


def main():
    try:
        _run()
    except Exception as exc:
        os.makedirs(STATE_DIR, exist_ok=True)
        append_jsonl(LEDGER_FILE, {"ts": now_utc_iso(), "error": str(exc)})
        print(f"[ERROR] Watchtower run failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
