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
from agent import scoring as scoring_mod
from agent import state as state_mod

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


def _sparkline_svg(
    values: list, width: int = 80, height: int = 22, color: str = "#0366d6"
) -> str:
    if len(values) < 2:
        return f'<span style="font-size:.8rem;color:#57606a">{values[-1] if values else 0}</span>'
    mn, mx = min(values), max(values)
    rng = mx - mn or 1
    pad = 2
    step = width / max(len(values) - 1, 1)
    pts = " ".join(
        f"{i * step:.1f},{height - pad - (v - mn) / rng * (height - pad * 2):.1f}"
        for i, v in enumerate(values)
    )
    lx = (len(values) - 1) * step
    ly = height - pad - (values[-1] - mn) / rng * (height - pad * 2)
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"'
        f' style="vertical-align:middle;overflow:visible">'
        f'<polyline points="{pts}" fill="none" stroke="{color}"'
        f' stroke-width="1.5" stroke-linejoin="round"/>'
        f'<circle cx="{lx:.1f}" cy="{ly:.1f}" r="2.5" fill="{color}"/>'
        f"</svg>"
    )


# ──────────────────────────────────────────────
# Threat constellation map — Python-rendered SVG
# ──────────────────────────────────────────────

_TM_NODES: dict = {
    # key: (cx, cy, display_label)   — radial mesh, no dominant axis
    "ai_threat": (680, 68, "AI / ML Threats"),
    "identity": (534, 132, "Identity / Auth"),
    "ca_trust": (345, 184, "CA / PKI"),
    "cloud_iam": (737, 197, "Cloud / IAM"),
    "crypto_lib": (180, 329, "Crypto Libs"),
    "web_framework": (478, 342, "Web / Servers"),
    "container": (659, 360, "Containers"),
    "browser_ext": (847, 307, "Browser Ext"),
    "os_kernel": (337, 460, "OS / Kernel"),
    "supply_chain": (119, 471, "Supply Chain"),
    "pkg_npm": (221, 583, "npm / Node"),
    "pkg_pypi": (381, 609, "PyPI / Python"),
    "pkg_maven": (534, 623, "Maven / Java"),
    "pkg_nuget": (690, 570, ".NET / NuGet"),
    "pkg_gem": (806, 473, "RubyGems"),
    "uncategorised": (858, 171, "Other"),
}

_TM_EDGES: list = [
    ("ai_threat", "cloud_iam"),
    ("ai_threat", "supply_chain"),
    ("ai_threat", "identity"),
    ("supply_chain", "pkg_npm"),
    ("supply_chain", "pkg_pypi"),
    ("supply_chain", "pkg_maven"),
    ("supply_chain", "pkg_nuget"),
    ("supply_chain", "pkg_gem"),
    ("supply_chain", "cloud_iam"),
    ("supply_chain", "identity"),
    ("pkg_npm", "web_framework"),
    ("pkg_npm", "os_kernel"),
    ("pkg_pypi", "web_framework"),
    ("pkg_maven", "web_framework"),
    ("pkg_nuget", "web_framework"),
    ("pkg_gem", "web_framework"),
    ("pkg_gem", "container"),
    ("web_framework", "os_kernel"),
    ("web_framework", "container"),
    ("web_framework", "cloud_iam"),
    ("web_framework", "identity"),
    ("os_kernel", "crypto_lib"),
    ("os_kernel", "container"),
    ("container", "cloud_iam"),
    ("container", "crypto_lib"),
    ("cloud_iam", "identity"),
    ("cloud_iam", "ca_trust"),
    ("identity", "ca_trust"),
    ("identity", "browser_ext"),
    ("ca_trust", "crypto_lib"),
    ("browser_ext", "cloud_iam"),
    ("browser_ext", "ca_trust"),
]


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


def _build_threat_map_svg(cards: list, heatmap: dict, velocity: dict = None) -> str:
    """Return an inline SVG constellation threat map, heat-coloured by domain activity."""
    # Raw per-domain heat score
    raw: dict[str, int] = {}
    for key in _TM_NODES:
        sub = [c for c in cards if key in c.get("domains", [])]
        cnt = len(sub)
        mx = max((c.get("risk_score", 0) for c in sub), default=0)
        p1 = sum(1 for c in sub if str(c.get("priority", "")).upper() == "P1")
        ex = sum(1 for c in sub if _is_exploitish(c))
        raw[key] = min(
            100,
            round(
                cnt * 8
                + mx * 0.55
                + (p1 / cnt * 24 if cnt else 0)
                + (ex / cnt * 18 if cnt else 0)
            ),
        )

    # Ambient heat: neighbours bleed 20 % of their score
    nbrs: dict[str, list] = {k: [] for k in _TM_NODES}
    for a, b in _TM_EDGES:
        if a in nbrs and b in nbrs:
            nbrs[a].append(b)
            nbrs[b].append(a)
    scores: dict[str, int] = {}
    for key in _TM_NODES:
        nb_max = max((raw[n] for n in nbrs[key] if n in raw), default=0)
        scores[key] = max(raw[key], int(nb_max * 0.08))

    def _heat(s: int):
        """Dark-center aura: outer bloom behind opaque disc, edge ring on perimeter."""
        t = max(0.06, s / 100.0)
        bloom_op = round(0.18 + t * 0.55, 3)  # outer aura fill: 0.18 → 0.73
        ring_op = round(0.35 + t * 0.50, 3)  # edge ring stroke: 0.35 → 0.85
        if s >= 85:
            bloom = f"rgba(255,40,40,{bloom_op})"
            ring = f"rgba(255,80,80,{ring_op})"
        else:
            bloom = f"rgba(200,200,200,{bloom_op})"
            ring = f"rgba(220,220,220,{ring_op})"
        return bloom, ring

    def _edge_style(sa: int, sb: int):
        s = max(sa, sb)
        t = min(1.0, s / 100.0)
        glow_op = round(0.10 + t * 0.40, 3)  # blurred glow behind: 0.10 → 0.50
        line_op = round(0.18 + t * 0.45, 3)  # crisp line on top:   0.18 → 0.63
        return glow_op, line_op

    W, H = 960, 760
    p: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
        'preserveAspectRatio="xMidYMid meet" '
        'style="width:100%;height:auto;display:block;background:#0a0a0a;border-radius:8px;border:1px solid #333">',
        "<defs>",
        '<filter id="f-outer" x="-300%" y="-300%" width="700%" height="700%">'
        '<feGaussianBlur stdDeviation="18"/>'
        "</filter>",
        '<filter id="f-mid" x="-150%" y="-150%" width="400%" height="400%">'
        '<feGaussianBlur stdDeviation="7"/>'
        "</filter>",
        '<filter id="edge-glow" x="-100%" y="-100%" width="300%" height="300%">'
        '<feGaussianBlur stdDeviation="4"/>'
        "</filter>",
        "</defs>",
    ]
    # Subtle background grid dots
    p.append('<g opacity="0.03">')
    for gx in range(44, W, 62):
        for gy in range(32, H, 62):
            p.append(f'<circle cx="{gx}" cy="{gy}" r="1" fill="#666"/>')
    p.append("</g>")

    # Edges — glow pass first (behind), crisp line pass on top
    for a, b in _TM_EDGES:
        if a not in _TM_NODES or b not in _TM_NODES:
            continue
        ax, ay, _ = _TM_NODES[a]
        bx, by, _ = _TM_NODES[b]
        glow_op, _ = _edge_style(scores[a], scores[b])
        p.append(
            f'<line x1="{ax}" y1="{ay}" x2="{bx}" y2="{by}" '
            f'stroke="rgba(150,150,150,{glow_op:.3f})" stroke-width="4.5" '
            f'stroke-linecap="round" filter="url(#edge-glow)"/>'
        )
    for a, b in _TM_EDGES:
        if a not in _TM_NODES or b not in _TM_NODES:
            continue
        ax, ay, _ = _TM_NODES[a]
        bx, by, _ = _TM_NODES[b]
        _, line_op = _edge_style(scores[a], scores[b])
        p.append(
            f'<line x1="{ax}" y1="{ay}" x2="{bx}" y2="{by}" '
            f'stroke="rgba(180,180,180,{line_op:.3f})" stroke-width="1.0" '
            f'stroke-linecap="round"/>'
        )

    # Nodes
    node_id = 0
    _vel = velocity or {}
    for key, (cx, cy, lbl) in _TM_NODES.items():
        s = scores[key]
        outer, ring_color = _heat(s)
        R = 24
        lf = "#e6e6e6" if s >= 20 else "#888"
        _accel_glow = (
            f'<circle cx="{cx}" cy="{cy}" r="{R+20}" '
            f'fill="rgba(220,120,30,0.09)" filter="url(#f-outer)"/>'
            if _vel.get(key) == "\u2191\u21911"
            else ""
        )

        p.append(
            f'<g class="tm-node" data-domain="{key}" '
            f'onclick="selectDomain(\'{key}\')" style="cursor:pointer">'
        )
        # Velocity acceleration glow (orange halo for accelerating domains)
        if _accel_glow:
            p.append(_accel_glow)
        # Layer 1: Outer aura — large fill, heavy blur, sits BEHIND disc
        p.append(
            f'<circle cx="{cx}" cy="{cy}" r="{R+14}" fill="{outer}" filter="url(#f-outer)"/>'
        )
        # Layer 2: Opaque dark disc — covers center so only perimeter glow shows
        p.append(
            f'<circle class="node-disc" cx="{cx}" cy="{cy}" r="{R}" '
            f'fill="rgba(15,15,15,0.95)" stroke="rgba(100,100,100,0.20)" stroke-width="0.6"/>'
        )
        # Layer 3: Edge ring — stroke-only at disc radius, medium blur, glows outward from rim
        p.append(
            f'<circle cx="{cx}" cy="{cy}" r="{R}" '
            f'fill="none" stroke="{ring_color}" stroke-width="3.5" filter="url(#f-mid)"/>'
        )
        # Selection ring — simple white ring, hidden at rest
        p.append(
            f'<circle class="sel-indicator" cx="{cx}" cy="{cy}" r="{R+5}" '
            f'fill="none" stroke="rgba(255,255,255,0.65)" stroke-width="1.5"/>'
        )
        # Label
        ly = cy + R + 13
        p.append(
            f'<text x="{cx}" y="{ly}" text-anchor="middle" '
            f'font-family="system-ui,sans-serif" font-size="10" font-weight="600" '
            f'fill="{lf}" stroke="#0f0f0f" stroke-width="2.5" paint-order="stroke fill">{lbl}</text>'
        )
        p.append("</g>")
        node_id += 1

    p.append("</svg>")
    return "\n".join(p)


def _compute_velocity(history_days: list) -> dict:
    """Return {domain_key: accel_label} for domains with notable acceleration.
    accel_label is one of '\u2191\u21911', '\u21911', '\u21931' (rising fast, rising, falling).
    Requires at least 4 days of history; returns {} otherwise.
    """
    if not history_days or len(history_days) < 4:
        return {}
    # history_days is sorted newest-first; take up to 7
    days = list(reversed(history_days[:7]))  # oldest-first for computation
    domain_series: dict = {k: [] for k in _TM_NODES}
    for day in days:
        day_cards = day.get("cards", [])
        for key in domain_series:
            domain_series[key].append(
                sum(1 for c in day_cards if key in c.get("domains", []))
            )
    result = {}
    for key, series in domain_series.items():
        if len(series) < 4:
            continue
        recent = sum(series[-2:]) / 2
        prior = sum(series[-4:-2]) / 2
        delta = recent - prior
        if delta >= 3:
            result[key] = "\u2191\u21911"  # ↑↑
        elif delta >= 1.5:
            result[key] = "\u21911"  # ↑
        elif delta <= -1.5:
            result[key] = "\u21931"  # ↓
    return result


def _build_domain_rank_html(cards: list, heatmap: dict, velocity: dict = None) -> str:
    """Ranked domain bar list for the threat map side panel."""
    velocity = velocity or {}
    rows: list[str] = []
    domain_scores: list[tuple] = []
    for key, (_, _, lbl) in _TM_NODES.items():
        sub = [c for c in cards if key in c.get("domains", [])]
        cnt = len(sub)
        mx = max((c.get("risk_score", 0) for c in sub), default=0)
        p1 = sum(1 for c in sub if str(c.get("priority", "")).upper() == "P1")
        ex = sum(1 for c in sub if _is_exploitish(c))
        sc = min(
            100,
            round(
                cnt * 8
                + mx * 0.55
                + (p1 / cnt * 24 if cnt else 0)
                + (ex / cnt * 18 if cnt else 0)
            ),
        )
        domain_scores.append((sc, cnt, key, lbl))

    domain_scores.sort(reverse=True)
    bar_colors = ["#1c2e42", "#223450", "#283e5e", "#2e4a6e", "#5a1a1a"]

    for sc, cnt, key, lbl in domain_scores:
        if sc == 0 and cnt == 0:
            continue
        pct = sc
        bidx = 0 if sc < 18 else 1 if sc < 38 else 2 if sc < 62 else 3 if sc < 82 else 4
        bcol = bar_colors[bidx]
        lc = "#8a3030" if sc >= 85 else "#6a8898"
        vc = "#5a2020" if sc >= 85 else "#3a5568"
        vel = velocity.get(key, "")
        vel_html = (
            f'<span class="vel-chip vel-up2" title="Accelerating">{vel}</span>'
            if vel == "\u2191\u21911"
            else (
                f'<span class="vel-chip vel-up1" title="Rising">{vel}</span>'
                if vel == "\u21911"
                else (
                    f'<span class="vel-chip vel-dn" title="Falling">{vel}</span>'
                    if vel == "\u21931"
                    else ""
                )
            )
        )
        rows.append(
            f'<div class="rank-row" onclick="selectDomain(\'{key}\')">'
            f'<span class="rank-label" style="color:{lc}" title="{lbl}">{lbl}</span>'
            f'<div class="rank-bar-wrap"><div class="rank-bar" style="width:{pct}%;background:{bcol}"></div></div>'
            f'{vel_html}<span class="rank-val" style="color:{vc}">{sc}</span>'
            f"</div>"
        )
    if not rows:
        return '<div class="muted" style="font-size:.78rem;padding:.4rem 0">No active findings in this window.</div>'
    total = len(cards)
    all_row = (
        f'<div class="rank-row rank-row-all" onclick="selectDomain(\'all\')" style="border-bottom:1px solid #252525;margin-bottom:.35rem;padding-bottom:.35rem">'
        f'<span class="rank-label" style="color:#c9d1d9;font-weight:700">All Domains</span>'
        f'<div class="rank-bar-wrap"></div>'
        f'<span class="rank-val" style="color:#c9d1d9;font-weight:700">{total}</span>'
        f"</div>"
    )
    return all_row + "".join(rows)


# -----------------------------
# P3: 7-day history helpers
# -----------------------------
def _build_calendar_html(history_days: list) -> str:
    """Build a 14-cell threat heatmap calendar from history_days (newest-first)."""
    if not history_days:
        return ""
    # Build a lookup: date_str -> {max_risk, count, p1}
    day_map: dict = {}
    for day in history_days:
        ds = day.get("date_str", "")
        cards = day.get("cards", [])
        if not ds:
            continue
        day_map[ds] = {
            "max_risk": max((c.get("risk_score", 0) for c in cards), default=0),
            "count": len(cards),
            "p1": sum(1 for c in cards if _derive_priority(c) == "P1"),
        }
    # Produce cells for the last 14 days (today back), oldest→newest
    today = (datetime.now(timezone.utc) - timedelta(hours=5)).date()
    cells = []
    for i in range(13, -1, -1):
        d = today - timedelta(days=i)
        ds = d.strftime("%Y-%m-%d")
        info = day_map.get(ds)
        if not info:
            color = "#1a1a1a"
            border = "#252525"
            tip = f"{ds} — no data"
        else:
            risk = info["max_risk"]
            count = info["count"]
            p1 = info["p1"]
            tip = f"{ds} · {count} finding{'s' if count != 1 else ''}"
            if p1:
                tip += f" · {p1} P1"
            tip += f" · peak risk {risk}"
            if risk >= 80:
                color, border = "rgba(170,28,28,.55)", "rgba(220,50,50,.4)"
            elif risk >= 60:
                color, border = "rgba(158,106,3,.50)", "rgba(210,153,34,.4)"
            elif risk >= 30:
                color, border = "rgba(30,80,160,.50)", "rgba(58,130,246,.4)"
            else:
                color, border = "rgba(35,90,35,.45)", "rgba(56,160,56,.35)"
        label = d.strftime("%d")
        cells.append(
            f'<div class="cal-cell" style="background:{color};border:1px solid {border}" '
            f'title="{tip}" aria-label="{tip}">'
            f'<span class="cal-day">{label}</span>'
            f"</div>"
        )
    month_labels = ""
    prev_month = ""
    for i in range(13, -1, -1):
        d = today - timedelta(days=i)
        m = d.strftime("%b")
        if m != prev_month:
            month_labels += (
                f'<span class="cal-month-label" style="grid-column:span 1">{m}</span>'
            )
            prev_month = m
        else:
            month_labels += '<span class="cal-month-label"></span>'
    return (
        '<section class="cal-section">'
        '<div class="cal-header">'
        '<span class="cal-title">14-Day Threat Heatmap</span>'
        '<span class="cal-legend">'
        '<span class="cal-legend-item" style="background:rgba(170,28,28,.55)">80+</span>'
        '<span class="cal-legend-item" style="background:rgba(158,106,3,.5)">60+</span>'
        '<span class="cal-legend-item" style="background:rgba(30,80,160,.5)">30+</span>'
        '<span class="cal-legend-item" style="background:rgba(35,90,35,.45)">&lt;30</span>'
        '<span class="cal-legend-item" style="background:#1a1a1a">—</span>'
        "</span>"
        "</div>"
        f'<div class="cal-grid">{"" .join(cells)}</div>'
        "</section>"
    )


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


def _build_history_accordion(days: list, today_str: str = "") -> str:
    """Build a 7-day briefing history accordion `<section>` element."""
    if not days:
        return (
            '<div class="history-panel muted" style="font-size:.78rem;padding:.4rem 0">'
            "No briefing history available yet.</div>"
        )
    items: list[str] = []
    for day in days:
        date_str = day["date_str"]
        ts_str = day["ts_str"]
        cards = day["cards"]
        count = len(cards)
        p1 = sum(1 for c in cards if _derive_priority(c) == "P1")
        exploited = sum(1 for c in cards if _is_exploitish(c))
        meta_parts = [f"{count} finding{'s' if count != 1 else ''}"]
        if p1:
            meta_parts.append(f"P1: {p1}")
        if exploited:
            meta_parts.append(f"exploited: {exploited}")
        meta_txt = " \u00b7 ".join(meta_parts)
        trows_list: list[str] = []
        for c in sorted(cards, key=lambda x: int(x.get("risk_score", 0)), reverse=True):
            pri = _derive_priority(c)
            pri_cls = "p1" if pri == "P1" else "p2" if pri == "P2" else "p3"
            ps = c.get("patch_status", "unknown")
            ps_cls = (
                "patch-badge--fixed"
                if ps == "patched"
                else (
                    "patch-badge--workaround"
                    if ps == "workaround"
                    else (
                        "patch-badge--no-fix"
                        if ps == "no_fix"
                        else "patch-badge--unknown"
                    )
                )
            )
            trows_list.append(
                "<tr>"
                f'<td class="ha-title">{html.escape(c.get("title", "")[:80])}</td>'
                f'<td class="ha-risk">{int(c.get("risk_score", 0))}</td>'
                f'<td class="ha-pri"><span class="priority {pri_cls}">{pri}</span></td>'
                f'<td class="ha-ps"><span class="patch-badge {ps_cls}" style="font-size:.58rem">{ps.replace("_"," ")}</span></td>'
                "</tr>"
            )
        trows = "".join(trows_list)
        open_attr = " open" if date_str == today_str else ""
        items.append(
            f'<details class="ha-day"{open_attr}>'
            f'<summary class="ha-summary">'
            f'<span class="ha-date">{html.escape(date_str)}</span>'
            f'<span class="ha-meta">{html.escape(meta_txt)}</span>'
            f'<span class="ha-ts">{html.escape(ts_str)}</span>'
            f"</summary>"
            f'<div class="ha-body">'
            f'<table class="ha-table"><thead><tr><th>Finding</th><th>Risk</th><th>Pri</th><th>Patch</th></tr></thead>'
            f"<tbody>{trows}</tbody></table>"
            f"</div>"
            f"</details>"
        )
    return (
        '<section class="panel ha-section">'
        '<h3 style="margin:.2rem 0 .5rem">7-Day Briefing History</h3>'
        + "".join(items)
        + "</section>"
    )


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


def _build_weekly_section(aggregate: dict) -> str:
    """Build the weekly scope <section> HTML block."""
    if not aggregate or aggregate.get("total_cards", 0) == 0:
        return ""
    total = aggregate.get("total_cards", 0)
    unique_cves = aggregate.get("unique_cves", 0)
    n_domains = len(aggregate.get("active_domains", []))
    most_active = aggregate.get("most_active_day", "\u2014")
    window = aggregate.get("window_days", 7)
    summary_txt = aggregate.get("weekly_summary", "")
    top_cves = aggregate.get("top_cves", [])
    max_count = top_cves[0]["count"] if top_cves else 1
    cve_rows = "".join(
        "<tr>"
        f'<td class="wcve-id">{html.escape(item["cve"])}</td>'
        f'<td class="wcve-bar-cell"><div class="wcve-bar-inner" style="width:{min(100, round(item["count"] / max_count * 100))}%"></div></td>'
        f'<td class="wcve-count">{item["count"]}</td>'
        "</tr>"
        for item in top_cves
    )
    summary_html = (
        f'<p class="weekly-review-text">{html.escape(summary_txt)}</p>'
        if summary_txt
        else '<p class="weekly-review-text muted">Week-in-review will appear after the next Groq analysis.</p>'
    )
    cve_block = (
        (
            '<details class="wcve-details">'
            f"<summary>Top CVEs this week ({len(top_cves)} tracked)</summary>"
            '<table class="wcve-table"><thead><tr>'
            "<th>CVE</th><th>Frequency</th><th>#</th>"
            "</tr></thead>"
            f"<tbody>{cve_rows}</tbody></table>"
            "</details>"
        )
        if top_cves
        else ""
    )
    return (
        '<section class="panel weekly-scope">'
        f'<h3 style="margin:.2rem 0 .6rem">{window}-Day Weekly Scope</h3>'
        '<div class="weekly-kpi-row">'
        f'<div class="wkpi"><span class="wk">Total Findings</span><span class="wv">{total}</span></div>'
        f'<div class="wkpi"><span class="wk">Unique CVEs</span><span class="wv">{unique_cves}</span></div>'
        f'<div class="wkpi"><span class="wk">Active Domains</span><span class="wv">{n_domains}</span></div>'
        f'<div class="wkpi"><span class="wk">Most Active Day</span><span class="wv wv-sm">{html.escape(most_active)}</span></div>'
        "</div>"
        '<div class="weekly-review-label">Week-in-Review</div>'
        + summary_html
        + cve_block
        + "</section>"
    )


def _build_enrichment_html(enrichment: dict) -> str:
    """Build a collapsed 'Extracted context' block from zero-token source enrichment data."""
    if not enrichment or enrichment.get("source_count", 0) == 0:
        return ""
    parts: list = []
    lede = enrichment.get("lede", "")
    if lede:
        parts.append(
            f'<p class="enrich-lede">{html.escape(lede)}</p>'
        )
    all_cves = enrichment.get("cves", [])
    extra_cves = enrichment.get("extra_cves", [])
    if all_cves:
        chips = "".join(
            f'<span class="enrich-cve{" enrich-cve--extra" if c in extra_cves else ""}">{html.escape(c)}</span>'
            for c in all_cves[:10]
        )
        parts.append(f'<div class="enrich-row"><span class="enrich-label">CVEs</span>{chips}</div>')
    products = enrichment.get("products", [])
    if products:
        chips = "".join(
            f'<span class="enrich-product">{html.escape(p)}</span>'
            for p in products[:8]
        )
        parts.append(f'<div class="enrich-row"><span class="enrich-label">Affected</span>{chips}</div>')
    versions = enrichment.get("versions", [])
    if versions:
        chips = "".join(
            f'<span class="enrich-version">{html.escape(v)}</span>'
            for v in versions[:6]
        )
        parts.append(f'<div class="enrich-row"><span class="enrich-label">Versions</span>{chips}</div>')
    dates = enrichment.get("dates", [])
    if dates:
        chips = "".join(
            f'<span class="enrich-date">{html.escape(d)}</span>'
            for d in dates[:4]
        )
        parts.append(f'<div class="enrich-row"><span class="enrich-label">Dates</span>{chips}</div>')
    if not parts:
        return ""
    src_count = enrichment.get("source_count", 0)
    inner = "".join(parts)
    return (
        f'<details class="enrich-block">'
        f'<summary class="enrich-summary">&#128269; Extracted context '
        f'<span class="enrich-src-count">{src_count} source{"s" if src_count != 1 else ""}</span>'
        f'</summary>'
        f'<div class="enrich-body">{inner}</div>'
        f'</details>'
    )


def _write_index_html(
    path: str,
    cards: list,
    heatmap: dict,
    ts: str,
    executive: str = "",
    history: list = None,
    since_hours: int = 6,
    groq_status: str = "unknown",
    delta: dict = None,
    history_days: list = None,
    weekly_html: str = "",
    feed_health: dict = None,
    run_metrics: dict = None,
    feed_run_metrics: dict = None,
    velocity: dict = None,
):
    # KPI stats
    total_findings = len(cards)
    p1_count = sum(1 for c in cards if _derive_priority(c) == "P1")
    exploited_count = sum(1 for c in cards if _is_exploitish(c))
    hp_count = sum(1 for c in cards if c.get("matched_targets"))
    control_plane_count = sum(
        1
        for c in cards
        if any(
            d in c.get("domains", []) for d in ("cloud_iam", "identity", "supply_chain")
        )
    )
    top_domain_key = (
        max(
            heatmap.keys(),
            key=lambda k: (heatmap[k].get("max_score", 0), heatmap[k].get("count", 0)),
        )
        if heatmap
        else "uncategorised"
    )
    top_domain_label = heatmap.get(top_domain_key, {}).get("label", "Other")

    trend_txt = "—"
    if history and len(history) >= 2:
        a = history[-2]["counts"]["clusters"]
        b = history[-1]["counts"]["clusters"]
        _trend_delta = b - a
        trend_txt = f"{_trend_delta:+d}"

    kpi_html = f"""
        <section class="kpi-grid">
            <div class="kpi"><span class="k">Findings</span><span class="v">{total_findings}</span></div>
            <div class="kpi"><span class="k">P1</span><span class="v">{p1_count}</span></div>
            <div class="kpi"><span class="k">Exploited</span><span class="v">{exploited_count}</span></div>
            <div class="kpi"><span class="k">High-Profile</span><span class="v">{hp_count}</span></div>
            <div class="kpi"><span class="k">Control Plane</span><span class="v">{control_plane_count}</span></div>
            <div class="kpi"><span class="k">Top Domain</span><span class="v v-sm">{html.escape(top_domain_label)}</span></div>
            <div class="kpi"><span class="k">Trend 24h</span><span class="v">{trend_txt}</span></div>
        </section>
        """

    # Feed contribution from cited source links (includes newly added feeds as domains appear)
    feed_rollup: dict = {}
    for c in cards:
        rs = int(c.get("risk_score", 0))
        for s in c.get("sources", {}).get("primary", []):
            dom = tldextract.extract(s.get("url", "")).registered_domain or "unknown"
            cur = feed_rollup.setdefault(dom, {"count": 0, "max_score": 0})
            cur["count"] += 1
            cur["max_score"] = max(cur["max_score"], rs)
    top_feeds = sorted(
        feed_rollup.items(),
        key=lambda kv: (kv[1]["count"], kv[1]["max_score"]),
        reverse=True,
    )[:10]
    feed_rows = "".join(
        f"<tr><td>{html.escape(dom)}</td><td>{vals['count']}</td><td>{vals['max_score']}</td></tr>"
        for dom, vals in top_feeds
    )

    # --- Run metrics bar and per-feed health table ---
    _fh = feed_health or {}
    _rm = run_metrics or {}
    _frm = feed_run_metrics or {}
    _rm_elapsed = _rm.get("elapsed_s", "—")
    _rm_ok = _rm.get("feeds_ok", "—")
    _rm_total = _rm.get("feeds_total", "—")
    _rm_fail = _rm.get("feeds_fail", "—")
    _rm_groq = _rm.get("groq_status", "—")
    _rm_items = _rm.get("items_polled", "—")
    run_metrics_html = (
        (
            f'<div class="run-metrics-bar">'
            f'<span class="rm-chip">⏱ {_rm_elapsed}s</span>'
            f'<span class="rm-chip rm-ok">✓ {_rm_ok}/{_rm_total} feeds</span>'
            f'<span class="rm-chip rm-fail">✗ {_rm_fail} failed</span>'
            f'<span class="rm-chip">📡 {_rm_items} items</span>'
            f'<span class="rm-chip">AI: {_rm_groq}</span>'
            f"</div>"
        )
        if _rm
        else ""
    )
    health_rows = ""
    for fid, fmeta in sorted(_frm.items()):
        hist = _fh.get(fid, {})
        total_calls = max(hist.get("total_calls", 1), 1)
        total_ok = hist.get("total_ok", 0)
        reliability = round(total_ok / total_calls * 100)
        consec_fail = hist.get("consecutive_fail", 0)
        status_dot = "🔴" if consec_fail >= 3 else "🟡" if consec_fail >= 1 else "🟢"
        health_rows += (
            f"<tr>"
            f"<td>{status_dot} {html.escape(fid)}</td>"
            f"<td>{fmeta.get('count', 0)}</td>"
            f"<td>{reliability}%</td>"
            f"<td>{fmeta.get('elapsed_ms', 0)}ms</td>"
            f"</tr>"
        )

    threat_svg = _build_threat_map_svg(cards, heatmap, velocity=velocity)
    domain_rank_html = _build_domain_rank_html(cards, heatmap, velocity=velocity)

    _today_et = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%d")
    history_section = _build_history_accordion(history_days or [], today_str=_today_et)
    calendar_html = _build_calendar_html(history_days or [])

    # --- Delta strip ---
    delta_strip_html = ""
    resolved_drawer_html = ""
    if delta is not None:
        n_new = len(delta.get("new", []))
        n_elev = len(delta.get("elevated", []))
        n_res = len(delta.get("resolved", []))
        if n_new == 0 and n_elev == 0 and n_res == 0:
            delta_strip_html = (
                '<div class="delta-strip">'
                '<span class="delta-chip delta-chip--quiet">No changes from previous run</span>'
                "</div>"
            )
        else:
            chips = []
            if n_new:
                chips.append(
                    f'<span class="delta-chip delta-chip--new">+{n_new}&nbsp;New</span>'
                )
            if n_elev:
                chips.append(
                    f'<span class="delta-chip delta-chip--elevated">{n_elev}&nbsp;Elevated</span>'
                )
            if n_res:
                chips.append(
                    f'<span class="delta-chip delta-chip--resolved">{n_res}&nbsp;Resolved</span>'
                )
            delta_strip_html = f'<div class="delta-strip">{"  ".join(chips)}</div>'
        if delta.get("resolved"):
            res_rows = "".join(
                f'<tr><td>{html.escape(c.get("title", "")[:90])}</td>'
                f'<td style="text-align:right;padding-right:.6rem">{int(c.get("risk_score", 0))}</td></tr>'
                for c in delta["resolved"]
            )
            resolved_drawer_html = (
                f'<details class="resolved-drawer">'
                f"<summary>{n_res} resolved since previous run</summary>"
                f'<table><thead><tr><th>Finding</th><th style="text-align:right">Prev&nbsp;risk</th></tr></thead>'
                f"<tbody>{res_rows}</tbody></table></details>"
            )

    # --- High-profile target panel (only rendered when matches exist) ---
    hp_panel_html = ""
    if hp_count:
        # Collect all matched targets across cards, count occurrences, sort by count desc
        from collections import Counter

        target_counter: Counter = Counter()
        for c in cards:
            for t in c.get("matched_targets", []):
                target_counter[t] += 1
        chips_html = "".join(
            f'<span class="hp-chip">{html.escape(name)}'
            f'<span class="hp-chip-count">{cnt}</span></span>'
            for name, cnt in target_counter.most_common()
        )
        hp_panel_html = (
            f'<section class="hp-panel">'
            f'<div class="hp-panel-title">High-Profile Targets in This Window</div>'
            f'<div class="hp-chip-list">{chips_html}</div>'
            f"</section>"
        )

    rows = ""
    for c in cards:
        links = "".join(
            f'<li><a href="{html.escape(s["url"])}" target="_blank" rel="noopener noreferrer">{html.escape(s["title"])}</a></li>'
            for s in c["sources"]["primary"]
        )
        badge_bg, badge_fg = _heatmap_cell_color(c["risk_score"], 1)
        pri = _derive_priority(c)
        pri_cls = "p1" if pri == "P1" else "p2" if pri == "P2" else "p3"
        conf = c.get("confidence", None)
        conf_txt = (
            f'<span class="confidence">confidence {float(conf):.2f}</span>'
            if isinstance(conf, (int, float))
            else ""
        )
        tags = " ".join(
            f'<span class="domain-tag">{html.escape(_TAXONOMY.get(d, {}).get("label", d))}</span>'
            for d in c.get("domains", [])
            if d != "uncategorised"
        )
        actions24 = c.get("recommended_actions_24h", [])[:4]
        actions7 = c.get("recommended_actions_7d", [])[:4]
        act24_html = "".join(f"<li>{html.escape(str(a))}</li>" for a in actions24)
        act7_html = "".join(f"<li>{html.escape(str(a))}</li>" for a in actions7)
        domains_attr = " ".join(c.get("domains", []))
        why_now = html.escape(c.get("why_now", ""))
        _ps = c.get("patch_status", "unknown")
        _patch_badge_cls = (
            "patch-badge--fixed"
            if _ps == "patched"
            else (
                "patch-badge--workaround"
                if _ps == "workaround"
                else (
                    "patch-badge--no-fix" if _ps == "no_fix" else "patch-badge--unknown"
                )
            )
        )
        _patch_badge_lbl = (
            "Patch Available"
            if _ps == "patched"
            else (
                "Workaround"
                if _ps == "workaround"
                else "No Fix · Exploited" if _ps == "no_fix" else "Status Unknown"
            )
        )
        patch_badge_html = (
            f'<span class="patch-badge {_patch_badge_cls}">{_patch_badge_lbl}</span>'
        )
        _hp_targets = c.get("matched_targets", [])
        hp_badge_html = (
            f'<span class="hp-badge" title="{html.escape(", ".join(_hp_targets[:5]))}">High-Profile</span>'
            if _hp_targets
            else ""
        )
        _cve_list = _extract_cves(c.get("title", "") + " " + c.get("summary", ""))
        cve_badge_html = (
            f'<span class="cve-badge">{len(_cve_list)} CVE{"s" if len(_cve_list) != 1 else ""}</span>'
            if _cve_list
            else ""
        )
        _tactic = c.get("tactic_name", "")
        tactic_chip_html = (
            f'<span class="tactic-chip">{html.escape(_tactic)}</span>'
            if _tactic
            else ""
        )
        _shelf_days = int(c.get("shelf_days", 0))
        _run_count = int(c.get("run_count", 1))
        shelf_badge_html = (
            f'<span class="shelf-badge" title="First seen {_shelf_days}d ago &middot; seen {_run_count} runs">'
            f"{_shelf_days}d</span>"
            if _shelf_days >= 1
            else ""
        )
        rows += f"""
                <details class="cluster" data-domains="{html.escape(domains_attr)}" data-tactic="{html.escape(_tactic)}">
                    <summary>
                        <span class="badge" style="background:{badge_bg};color:{badge_fg}">{c['risk_score']}</span>
                        <span class="priority {pri_cls}">{pri}</span>
                        {patch_badge_html}
                        {hp_badge_html}
                        {cve_badge_html}
                        {tactic_chip_html}
                        {shelf_badge_html}
                        {html.escape(c['title'])}
                        <div class="domain-tags" style="margin:0 0 0 .5rem;display:inline">{tags}</div>
                    </summary>
                    <div class="cluster-body">
                        <p>{html.escape(c['summary'])}</p>
                        {f'<p class="why-now"><strong>Why now:</strong> {why_now}</p>' if why_now else ''}
                        {conf_txt}
                        {f'<div class="actions"><div><strong>Next 24h</strong><ul>{act24_html}</ul></div><div><strong>Next 7d</strong><ul>{act7_html}</ul></div></div>' if (act24_html or act7_html) else ''}
                        {_build_enrichment_html(c.get('enrichment'))}
                        <ul>{links}</ul>
                    </div>
                </details>"""

    # Holistic stress matrix (adjacency feel): domain x indicator intensity
    indicator_defs = [
        ("volume", "Volume"),
        ("severity", "Severity"),
        ("urgency", "Urgency"),
        ("exploit", "Exploit"),
        ("confidence", "Confidence"),
    ]
    domain_order = [k for k in _TAXONOMY.keys() if k != "uncategorised"]
    if "uncategorised" in _TAXONOMY:
        domain_order.append("uncategorised")

    domain_stats = {}
    for dk in domain_order:
        subset = [c for c in cards if dk in c.get("domains", [])]
        count = len(subset)
        max_risk = max((int(c.get("risk_score", 0)) for c in subset), default=0)
        p1 = sum(1 for c in subset if _derive_priority(c) == "P1")
        exploit = sum(1 for c in subset if _is_exploitish(c))
        conf_vals = [
            float(c.get("confidence"))
            for c in subset
            if isinstance(c.get("confidence", None), (int, float))
        ]
        avg_conf = (sum(conf_vals) / len(conf_vals)) if conf_vals else 0.0
        domain_stats[dk] = {
            "count": count,
            "max_risk": max_risk,
            "p1_ratio": (p1 / count) if count else 0.0,
            "exploit_ratio": (exploit / count) if count else 0.0,
            "avg_conf": avg_conf,
        }

    max_count = max((v["count"] for v in domain_stats.values()), default=0)

    def _indicator_val(dk: str, ik: str) -> int:
        ds = domain_stats.get(dk, {})
        if ik == "volume":
            return int(
                round(((ds.get("count", 0) / max_count) if max_count else 0.0) * 100)
            )
        if ik == "severity":
            return int(ds.get("max_risk", 0))
        if ik == "urgency":
            return int(round(ds.get("p1_ratio", 0.0) * 100))
        if ik == "exploit":
            return int(round(ds.get("exploit_ratio", 0.0) * 100))
        if ik == "confidence":
            return int(round(ds.get("avg_conf", 0.0) * 100))
        return 0

    matrix_head = "".join(f"<th>{lbl}</th>" for _, lbl in indicator_defs)
    matrix_rows = ""
    for dk in domain_order:
        dlabel = _TAXONOMY.get(dk, {}).get("label", dk)
        tds = ""
        for ik, ilabel in indicator_defs:
            val = max(0, min(100, _indicator_val(dk, ik)))
            alpha = 0.06 + (0.72 * (val / 100.0))
            glow = 2 + int((val / 100.0) * 14)
            tds += (
                f'<td class="mx-cell" style="background:rgba(31,111,235,{alpha:.3f});box-shadow:inset 0 0 {glow}px rgba(88,166,255,.35)" '
                f'title="{html.escape(dlabel)} · {ilabel}: {val}">'
                f'<span class="mx-dot" style="opacity:{0.2 + (val/100.0)*0.8:.3f}"></span>'
                f'<span class="mx-count">{val}</span>'
                f"</td>"
            )
        matrix_rows += f'<tr><th class="mx-row">{html.escape(dlabel)}</th>{tds}</tr>'

    matrix_section = f"""
        <section class="panel matrix-panel">
            <h3 style="margin:.1rem 0 .5rem">Holistic Domain Matrix</h3>
            <div class="muted" style="margin:0 0 .55rem">Uniform adjacency-style grid. Cell intensity tracks domain indicators.</div>
            <table class="risk-matrix">
                <thead><tr><th>Domain</th>{matrix_head}</tr></thead>
                <tbody>{matrix_rows}</tbody>
            </table>
        </section>
    """

    # --- MITRE tactic filter strip ---
    _MITRE_TACTICS = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command & Control",
        "Exfiltration",
        "Impact",
    ]
    active_tactics = {c.get("tactic_name", "") for c in cards if c.get("tactic_name")}
    covered_count = len(active_tactics)
    total_tactics = len(_MITRE_TACTICS)
    coverage_pct = round(covered_count / total_tactics * 100) if total_tactics else 0
    # Coverage bar: 14 pips, filled = tactic present in this window's findings
    pip_html = "".join(
        f'<span class="tactic-pip tactic-pip--{"filled" if t in active_tactics else "hollow"}" '
        f'title="{html.escape(t)}"></span>'
        for t in _MITRE_TACTICS
    )
    coverage_bar_html = (
        f'<div class="tactic-coverage" id="tactic-coverage">'
        f'<span class="tactic-coverage-label">{covered_count} / {total_tactics} tactics covered</span>'
        f'<span class="tactic-coverage-bar">{pip_html}</span>'
        f'<span class="tactic-coverage-pct">{coverage_pct}%</span>'
        f"</div>"
        if active_tactics
        else ""
    )
    tactic_buttons = "".join(
        f'<button class="tactic-btn{" tactic-btn--active" if t in active_tactics else ""}" '
        f'data-tactic="{html.escape(t)}" type="button">{html.escape(t)}</button>'
        for t in _MITRE_TACTICS
    )
    tactic_strip_html = (
        (
            f"{coverage_bar_html}"
            f'<div class="tactic-strip" id="tactic-strip">'
            f'<button class="tactic-btn tactic-btn--all tactic-btn--active" data-tactic="all" type="button">All Tactics</button>'
            f"{tactic_buttons}"
            f"</div>"
        )
        if active_tactics
        else ""
    )

    card_data = []
    for c in cards:
        card_data.append(
            {
                "title": c.get("title", ""),
                "risk_score": int(c.get("risk_score", 0)),
                "priority": _derive_priority(c),
                "domains": c.get("domains", []),
                "summary": c.get("summary", ""),
            }
        )

    page_html = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Watchtower — InfraSec Briefing</title>
<style>
:root{{--rail-width-expanded:360px;--rail-width-collapsed:64px;--rail-width:var(--rail-width-expanded);--rail-min-width:320px;--rail-max-width:480px;--rail-gap:8px;--page-gutter:16px}}
*{{box-sizing:border-box}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:#0a0a0a}}
::-webkit-scrollbar-thumb{{background:#2a2a2a;border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:#3a3a3a}}
*{{scrollbar-width:thin;scrollbar-color:#2a2a2a #0a0a0a}}
body{{font-family:system-ui,sans-serif;margin:0;padding:0;background:#0f0f0f;color:#c9d1d9}}
.page-wrap{{max-width:1320px;margin:0 auto;position:relative}}
.app-shell{{position:relative;padding-top:88px}}
.app-main{{padding:0 var(--page-gutter) 1.4rem;padding-right:calc(var(--rail-width) + var(--rail-gap) + var(--page-gutter));transition:padding-right .2s ease}}
body.rail-collapsed .app-main{{padding-right:calc(var(--rail-width-collapsed) + var(--rail-gap) + var(--page-gutter))}}
.header-bar{{position:fixed;top:0;left:0;right:0;background:#0f0f0f;border-bottom:1px solid #2a2a2a;z-index:20;padding:.8rem var(--page-gutter);box-shadow:0 2px 8px rgba(0,0,0,.2)}}
.header-content{{max-width:1320px;margin:0 auto;padding-right:calc(var(--rail-width) + var(--rail-gap))}}
body.rail-collapsed .header-content{{padding-right:calc(var(--rail-width-collapsed) + var(--rail-gap))}}
.header-bar h1{{margin:0;padding:0;border:none;font-size:1.35rem}}
.header-bar p{{margin:.25rem 0 0;font-size:.82rem;color:#8b949e}}
h1{{border-bottom:2px solid #333;padding-bottom:.4rem;color:#e6edf3}}
h2{{color:#e6edf3}}
a{{color:#999}}
p{{color:#c9d1d9}}
.kpi-grid{{display:grid;grid-template-columns:repeat(7,minmax(110px,1fr));gap:8px;margin:1rem 0 1.2rem}}
.kpi{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.55rem .7rem;display:flex;flex-direction:column;gap:.2rem}}
.kpi .k{{font-size:.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700}}
.kpi .v{{font-size:1.2rem;color:#e6edf3;font-weight:800}}
.kpi .v-sm{{font-size:.95rem}}
.hm-cell{{border-radius:6px;padding:.7rem .55rem;text-align:center;border:1px solid rgba(255,255,255,.08);cursor:pointer;font-family:inherit}}
.hm-cell.active{{outline:2px solid #666;outline-offset:1px}}
.hm-label{{display:block;font-size:.72rem;font-weight:700;margin:.15rem 0}} 
.hm-meta{{display:block;font-size:.66rem;opacity:.85}}
.hm-score{{display:block;font-size:1.15rem;font-weight:800;margin-top:.2rem}}
.panel{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:.7rem .8rem}}
.panel h3{{margin:.2rem 0 .5rem;font-size:.92rem;color:#e6edf3}}
.panel .muted{{color:#8b949e;font-size:.8rem}}
.feed-table{{width:100%;border-collapse:collapse;font-size:.78rem}}
.feed-table th,.feed-table td{{border-bottom:1px solid #333;padding:.3rem .2rem;text-align:left}}
.matrix-panel{{margin:.2rem 0 1rem}}
.risk-matrix{{width:100%;border-collapse:separate;border-spacing:4px;table-layout:fixed}}
.risk-matrix th{{font-size:.68rem;color:#8b949e;font-weight:700;text-align:center;letter-spacing:.02em}}
.risk-matrix .mx-row{{text-align:left;padding-left:.3rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}}
.mx-cell{{height:44px;border:1px solid #333;border-radius:6px;position:relative;text-align:center;vertical-align:middle;overflow:hidden;transition:filter .12s ease,transform .12s ease}}
.mx-cell:hover{{filter:brightness(1.1);transform:translateY(-1px)}}
.mx-dot{{position:absolute;left:50%;top:50%;width:20px;height:20px;border-radius:999px;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(180,180,180,.75) 0%, rgba(180,180,180,.05) 70%)}}
.mx-count{{position:relative;display:block;font-size:.82rem;font-weight:800;color:#e6edf3;line-height:1}}
.cluster{{background:rgba(255,255,255,0.01);border:1px solid #2a2a2a;border-radius:6px;padding:0;margin:.55rem 0;overflow:hidden}}
.cluster summary{{list-style:none;padding:.62rem .85rem;cursor:pointer;display:flex;align-items:center;gap:.35rem;user-select:none;color:#c9d1d9;font-size:.92rem}}
.cluster summary::-webkit-details-marker{{display:none}}
.cluster summary::before{{content:"–";font-size:.75rem;transition:transform .15s;flex-shrink:0;color:#8b949e;display:inline-block;width:.7rem;text-align:center}}
.cluster[open] summary::before{{transform:none;content:"+"}}
.cluster-body{{padding:.2rem .9rem .85rem;color:#c9d1d9}}
.badge{{border-radius:999px;padding:2px 8px;font-size:.72rem;font-weight:700;margin-right:.35rem;background:rgba(255,255,255,.06)!important;color:#c9d1d9!important}}
.priority{{border-radius:999px;padding:2px 8px;font-size:.68rem;font-weight:800;letter-spacing:.02em;margin-right:.3rem;border:1px solid #333}}
.priority.p1{{background:rgba(170,28,28,.16);color:#c88888;border-color:rgba(170,28,28,.36)}}
.priority.p2{{background:rgba(100,100,100,.15);color:#aaa;border-color:rgba(100,100,100,.30)}}
.priority.p3{{background:#252525;color:#c9d1d9}}
.domain-tags{{margin:.3rem 0 .6rem}} .domain-tag{{display:inline-block;background:#252525;color:#8b949e;border:1px solid #333;border-radius:3px;font-size:.7rem;padding:1px 6px;margin:0 3px 3px 0}}
.executive{{background:#1a1a1a;border-left:3px solid #555;border-radius:4px;padding:.8rem 1.1rem;margin:1rem 0 1.8rem}}
.executive h2{{margin:0 0 .4rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:#999}}
.executive p{{margin:0;line-height:1.75;font-size:.95rem;color:#c9d1d9}}
.history-panel{{background:#1a1a1a;border:1px solid #333;border-radius:4px;padding:.45rem 1rem;margin:0 0 1.2rem;display:flex;align-items:center;gap:.8rem;flex-wrap:wrap}}
.hs-label{{color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:.68rem}}
.hs-val{{font-weight:700;font-size:.85rem;color:#e6edf3}}
.actions{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:.4rem 0 .7rem}}
.actions ul{{margin:.3rem 0 .2rem 1rem;padding:0}}
.confidence{{display:inline-block;font-size:.72rem;color:#8b949e;border:1px solid #333;border-radius:999px;padding:2px 8px;margin-bottom:.3rem}}
.patch-badge{{display:inline-block;font-size:.65rem;font-weight:700;letter-spacing:.04em;border-radius:3px;padding:1px 7px;margin-left:.45rem;vertical-align:middle;text-transform:uppercase}}
.patch-badge--fixed{{background:rgba(35,134,54,.18);color:#3fb950;border:1px solid rgba(35,134,54,.35)}}
.patch-badge--workaround{{background:rgba(158,106,3,.18);color:#d29922;border:1px solid rgba(158,106,3,.35)}}
.patch-badge--no-fix{{background:rgba(170,28,28,.18);color:#f85149;border:1px solid rgba(170,28,28,.35)}}
.patch-badge--unknown{{background:rgba(60,60,60,.5);color:#8b949e;border:1px solid #333}}
.cve-badge{{display:inline-block;font-size:.62rem;font-weight:700;background:rgba(30,100,200,.12);color:#6ea8fe;border:1px solid rgba(30,100,200,.28);border-radius:3px;padding:1px 6px;margin-left:.35rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0}}
.findings-filter{{display:flex;align-items:center;gap:.6rem;margin:.25rem 0 .6rem}}
.findings-search{{background:#151515;border:1px solid #333;border-radius:4px;color:#c9d1d9;font-size:.82rem;padding:.3rem .55rem;width:min(340px,100%);outline:none}}
.findings-search:focus{{border-color:#555;background:#1a1a1a}}
.findings-count{{font-size:.75rem;color:#8b949e}}
.run-metrics-bar{{display:flex;gap:.35rem;flex-wrap:wrap;margin:.2rem 0 .45rem;padding:.3rem 0;border-bottom:1px solid #252525}}
.rm-chip{{font-size:.68rem;padding:2px 7px;border-radius:999px;border:1px solid #333;background:#181818;color:#aaa}}
.rm-ok{{color:#3fb950;border-color:rgba(35,134,54,.35);background:rgba(35,134,54,.08)}}
.rm-fail{{color:#f85149;border-color:rgba(170,28,28,.35);background:rgba(170,28,28,.08)}}
.vel-chip{{font-size:.62rem;font-weight:800;padding:0 3px;flex-shrink:0}}
.vel-up2{{color:#f0883e}}
.vel-up1{{color:#d29922}}
.vel-dn{{color:#3fb950}}
.cal-section{{margin:0 0 1rem}}
.cal-header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:.35rem;flex-wrap:wrap;gap:.3rem}}
.cal-title{{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#8b949e}}
.cal-legend{{display:flex;align-items:center;gap:.3rem;flex-wrap:wrap}}
.cal-legend-item{{display:inline-block;width:14px;height:14px;border-radius:3px;font-size:.58rem;line-height:14px;text-align:center;color:rgba(255,255,255,.65)}}
.cal-grid{{display:grid;grid-template-columns:repeat(14,1fr);gap:4px}}
.cal-cell{{aspect-ratio:1;border-radius:4px;display:flex;align-items:center;justify-content:center;cursor:default;transition:transform .1s,filter .1s}}
.cal-cell:hover{{transform:scale(1.12);filter:brightness(1.25)}}
.cal-day{{font-size:.6rem;color:rgba(255,255,255,.55);font-weight:600;pointer-events:none}}
.tactic-strip{{display:flex;flex-wrap:wrap;gap:5px;margin:.3rem 0 .55rem;padding:.45rem 0;border-bottom:1px solid #252525}}
.tactic-coverage{{display:flex;align-items:center;gap:.55rem;padding:.35rem 0 .3rem;border-top:1px solid #252525;border-bottom:1px solid #1e1e1e;margin-bottom:.3rem;flex-wrap:wrap}}
.tactic-coverage-label{{font-size:.67rem;color:#5a7090;white-space:nowrap}}
.tactic-coverage-bar{{display:flex;gap:3px;align-items:center}}
.tactic-coverage-pct{{font-size:.67rem;color:#5a7090;font-weight:700}}
.tactic-pip{{display:inline-block;width:10px;height:10px;border-radius:2px;transition:transform .1s}}
.tactic-pip--filled{{background:rgba(58,130,246,.55);border:1px solid rgba(58,130,246,.7)}}
.tactic-pip--filled:hover{{transform:scale(1.3)}}
.tactic-pip--hollow{{background:#1a1a1a;border:1px solid #2e2e2e}}
.tactic-btn{{background:#181818;border:1px solid #2a2a2a;color:#5a6a7a;font-size:.67rem;padding:2px 9px;border-radius:999px;cursor:pointer;transition:background .12s,color .12s}}
.tactic-btn:hover{{background:#252525;color:#aaa}}
.tactic-btn--active{{background:rgba(30,80,160,.18);border-color:rgba(58,130,246,.35);color:#79b8ff}}
.tactic-btn--all.tactic-btn--active{{background:rgba(50,50,50,.25);border-color:#555;color:#c9d1d9}}
.tactic-chip{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(88,130,240,.12);color:#6ea8fe;border:1px solid rgba(88,130,240,.25);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0}}
.shelf-badge{{display:inline-block;font-size:.6rem;font-weight:700;background:rgba(210,90,20,.1);color:#e8864a;border:1px solid rgba(210,90,20,.25);border-radius:3px;padding:1px 5px;margin-left:.25rem;letter-spacing:.02em;vertical-align:middle;flex-shrink:0;cursor:default}}
.enrich-block{{margin:.6rem 0 .2rem;border:1px solid #222;border-radius:5px;overflow:hidden}}
.enrich-summary{{font-size:.72rem;color:#5a7090;cursor:pointer;padding:.35rem .6rem;list-style:none;display:flex;align-items:center;gap:.4rem;user-select:none}}
.enrich-summary::-webkit-details-marker{{display:none}}
.enrich-summary:hover{{color:#88a0b8}}
.enrich-src-count{{font-size:.65rem;color:#3a5070;background:#141e2a;border-radius:999px;padding:0 6px}}
.enrich-body{{padding:.4rem .65rem .5rem;border-top:1px solid #1e1e1e;display:flex;flex-direction:column;gap:.3rem}}
.enrich-lede{{font-size:.75rem;color:#8899aa;margin:0 0 .2rem;line-height:1.45;font-style:italic}}
.enrich-row{{display:flex;align-items:center;flex-wrap:wrap;gap:.25rem;font-size:.68rem}}
.enrich-label{{color:#3a5070;font-size:.63rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;min-width:4rem;flex-shrink:0}}
.enrich-cve{{background:rgba(220,50,50,.1);color:#e05555;border:1px solid rgba(220,50,50,.2);border-radius:3px;padding:1px 5px;font-size:.65rem;font-weight:700}}
.enrich-cve--extra{{background:rgba(220,50,50,.05);color:#a04040;border-style:dashed}}
.enrich-product{{background:rgba(50,130,200,.1);color:#5599cc;border:1px solid rgba(50,130,200,.2);border-radius:3px;padding:1px 6px;font-size:.65rem}}
.enrich-version{{background:rgba(80,160,80,.08);color:#66aa66;border:1px solid rgba(80,160,80,.2);border-radius:3px;padding:1px 5px;font-size:.65rem;font-family:monospace}}
.enrich-date{{background:rgba(160,130,50,.08);color:#aa9955;border:1px solid rgba(160,130,50,.18);border-radius:3px;padding:1px 6px;font-size:.65rem}}
.hp-badge{{display:inline-block;font-size:.65rem;font-weight:700;letter-spacing:.04em;border-radius:3px;padding:1px 7px;margin-left:.45rem;vertical-align:middle;text-transform:uppercase;background:rgba(139,92,246,.15);color:#a78bfa;border:1px solid rgba(139,92,246,.3)}}
.hp-panel{{background:rgba(139,92,246,.06);border:1px solid rgba(139,92,246,.2);border-radius:6px;padding:.65rem 1rem .7rem;margin:.2rem 0 1rem}}
.hp-panel-title{{font-size:.75rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#a78bfa;margin-bottom:.5rem}}
.hp-chip-list{{display:flex;flex-wrap:wrap;gap:.35rem}}
.hp-chip{{display:inline-flex;align-items:center;gap:.3rem;background:rgba(139,92,246,.1);color:#c4b5fd;border:1px solid rgba(139,92,246,.25);border-radius:999px;font-size:.71rem;padding:2px 10px;font-weight:600}}
.hp-chip-count{{background:rgba(139,92,246,.3);color:#ede9fe;border-radius:999px;font-size:.65rem;font-weight:700;padding:0 5px;min-width:1.2em;text-align:center}}
.delta-strip{{display:flex;align-items:center;gap:.5rem;margin:.2rem 0 1rem;flex-wrap:wrap;min-height:1.6rem}}
.delta-chip{{display:inline-flex;align-items:center;border-radius:999px;padding:3px 11px;font-size:.71rem;font-weight:700;border:1px solid;letter-spacing:.03em}}
.delta-chip--new{{background:rgba(100,100,100,.12);color:#aaa;border-color:rgba(100,100,100,.3)}}
.delta-chip--elevated{{background:rgba(158,106,3,.12);color:#d29922;border-color:rgba(158,106,3,.3)}}
.delta-chip--resolved{{background:rgba(35,134,54,.12);color:#3fb950;border-color:rgba(35,134,54,.3)}}
.delta-chip--quiet{{color:#8b949e;border-color:#333;background:transparent}}
.resolved-drawer{{margin:.5rem 0 1rem;color:#8b949e}}
.resolved-drawer summary{{font-size:.8rem;cursor:pointer;padding:.3rem 0;list-style:none}}
.resolved-drawer summary::-webkit-details-marker{{display:none}}
.resolved-drawer table{{width:100%;border-collapse:collapse;font-size:.78rem;margin-top:.4rem}}
.resolved-drawer th{{font-size:.68rem;color:#777;font-weight:700;border-bottom:1px solid #252525;padding:.2rem .4rem}}
.resolved-drawer td{{padding:.25rem .4rem;border-bottom:1px solid #252525}}
.ha-section{{margin:0 0 1rem}}.ha-day{{border-bottom:1px solid #252525}}.ha-day:last-child{{border-bottom:none}}
.ha-summary{{display:flex;align-items:center;gap:.7rem;padding:.42rem .3rem;cursor:pointer;list-style:none;font-size:.82rem}}.ha-summary::-webkit-details-marker{{display:none}}
.ha-date{{font-weight:700;color:#e6edf3;flex:0 0 92px}}.ha-meta{{color:#c9d1d9;flex:1;font-size:.78rem}}.ha-ts{{color:#8b949e;font-size:.68rem;margin-left:auto;flex-shrink:0}}
.ha-body{{padding:.25rem .2rem .5rem .5rem}}.ha-table{{width:100%;border-collapse:collapse;font-size:.76rem}}.ha-table th{{font-size:.67rem;color:#777;font-weight:700;border-bottom:1px solid #252525;padding:.2rem .35rem}}
.ha-table td{{padding:.22rem .35rem;border-bottom:1px solid #1a1a1a;vertical-align:top}}.ha-title{{max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}.ha-risk{{text-align:right;font-weight:700;color:#e6edf3;min-width:30px}}.ha-pri,.ha-ps{{text-align:center;min-width:40px;white-space:nowrap}}
.weekly-scope{{margin:0 0 1rem}}.weekly-kpi-row{{display:flex;gap:10px;flex-wrap:wrap;margin:.4rem 0 .75rem}}
.wkpi{{background:#0f0f0f;border:1px solid #252525;border-radius:5px;padding:.4rem .65rem;display:flex;flex-direction:column;gap:.15rem;min-width:110px}}
.wk{{font-size:.65rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700}}.wv{{font-size:1.1rem;color:#e6edf3;font-weight:800}}.wv-sm{{font-size:.85rem}}
.weekly-review-label{{font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;font-weight:700;color:#999;margin:.3rem 0 .2rem}}
.weekly-review-text{{margin:0 0 .7rem;line-height:1.75;font-size:.9rem;color:#c9d1d9}}
.wcve-details{{margin:.3rem 0 0}}.wcve-details summary{{font-size:.78rem;color:#8b949e;cursor:pointer;padding:.25rem 0;list-style:none}}.wcve-details summary::-webkit-details-marker{{display:none}}
.wcve-table{{width:100%;border-collapse:collapse;font-size:.76rem;margin-top:.35rem}}.wcve-table th{{font-size:.67rem;color:#777;font-weight:700;border-bottom:1px solid #252525;padding:.2rem .4rem}}.wcve-table td{{padding:.22rem .4rem;border-bottom:1px solid #1a1a1a}}
.wcve-id{{font-family:monospace;color:#999;font-size:.75rem}}.wcve-bar-cell{{min-width:80px}}.wcve-bar-inner{{height:5px;background:#666;border-radius:2px;min-width:2px}}.wcve-count{{text-align:right;font-weight:700;color:#e6edf3;min-width:22px}}
.threat-section{{display:block;margin:0 0 1rem}}
.threat-main{{padding:.3rem .4rem .5rem}}
.threat-toolbar{{display:flex;justify-content:space-between;align-items:center;padding:.3rem .3rem .45rem}}
.threat-title{{font-size:.9rem;font-weight:700;color:#e6edf3}}
.threat-sub{{font-size:.72rem;color:#8b949e}}
.right-rail{{position:fixed;right:0;top:0;bottom:0;width:var(--rail-width);padding:.8rem .7rem;display:flex;flex-direction:column;overflow:hidden;z-index:25;transition:width .2s ease,transform .22s ease;background:#1a1a1a;border:none;border-left:1px solid #2a2a2a;border-radius:0;box-shadow:-2px 0 8px rgba(0,0,0,.15)}}
body.rail-collapsed .right-rail{{width:var(--rail-width-collapsed);padding:.8rem .45rem}}
.rail-header{{display:flex;align-items:center;justify-content:space-between;gap:.4rem;padding:0 0 .45rem;border-bottom:1px solid #2a2a2a}}
.rail-actions{{display:flex;gap:.35rem;align-items:center}}
.rail-btn{{background:#151515;border:1px solid #3a3a3a;color:#aaa;border-radius:4px;font-size:.72rem;padding:.2rem .45rem;cursor:pointer}}
.rail-btn:hover{{background:#202020}}
.rail-content{{overflow:auto;padding:.5rem .05rem .2rem;display:flex;flex-direction:column;gap:.35rem}}
body.rail-collapsed .rail-content,body.rail-collapsed .rail-header h3{{display:none}}
.rail-collapsed-pill{{display:none;writing-mode:vertical-rl;transform:rotate(180deg);font-size:.72rem;letter-spacing:.04em;color:#8b949e;margin:.2rem auto 0}}
body.rail-collapsed .rail-collapsed-pill{{display:block}}
.rail-handle{{position:absolute;left:-4px;top:0;bottom:0;width:8px;cursor:ew-resize;background:linear-gradient(to right,rgba(160,160,160,.18),rgba(160,160,160,0));border-radius:3px;opacity:.4}}
.rail-handle:hover{{opacity:.85;background:linear-gradient(to right,rgba(180,180,180,.35),rgba(180,180,180,0))}}
.rail-tablist{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px;margin:.1rem 0 .2rem}}
.rail-tab{{border:1px solid #333;background:#181818;color:#999;font-size:.68rem;padding:.24rem .2rem;border-radius:4px;text-align:center;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.rail-tab[aria-selected="true"]{{background:#2a2a2a;color:#c9d1d9;border-color:#555}}
.rail-panel{{display:none}}
.rail-panel.active{{display:block}}
.rail-placeholder{{font-size:.78rem;color:#8b949e;line-height:1.5;padding:.3rem 0}}
.rail-mobile-toggle{{display:none;position:fixed;right:14px;bottom:14px;z-index:16;background:#252525;border:1px solid #444;color:#ccc;border-radius:999px;padding:.42rem .8rem;font-size:.74rem;cursor:pointer}}
.rail-backdrop{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.58);backdrop-filter:blur(1px);z-index:14}}
body.rail-open .rail-backdrop{{display:block}}
.tm-node .node-disc{{transition:stroke .12s,stroke-width .12s}}
.tm-node:hover .node-disc{{stroke:rgba(160,160,160,0.5)!important;stroke-width:1.4px!important}}
.tm-node .sel-indicator{{opacity:0;transition:opacity .18s}}
.tm-node.tm-selected .sel-indicator{{opacity:1}}
.rank-row{{display:flex;align-items:center;gap:6px;padding:.28rem 0;border-bottom:1px solid #222;cursor:pointer;border-radius:3px}}
.rank-row:hover{{background:rgba(255,255,255,.03)}}
.rank-label{{font-size:.77rem;flex:0 0 92px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.rank-bar-wrap{{flex:1;background:#181818;border-radius:2px;height:3px}}
.rank-bar{{height:3px;border-radius:2px;min-width:1px}}
.rank-val{{font-size:.7rem;font-weight:700;flex:0 0 22px;text-align:right}}
.chip{{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #333;background:#252525;color:#c9d1d9;font-size:.72rem}}
.next-run{{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;border:1px solid #3a3a3a;background:#1a1a1a;color:#999;font-size:.72rem;font-variant-numeric:tabular-nums;margin-left:.6rem}}
.next-run.soon{{border-color:#4a2a00;background:#1c1000;color:#e3a020}}
.next-run.now{{border-color:#2a3a2a;background:#151f15;color:#3fb950;animation:pulse-now 1s ease-in-out infinite}}
@keyframes pulse-now{{0%,100%{{opacity:1}}50%{{opacity:.55}}}}
footer{{color:#8b949e;font-size:.8rem;margin-top:2rem;padding-top:.8rem;border-top:1px solid #333}}
@media (max-width:900px){{
  :root{{--page-gutter:12px}}
  .header-bar{{padding:.45rem 12px}}
  .header-content{{padding-right:0!important}}
  body.rail-collapsed .header-content{{padding-right:0!important}}
  .header-bar h1{{font-size:1.02rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .header-bar p{{font-size:.72rem;display:flex;align-items:center;gap:.2rem;flex-wrap:nowrap;overflow:hidden}}
  .next-run{{font-size:.64rem;padding:2px 6px;margin-left:.3rem;flex-shrink:0}}
  .app-shell{{padding-top:68px}}
  .app-main{{padding:0 var(--page-gutter) 1rem;padding-right:var(--page-gutter)}}
  body.rail-collapsed .app-main{{padding-right:var(--page-gutter)}}
  .kpi-grid{{grid-template-columns:repeat(3,1fr);gap:6px;margin:.65rem 0 .85rem}}
  .kpi:last-child{{grid-column:1/-1;flex-direction:row;align-items:center;justify-content:space-between;padding:.38rem .75rem}}
  .kpi{{padding:.4rem .5rem}}
  .kpi .v{{font-size:1.05rem}}
  .kpi .v-sm{{font-size:.88rem}}
  .cluster summary{{flex-wrap:wrap;row-gap:.2rem;padding:.55rem .7rem}}
  .domain-tags{{margin:.15rem 0 0!important}}
  .matrix-panel{{display:none}}
  .executive{{padding:.6rem .85rem;margin:.5rem 0 1rem}}
  .hp-panel{{padding:.5rem .8rem .55rem}}
  .findings-filter{{gap:.4rem}}
  .findings-search{{width:100%}}
  .ha-title{{max-width:min(55vw,260px)}}
  h2{{font-size:1rem;margin:.75rem 0 .25rem}}
  .threat-toolbar{{flex-wrap:wrap;gap:.25rem}}
  .delta-strip{{margin:.1rem 0 .6rem}}
  .weekly-kpi-row{{gap:7px}}
  .right-rail{{right:0;top:0;bottom:0;width:min(92vw,420px);max-width:92vw;transform:translateX(100%);border-radius:0;box-shadow:-4px 0 12px rgba(0,0,0,.25)}}
  body.rail-open .right-rail{{transform:translateX(0)}}
  .rail-mobile-toggle{{display:inline-flex;align-items:center;gap:6px}}
}}
@media (max-width:480px){{
  .header-bar h1{{font-size:.92rem}}
  .next-run{{display:none}}
  .kpi-grid{{gap:5px;margin:.5rem 0 .7rem}}
  .kpi .k{{font-size:.6rem;letter-spacing:0}}
  .kpi .v{{font-size:.9rem}}
  .kpi:last-child .kpi .k{{font-size:.62rem}}
  .cluster summary{{font-size:.84rem;padding:.48rem .6rem;gap:.18rem}}
  .badge{{font-size:.67rem;padding:1px 6px}}
  .priority{{font-size:.62rem;padding:1px 5px}}
  .patch-badge,.cve-badge,.hp-badge{{font-size:.6rem;padding:1px 5px}}
  .ha-pri,.ha-ps{{display:none}}
  .wkpi{{min-width:76px;padding:.35rem .5rem}}
  .wv{{font-size:.95rem}}
  .cluster-body{{padding:.15rem .7rem .7rem}}
  footer{{font-size:.72rem}}
}}
        </style>
        </head>
        <body>
        <div class="rail-backdrop" id="rail-backdrop"></div>
        <button id="rail-mobile-toggle" class="rail-mobile-toggle" type="button" aria-controls="domain-rail" aria-expanded="false">Domain Activity</button>
        <header class="header-bar">
          <div class="header-content">
            <h1>Watchtower — Infrastructure Security Briefing</h1>
            <p>Generated <strong>{ts.replace('_', ' ')}</strong> UTC | <a href="latest.md">latest.md</a><span class="next-run" id="next-run-cd" title="Scheduled runs: 00:05, 06:05, 12:05, 18:05 ET">Next run —</span></p>
          </div>
        </header>
        <div class="page-wrap">
        <div class="app-shell">
        <main class="app-main">
        {f'<div class="executive"><h2>Analyst Summary</h2><p>{html.escape(executive)}</p></div>' if executive else ''}
{kpi_html}
{delta_strip_html}
{hp_panel_html}
<section class="threat-section">
  <div class="panel threat-main">
    <div class="threat-toolbar">
      <div>
        <div class="threat-title">Surface Threat Map</div>
        <div class="threat-sub">Domain constellation — node intensity shows activity heat, edges show blast-radius pathways. Click any node to filter findings.</div>
      </div>
      <span class="chip">Window {since_hours}h</span>
    </div>
    {threat_svg}
  </div>
</section>
{history_section}
{calendar_html}
{weekly_html}
{tactic_strip_html}
<h2>Top Findings</h2>
<div class="findings-filter">
  <input type="search" id="findings-search" class="findings-search" placeholder="Search findings\u2026" aria-label="Search findings" />
  <span id="findings-count" class="findings-count"></span>
</div>
{rows}
{resolved_drawer_html}
<footer>Watchtower · scheduled 00:05 / 06:05 / 12:05 / 18:05 ET · placeholder mode: {str(placeholder_mode()).lower()}</footer>
                </main>
                <aside id="domain-rail" class="panel right-rail" role="complementary" aria-label="Domain Activity">
                    <div class="rail-handle" id="rail-handle" role="separator" aria-orientation="vertical" aria-label="Resize Domain Activity panel"></div>
                    <div class="rail-header">
                        <h3 style="margin:.2rem 0 .2rem">Domain Activity</h3>
                        <div class="rail-actions">
                            <button id="rail-toggle" class="rail-btn" type="button" aria-expanded="true">Collapse</button>
                            <button id="rail-close" class="rail-btn" type="button" style="display:none">Close</button>
                        </div>
                    </div>
                    <div class="rail-collapsed-pill">DOMAIN ACTIVITY</div>
                    <div class="rail-content" id="rail-content">
                        <div class="rail-tablist" role="tablist" aria-label="Domain Activity modules">
                            <button class="rail-tab" type="button" id="tab-overview" role="tab" aria-controls="panel-overview" aria-selected="true" data-tab="overview">Overview</button>
                            <button class="rail-tab" type="button" id="tab-feeds" role="tab" aria-controls="panel-feeds" aria-selected="false" data-tab="feeds">Feeds</button>
                            <button class="rail-tab" type="button" id="tab-alerts" role="tab" aria-controls="panel-alerts" aria-selected="false" data-tab="alerts">Alerts</button>
                            <button class="rail-tab" type="button" id="tab-forensics" role="tab" aria-controls="panel-forensics" aria-selected="false" data-tab="forensics">Forensics</button>
                        </div>
                        <section class="rail-panel active" id="panel-overview" role="tabpanel" aria-labelledby="tab-overview">
                            <h3 style="margin:.2rem 0 .45rem">Domain Activity</h3>
                            {domain_rank_html}
                            <h3 style="margin:.7rem 0 .35rem">Selected Domain</h3>
                            <div id="tm-detail" class="muted" style="font-size:.8rem">Click a node to inspect findings.</div>
                        </section>
                        <section class="rail-panel" id="panel-feeds" role="tabpanel" aria-labelledby="tab-feeds">
                            <h3 style="margin:.2rem 0 .35rem">Run Metrics</h3>
                            {run_metrics_html}
                            <h3 style="margin:.6rem 0 .35rem">Feed Health</h3>
                            <table class="feed-table"><thead><tr><th>Feed</th><th>Items</th><th>Reliability</th><th>Time</th></tr></thead><tbody>{health_rows}</tbody></table>
                            <h3 style="margin:.6rem 0 .35rem">Source References</h3>
                            <table class="feed-table"><thead><tr><th>Domain</th><th>Refs</th><th>Max risk</th></tr></thead><tbody>{feed_rows}</tbody></table>
                        </section>
                        <section class="rail-panel" id="panel-alerts" role="tabpanel" aria-labelledby="tab-alerts" data-lazy="true">
                            <h3 style="margin:.2rem 0 .35rem">Alerts</h3>
                            <div class="rail-placeholder">Reserved module slot. Use this area for triage queues, ownership routing, and SLA timers.</div>
                        </section>
                        <section class="rail-panel" id="panel-forensics" role="tabpanel" aria-labelledby="tab-forensics" data-lazy="true">
                            <h3 style="margin:.2rem 0 .35rem">Forensics</h3>
                            <div class="rail-placeholder">Reserved module slot. Use this area for IOCs, kill-chain pivots, and evidence links.</div>
                        </section>
                    </div>
                </aside>
                </div>
                </div>
<script>
var CARDS={json.dumps(card_data)};
var CURRENT_DOMAIN='all';
var DOMAIN_LABELS={json.dumps({k: v.get('label', k) for k, v in heatmap.items()})};
var WT_TELEMETRY=[];

function trackUi(evt,payload){{
        var e={{event:evt,ts:new Date().toISOString(),payload:payload||{{}}}};
        WT_TELEMETRY.push(e);
}}

function isNarrow(){{return window.matchMedia('(max-width: 900px)').matches;}}

function applyRailWidth(w){{
        var min=320,max=480;
        var n=Math.max(min,Math.min(max,Math.round(w||360)));
        document.documentElement.style.setProperty('--rail-width',n+'px');
        try{{localStorage.setItem('wt.rail.width',String(n));}}catch(e){{}}
        window.dispatchEvent(new Event('resize'));
}}

function setRailCollapsed(collapsed,persist){{
        document.body.classList.toggle('rail-collapsed',!!collapsed);
        var t=document.getElementById('rail-toggle');
        if(t){{
                t.textContent=collapsed?'Expand':'Collapse';
                t.setAttribute('aria-expanded',(!collapsed).toString());
        }}
        if(persist!==false){{
                try{{localStorage.setItem('wt.rail.collapsed',collapsed?'1':'0');}}catch(e){{}}
        }}
        trackUi(collapsed?'rail_collapsed':'rail_expanded');
        window.dispatchEvent(new Event('resize'));
}}

function setRailOpen(open,persist){{
        document.body.classList.toggle('rail-open',!!open);
        var mt=document.getElementById('rail-mobile-toggle');
        if(mt) mt.setAttribute('aria-expanded',open?'true':'false');
        if(persist!==false){{
                try{{localStorage.setItem('wt.rail.mobileOpen',open?'1':'0');}}catch(e){{}}
        }}
        trackUi(open?'rail_opened':'rail_closed',{{mobile:isNarrow()}});
}}

function setRailTab(tab){{
        document.querySelectorAll('.rail-tab').forEach(function(btn){{
                var active=btn.getAttribute('data-tab')===tab;
                btn.setAttribute('aria-selected',active?'true':'false');
                btn.tabIndex=active?0:-1;
        }});
        document.querySelectorAll('.rail-panel').forEach(function(p){{
                p.classList.toggle('active',p.id==='panel-'+tab);
        }});
        try{{localStorage.setItem('wt.rail.tab',tab);}}catch(e){{}}
        trackUi('rail_tab',{{tab:tab}});
}}

function initRightRail(){{
        var toggle=document.getElementById('rail-toggle');
        var close=document.getElementById('rail-close');
        var mobileToggle=document.getElementById('rail-mobile-toggle');
        var backdrop=document.getElementById('rail-backdrop');
        var handle=document.getElementById('rail-handle');

        var initialTab='overview';
        try{{initialTab=localStorage.getItem('wt.rail.tab')||'overview';}}catch(e){{}}
        setRailTab(initialTab);

        var savedW=360;
        try{{savedW=parseInt(localStorage.getItem('wt.rail.width')||'360',10)||360;}}catch(e){{}}
        applyRailWidth(savedW);

        var collapsed=false;
        try{{collapsed=localStorage.getItem('wt.rail.collapsed')==='1';}}catch(e){{}}
        if(!isNarrow()) setRailCollapsed(collapsed,false);

        document.querySelectorAll('.rail-tab').forEach(function(btn){{
                btn.addEventListener('click',function(){{ setRailTab(btn.getAttribute('data-tab')); }});
        }});

        if(toggle) toggle.addEventListener('click',function(){{ setRailCollapsed(!document.body.classList.contains('rail-collapsed')); }});
        if(mobileToggle) mobileToggle.addEventListener('click',function(){{ setRailOpen(true); }});
        if(close) close.addEventListener('click',function(){{ setRailOpen(false); }});
        if(backdrop) backdrop.addEventListener('click',function(){{ setRailOpen(false); }});
        document.addEventListener('keydown',function(e){{ if(e.key==='Escape') setRailOpen(false); }});

        if(handle){{
                var dragging=false;
                handle.addEventListener('pointerdown',function(e){{
                        if(isNarrow()) return;
                        dragging=true;
                        handle.setPointerCapture(e.pointerId);
                        document.body.style.userSelect='none';
                        trackUi('rail_resize_start');
                }});
                handle.addEventListener('pointermove',function(e){{
                        if(!dragging||isNarrow()) return;
                        var w=(window.innerWidth-e.clientX)-parseInt(getComputedStyle(document.documentElement).getPropertyValue('--page-gutter')||16,10);
                        applyRailWidth(w);
                }});
                handle.addEventListener('pointerup',function(){{
                        if(!dragging) return;
                        dragging=false;
                        document.body.style.userSelect='';
                        var cur=parseInt(getComputedStyle(document.documentElement).getPropertyValue('--rail-width')||'360',10);
                        trackUi('rail_resized',{{width:cur}});
                }});
        }}

        var mq=window.matchMedia('(max-width: 900px)');
        function onViewport(){{
                if(close) close.style.display=isNarrow()?'inline-block':'none';
                if(!isNarrow()){{ setRailOpen(false,false); }}
                window.dispatchEvent(new Event('resize'));
        }}
        if(mq.addEventListener) mq.addEventListener('change',onViewport); else mq.addListener(onViewport);
        onViewport();
}}

function selectDomain(domain){{
    CURRENT_DOMAIN = domain||'all';
    document.querySelectorAll('.tm-node').forEach(function(g){{ g.classList.remove('tm-selected'); }});
    if(domain&&domain!=='all'){{
        var n=document.querySelector('.tm-node[data-domain="'+domain+'"]');
        if(n) n.classList.add('tm-selected');
    }}
    document.querySelectorAll('.cluster').forEach(function(el){{
        if(CURRENT_DOMAIN==='all'){{el.style.display='block';return;}}
        var ds=(el.getAttribute('data-domains')||'').split(/\\s+/);
        el.style.display=ds.indexOf(CURRENT_DOMAIN)>=0?'block':'none';
    }});
    var subset=CURRENT_DOMAIN==='all'?CARDS:CARDS.filter(function(c){{return(c.domains||[]).indexOf(CURRENT_DOMAIN)>=0;}});
    var p1=subset.filter(function(c){{return c.priority==='P1';}}).length;
    var maxRisk=subset.reduce(function(m,c){{return Math.max(m,c.risk_score||0);}},0);
    var lbl=DOMAIN_LABELS[domain]||domain||'All domains';
    var lines=subset.slice().sort(function(a,b){{return(b.risk_score||0)-(a.risk_score||0);}}).slice(0,5)
        .map(function(c){{return '<li style="margin:.2rem 0">'+c.title+' <span style="color:#5a7090">('+c.risk_score+')</span></li>';}}).join('');
    var t=document.getElementById('tm-detail');
    if(t){{
        t.innerHTML='<strong style="color:#c9d1d9">'+lbl+'</strong>'
            +'<div style="color:#6a7f98;font-size:.75rem;margin:.2rem 0 .35rem">Findings: '+subset.length+' &middot; P1: '+p1+' &middot; Max risk: '+maxRisk+'</div>'
            +(lines?'<ul style="margin:.3rem 0 0 1rem;padding:0;font-size:.78rem">'+lines+'</ul>':'<div style="color:#5a7090;font-size:.78rem">No findings in this window.</div>');
    }}
    trackUi('domain_selected',{{domain:CURRENT_DOMAIN,count:subset.length,maxRisk:maxRisk}});
}}
(function(){{
  var SLOTS=[0,6,12,18],MIN=5;
  var el=document.getElementById('next-run-cd');
  if(!el)return;
  var fmt=new Intl.DateTimeFormat('en-US',{{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}});
  function etP(d){{return fmt.formatToParts(d).reduce(function(a,p){{if(p.type!='literal')a[p.type]=+p.value;return a;}},{{}});}}
  function nextRun(now){{
    var et=etP(now);
    for(var d=0;d<2;d++){{
      for(var i=0;i<SLOTS.length;i++){{
        if(d===0&&(SLOTS[i]<et.hour||(SLOTS[i]===et.hour&&MIN<=et.minute)))continue;
        var noon=new Date(Date.UTC(et.year,et.month-1,et.day+d,12,0,0));
        var off=12-etP(noon).hour;
        var cand=new Date(Date.UTC(et.year,et.month-1,et.day+d,SLOTS[i]+off,MIN,0));
        if(cand>now)return cand;
      }}
    }}
    return new Date(now.getTime()+7*3600*1000);
  }}
  function pad(n){{return String(n).padStart(2,'0');}}
  function tick(){{
    var now=new Date(),next=nextRun(now);
    var diff=Math.max(0,Math.floor((next-now)/1000));
    var h=Math.floor(diff/3600),m=Math.floor((diff%3600)/60),s=diff%60;
    el.textContent='Next run '+pad(h)+':'+pad(m)+':'+pad(s);
    el.title='Next run: '+next.toLocaleTimeString('en-US',{{timeZone:'America/New_York',hour:'2-digit',minute:'2-digit'}})+' ET';
    el.className='next-run'+(diff<600?' soon':'')+(diff<60?' now':'');
  }}
  tick();setInterval(tick,1000);
}})();
function initFindingsFilter(){{
  var inp=document.getElementById('findings-search');
  var allClusters=Array.from(document.querySelectorAll('.cluster'));
  var currentTactic='all';
  function applyFilters(){{
    var q=inp?inp.value.trim().toLowerCase():'';
    var visible=0;
    allClusters.forEach(function(el){{
      var inDomain=CURRENT_DOMAIN==='all'||(el.getAttribute('data-domains')||'').split(/\\s+/).indexOf(CURRENT_DOMAIN)>=0;
      var inTactic=currentTactic==='all'||(el.getAttribute('data-tactic')||'')=== currentTactic;
      var inSearch=!q||el.textContent.toLowerCase().includes(q);
      el.style.display=(inDomain&&inTactic&&inSearch)?'':'none';
      if(inDomain&&inTactic&&inSearch)visible++;
    }});
    var cnt=document.getElementById('findings-count');
    if(cnt)cnt.textContent=(q||currentTactic!=='all')?visible+' of '+allClusters.length+' shown':'';
  }}
  if(inp)inp.addEventListener('input',applyFilters);
  document.querySelectorAll('.tactic-btn').forEach(function(btn){{
    btn.addEventListener('click',function(){{
      currentTactic=btn.getAttribute('data-tactic');
      document.querySelectorAll('.tactic-btn').forEach(function(b){{b.classList.toggle('tactic-btn--active',b===btn);}});
      applyFilters();
    }});
  }});
}}
initRightRail();
selectDomain('all');
initFindingsFilter();
</script>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(page_html)


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
