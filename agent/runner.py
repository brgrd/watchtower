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

import feedparser
import requests
import tldextract
import yaml
from bs4 import BeautifulSoup

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
    if host.endswith(".local") or host.endswith(".lan"):
        return True
    return host.startswith(PRIVATE_PREFIXES) or host == "::1"


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
                published = datetime(*val[:6])
                break
        if published and published < cutoff:
            continue
        published_iso = (
            published.replace(tzinfo=timezone.utc).isoformat() if published else ""
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
        }
        for it in kev_items[:6]
    ]
    nvd_block = [
        {"cve": it["title"], "description": it.get("summary", "")[:80]}
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
            "You are a senior threat intelligence analyst writing a concise briefing "
            f"for the period {reporting_window}. "
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
            "isolate, or monitor, and name the affected product/version if available. "
            "Do NOT use vague language like 'various systems' or 'multiple vendors' — always name names. "
            "Keep the summary anchored to the reporting window and only reference items present in the input data. "
            "(2) findings: JSON array of up to 12 distinct threat or vulnerability findings. "
            "For each finding: title (under 100 chars), summary (1-2 sentence analyst note "
            "on what is affected, exploit/patch status, urgency), risk_score (integer 0-100: "
            "base 40 for known CVE, +30 if actively exploited in the wild, +15 if PoC exists, "
            "+15 if critical infrastructure), domains (array of matching keys from: "
            + domain_keys
            + "), references (array of {title, url} — cite ONLY urls that appear verbatim "
            "in the news_articles input, 1-3 most relevant per finding), priority (P1|P2|P3), "
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


def classify_domains(item: dict) -> list:
    txt = (item.get("title", "") + " " + item.get("summary", "")).lower()
    matched = []
    for bucket, cfg in _TAXONOMY.items():
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
    if all_items:
        for it in all_items:
            cc = it.get("country", "")
            url = it.get("url", "")
            if cc and url:
                url_to_country[url] = cc
                dom = tldextract.extract(url).registered_domain
                if dom and dom not in domain_to_country:
                    domain_to_country[dom] = cc

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


def _build_threat_map_svg(cards: list, heatmap: dict) -> str:
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
        bloom_op = round(0.20 + t * 0.72, 3)  # outer aura fill: 0.24 → 0.92
        ring_op = round(0.40 + t * 0.55, 3)  # edge ring stroke: 0.43 → 0.95
        if s >= 85:
            bloom = f"rgba(255,40,40,{bloom_op})"
            ring = f"rgba(255,80,80,{ring_op})"
        else:
            bloom = f"rgba(30,110,255,{bloom_op})"
            ring = f"rgba(70,155,255,{ring_op})"
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
        'style="width:100%;height:auto;display:block;background:#090d18;border-radius:8px;border:1px solid #161d2a">',
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
    p.append('<g opacity="0.04">')
    for gx in range(44, W, 62):
        for gy in range(32, H, 62):
            p.append(f'<circle cx="{gx}" cy="{gy}" r="1" fill="#7090a8"/>')
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
            f'stroke="rgba(55,110,195,{glow_op:.3f})" stroke-width="5.5" '
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
            f'stroke="rgba(70,130,210,{line_op:.3f})" stroke-width="1.1" '
            f'stroke-linecap="round"/>'
        )

    # Nodes
    node_id = 0
    for key, (cx, cy, lbl) in _TM_NODES.items():
        s = scores[key]
        outer, ring_color = _heat(s)
        R = 24
        lf = "#c8d8e8" if s >= 20 else "#5a6a7a"

        p.append(
            f'<g class="tm-node" data-domain="{key}" '
            f'onclick="selectDomain(\'{key}\')" style="cursor:pointer">'
        )
        # Layer 1: Outer aura — large fill, heavy blur, sits BEHIND disc
        p.append(
            f'<circle cx="{cx}" cy="{cy}" r="{R+16}" fill="{outer}" filter="url(#f-outer)"/>'
        )
        # Layer 2: Opaque dark disc — covers center so only perimeter glow shows
        p.append(
            f'<circle class="node-disc" cx="{cx}" cy="{cy}" r="{R}" '
            f'fill="rgba(4,8,18,0.92)" stroke="rgba(80,110,160,0.25)" stroke-width="0.8"/>'
        )
        # Layer 3: Edge ring — stroke-only at disc radius, medium blur, glows outward from rim
        p.append(
            f'<circle cx="{cx}" cy="{cy}" r="{R}" '
            f'fill="none" stroke="{ring_color}" stroke-width="4" filter="url(#f-mid)"/>'
        )
        # Selection ring — simple white ring, hidden at rest
        p.append(
            f'<circle class="sel-indicator" cx="{cx}" cy="{cy}" r="{R+5}" '
            f'fill="none" stroke="rgba(255,255,255,0.75)" stroke-width="1.5"/>'
        )
        # Label
        ly = cy + R + 13
        p.append(
            f'<text x="{cx}" y="{ly}" text-anchor="middle" '
            f'font-family="system-ui,sans-serif" font-size="10" font-weight="600" '
            f'fill="{lf}" stroke="#03060e" stroke-width="2.5" paint-order="stroke fill">{lbl}</text>'
        )
        p.append("</g>")
        node_id += 1

    p.append("</svg>")
    return "\n".join(p)


def _build_domain_rank_html(cards: list, heatmap: dict) -> str:
    """Ranked domain bar list for the threat map side panel."""
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
        rows.append(
            f'<div class="rank-row" onclick="selectDomain(\'{key}\')">'
            f'<span class="rank-label" style="color:{lc}" title="{lbl}">{lbl}</span>'
            f'<div class="rank-bar-wrap"><div class="rank-bar" style="width:{pct}%;background:{bcol}"></div></div>'
            f'<span class="rank-val" style="color:{vc}">{sc}</span>'
            f"</div>"
        )
    if not rows:
        return '<div class="muted" style="font-size:.78rem;padding:.4rem 0">No active findings in this window.</div>'
    return "".join(rows)


def _write_index_html(
    path: str,
    cards: list,
    heatmap: dict,
    ts: str,
    executive: str = "",
    history: list = None,
    since_hours: int = 6,
    groq_status: str = "unknown",
):
    # KPI stats
    total_findings = len(cards)
    p1_count = sum(1 for c in cards if _derive_priority(c) == "P1")
    exploited_count = sum(1 for c in cards if _is_exploitish(c))
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
        delta = b - a
        trend_txt = f"{delta:+d}"

    kpi_html = f"""
        <section class="kpi-grid">
            <div class="kpi"><span class="k">Findings</span><span class="v">{total_findings}</span></div>
            <div class="kpi"><span class="k">P1</span><span class="v">{p1_count}</span></div>
            <div class="kpi"><span class="k">Exploited</span><span class="v">{exploited_count}</span></div>
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

    threat_svg = _build_threat_map_svg(cards, heatmap)
    domain_rank_html = _build_domain_rank_html(cards, heatmap)

    history_section = ""
    if history:
        polled_vals = [e["counts"]["polled"] for e in history]
        cluster_vals = [e["counts"]["clusters"] for e in history]
        p_spark = _sparkline_svg(polled_vals, color="#0366d6")
        c_spark = _sparkline_svg(cluster_vals, color="#28a745")
        history_section = (
            f'<div class="history-panel">'
            f'<span class="hs-label">Fresh&nbsp;items</span>&nbsp;{p_spark}&nbsp;<span class="hs-val">{polled_vals[-1]}</span>'
            f'&emsp;<span class="hs-label">Findings over time</span>&nbsp;{c_spark}&nbsp;<span class="hs-val">{cluster_vals[-1]}</span>'
            f'&emsp;<span class="hs-label">Runs&nbsp;logged</span>&nbsp;<span class="hs-val">{len(history)}</span>'
            f"</div>"
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
        rows += f"""
                <details class="cluster" data-domains="{html.escape(domains_attr)}">
                    <summary>
                        <span class="badge" style="background:{badge_bg};color:{badge_fg}">{c['risk_score']}</span>
                        <span class="priority {pri_cls}">{pri}</span>
                        {html.escape(c['title'])}
                        <div class="domain-tags" style="margin:0 0 0 .5rem;display:inline">{tags}</div>
                    </summary>
                    <div class="cluster-body">
                        <p>{html.escape(c['summary'])}</p>
                        {f'<p class="why-now"><strong>Why now:</strong> {why_now}</p>' if why_now else ''}
                        {conf_txt}
                        {f'<div class="actions"><div><strong>Next 24h</strong><ul>{act24_html}</ul></div><div><strong>Next 7d</strong><ul>{act7_html}</ul></div></div>' if (act24_html or act7_html) else ''}
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
*{{box-sizing:border-box}}
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:#080c12}}
::-webkit-scrollbar-thumb{{background:#1e2c3a;border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:#2c3e50}}
*{{scrollbar-width:thin;scrollbar-color:#1e2c3a #080c12}}
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#c9d1d9}}
h1{{border-bottom:2px solid #30363d;padding-bottom:.4rem;color:#e6edf3}}
h2{{color:#e6edf3}}
a{{color:#58a6ff}}
p{{color:#c9d1d9}}
.kpi-grid{{display:grid;grid-template-columns:repeat(6,minmax(120px,1fr));gap:8px;margin:1rem 0 1.2rem}}
.kpi{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.55rem .7rem;display:flex;flex-direction:column;gap:.2rem}}
.kpi .k{{font-size:.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;font-weight:700}}
.kpi .v{{font-size:1.2rem;color:#e6edf3;font-weight:800}}
.kpi .v-sm{{font-size:.95rem}}
.hm-cell{{border-radius:6px;padding:.7rem .55rem;text-align:center;border:1px solid rgba(255,255,255,.08);cursor:pointer;font-family:inherit}}
.hm-cell.active{{outline:2px solid #1f6feb;outline-offset:1px}}
.hm-label{{display:block;font-size:.72rem;font-weight:700;margin:.15rem 0}} 
.hm-meta{{display:block;font-size:.66rem;opacity:.85}}
.hm-score{{display:block;font-size:1.15rem;font-weight:800;margin-top:.2rem}}
.panel{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.7rem .8rem}}
.panel h3{{margin:.2rem 0 .5rem;font-size:.92rem;color:#e6edf3}}
.panel .muted{{color:#8b949e;font-size:.8rem}}
.feed-table{{width:100%;border-collapse:collapse;font-size:.78rem}}
.feed-table th,.feed-table td{{border-bottom:1px solid #30363d;padding:.3rem .2rem;text-align:left}}
.matrix-panel{{margin:.2rem 0 1rem}}
.risk-matrix{{width:100%;border-collapse:separate;border-spacing:4px;table-layout:fixed}}
.risk-matrix th{{font-size:.68rem;color:#8b949e;font-weight:700;text-align:center;letter-spacing:.02em}}
.risk-matrix .mx-row{{text-align:left;padding-left:.3rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:160px}}
.mx-cell{{height:44px;border:1px solid #30363d;border-radius:6px;position:relative;text-align:center;vertical-align:middle;overflow:hidden;transition:filter .12s ease,transform .12s ease}}
.mx-cell:hover{{filter:brightness(1.1);transform:translateY(-1px)}}
.mx-dot{{position:absolute;left:50%;top:50%;width:20px;height:20px;border-radius:999px;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(88,166,255,.75) 0%, rgba(88,166,255,.05) 70%)}}
.mx-count{{position:relative;display:block;font-size:.82rem;font-weight:800;color:#e6edf3;line-height:1}}
.cluster{{background:rgba(255,255,255,0.01);border:1px solid #2b313a;border-radius:6px;padding:0;margin:.55rem 0;overflow:hidden}}
.cluster summary{{list-style:none;padding:.62rem .85rem;cursor:pointer;display:flex;align-items:center;gap:.35rem;user-select:none;color:#c9d1d9;font-size:.92rem}}
.cluster summary::-webkit-details-marker{{display:none}}
.cluster summary::before{{content:"▶";font-size:.7rem;transition:transform .15s;flex-shrink:0;color:#8b949e}}
.cluster[open] summary::before{{transform:rotate(90deg)}}
.cluster-body{{padding:.2rem .9rem .85rem;color:#c9d1d9}}
.badge{{border-radius:999px;padding:2px 8px;font-size:.72rem;font-weight:700;margin-right:.35rem;background:rgba(255,255,255,.06)!important;color:#c9d1d9!important}}
.priority{{border-radius:999px;padding:2px 8px;font-size:.68rem;font-weight:800;letter-spacing:.02em;margin-right:.3rem;border:1px solid #30363d}}
.priority.p1{{background:rgba(170,28,28,.16);color:#c88888;border-color:rgba(170,28,28,.36)}}
.priority.p2{{background:rgba(50,80,125,.15);color:#8aa8c0;border-color:rgba(50,80,125,.30)}}
.priority.p3{{background:#21262d;color:#c9d1d9}}
.domain-tags{{margin:.3rem 0 .6rem}} .domain-tag{{display:inline-block;background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:3px;font-size:.7rem;padding:1px 6px;margin:0 3px 3px 0}}
.executive{{background:#0e1620;border-left:3px solid #2e5070;border-radius:4px;padding:.8rem 1.1rem;margin:1rem 0 1.8rem}}
.executive h2{{margin:0 0 .4rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:#4e7898}}
.executive p{{margin:0;line-height:1.75;font-size:.95rem;color:#c9d1d9}}
.history-panel{{background:#161b22;border:1px solid #30363d;border-radius:4px;padding:.45rem 1rem;margin:0 0 1.2rem;display:flex;align-items:center;gap:.8rem;flex-wrap:wrap}}
.hs-label{{color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:.68rem}}
.hs-val{{font-weight:700;font-size:.85rem;color:#e6edf3}}
.actions{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:.4rem 0 .7rem}}
.actions ul{{margin:.3rem 0 .2rem 1rem;padding:0}}
.confidence{{display:inline-block;font-size:.72rem;color:#8b949e;border:1px solid #30363d;border-radius:999px;padding:2px 8px;margin-bottom:.3rem}}
.threat-section{{display:grid;grid-template-columns:2fr 1fr;gap:12px;align-items:start;margin:0 0 1rem}}
.threat-main{{padding:.3rem .4rem .5rem}}
.threat-toolbar{{display:flex;justify-content:space-between;align-items:center;padding:.3rem .3rem .45rem}}
.threat-title{{font-size:.9rem;font-weight:700;color:#e6edf3}}
.threat-sub{{font-size:.72rem;color:#8b949e}}
.threat-side{{overflow-y:auto;max-height:580px}}
.tm-node .node-disc{{transition:stroke .12s,stroke-width .12s}}
.tm-node:hover .node-disc{{stroke:rgba(120,160,220,0.5)!important;stroke-width:1.4px!important}}
.tm-node .sel-indicator{{opacity:0;transition:opacity .18s}}
.tm-node.tm-selected .sel-indicator{{opacity:1}}
.rank-row{{display:flex;align-items:center;gap:6px;padding:.28rem 0;border-bottom:1px solid #161d2a;cursor:pointer;border-radius:3px}}
.rank-row:hover{{background:rgba(255,255,255,.03)}}
.rank-label{{font-size:.77rem;flex:0 0 92px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.rank-bar-wrap{{flex:1;background:#0e1520;border-radius:2px;height:3px}}
.rank-bar{{height:3px;border-radius:2px;min-width:1px}}
.rank-val{{font-size:.7rem;font-weight:700;flex:0 0 22px;text-align:right}}
.chip{{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #30363d;background:#21262d;color:#c9d1d9;font-size:.72rem}}
.next-run{{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;border:1px solid #1a3a5c;background:#0d1f30;color:#58a6ff;font-size:.72rem;font-variant-numeric:tabular-nums;margin-left:.6rem}}
.next-run.soon{{border-color:#4a2a00;background:#1c1000;color:#e3a020}}
.next-run.now{{border-color:#1a3a1a;background:#0a1f0a;color:#3fb950;animation:pulse-now 1s ease-in-out infinite}}
@keyframes pulse-now{{0%,100%{{opacity:1}}50%{{opacity:.55}}}}
footer{{color:#8b949e;font-size:.8rem;margin-top:2rem;padding-top:.8rem;border-top:1px solid #30363d}}
@media (max-width:900px){{.kpi-grid{{grid-template-columns:repeat(3,minmax(110px,1fr));}}.threat-section{{grid-template-columns:1fr;}}}}
        </style>
        </head>
        <body>
        <h1>Watchtower — Infrastructure Security Briefing</h1>
        <p>Generated <strong>{ts.replace('_', ' ')}</strong> UTC | <a href="latest.md">latest.md</a><span class="next-run" id="next-run-cd" title="Scheduled runs: 00:05, 06:05, 12:05, 18:05 ET">⏱ next run —</span></p>
        {f'<div class="executive"><h2>Analyst Summary</h2><p>{html.escape(executive)}</p></div>' if executive else ''}
{kpi_html}
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
  <aside class="panel threat-side">
    <h3 style="margin:.2rem 0 .45rem">Domain Activity</h3>
    {domain_rank_html}
    <h3 style="margin:.7rem 0 .35rem">Selected Domain</h3>
    <div id="tm-detail" class="muted" style="font-size:.8rem">Click a node to inspect findings.</div>
    <h3 style="margin:.7rem 0 .35rem">Feed Contribution</h3>
    <table class="feed-table"><thead><tr><th>Feed domain</th><th>Refs</th><th>Max risk</th></tr></thead><tbody>{feed_rows}</tbody></table>
  </aside>
</section>
{history_section}
<h2>Top Findings</h2>
{rows}
<footer>Watchtower · scheduled 00:05 / 06:05 / 12:05 / 18:05 ET · placeholder mode: {str(placeholder_mode()).lower()}</footer>
<script>
var CARDS={json.dumps(card_data)};
var CURRENT_DOMAIN='all';
var DOMAIN_LABELS={json.dumps({k: v.get('label', k) for k, v in heatmap.items()})};

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
    el.textContent='⏱ '+pad(h)+':'+pad(m)+':'+pad(s);
    el.title='Next run: '+next.toLocaleTimeString('en-US',{{timeZone:'America/New_York',hour:'2-digit',minute:'2-digit'}})+' ET';
    el.className='next-run'+(diff<600?' soon':'')+(diff<60?' now':'');
  }}
  tick();setInterval(tick,1000);
}})();
</script>
</body></html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(page_html)


# -----------------------------
# Main
# -----------------------------
def _run():
    from agent.planning import dispatch_plan

    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)

    ignore = load_json(
        IGNORE_FILE, {"ignore_url": {}, "ignore_domain": {}, "ignore_url_prefix": {}}
    )
    seen = load_seen()

    budgets = CONFIG["budgets"]
    since_hours = budgets.get("since_hours", 6)
    feeds_cfg = [f for f in CONFIG["feeds"] if f.get("enabled", True)]
    run_deadline = time.monotonic() + budgets["max_runtime_seconds"]

    polled = []
    feed_workers = budgets.get("max_fetch_workers", 6)
    feeds_to_poll = feeds_cfg[: budgets["max_feeds_polled"]]

    def _poll_one(fcfg):
        if time.monotonic() > run_deadline:
            return []
        return poll_feed(fcfg, since_hours, ignore)

    with ThreadPoolExecutor(max_workers=feed_workers) as pool:
        futs = [pool.submit(_poll_one, fcfg) for fcfg in feeds_to_poll]
        for fut in as_completed(futs):
            if time.monotonic() > run_deadline:
                print("[WARN] Runtime budget reached during feed polling")
                break
            try:
                polled.extend(fut.result())
            except Exception as exc:
                print(f"[WARN] Feed poll task failed: {exc}")

    polled, seen = deduplicate(polled, seen)
    save_seen(seen)

    first_seen = now_utc_iso()
    for it in polled:
        it.setdefault("first_seen_at", first_seen)

    polled = dispatch_plan(
        {"steps": [{"tool": "CLUSTER", "args": {"window_hours": since_hours}}]},
        polled,
        ignore,
        budgets,
        since_hours,
        run_deadline,
    )

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
    with open(out_jsonl, "w", encoding="utf-8") as f:
        for c in cards:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

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
        },
    )

    history = _read_ledger_history()
    _write_index_html(
        index_html,
        cards,
        heatmap,
        ts,
        executive,
        history,
        since_hours=since_hours,
        groq_status=groq_status,
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
