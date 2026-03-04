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

COUNTRY_META: dict = {
    "US": {"label": "United States", "cc": "US"},
    "GB": {"label": "United Kingdom", "cc": "GB"},
    "DE": {"label": "Germany", "cc": "DE"},
    "FR": {"label": "France", "cc": "FR"},
    "AU": {"label": "Australia", "cc": "AU"},
    "EU": {"label": "EU / CERT-EU", "cc": "EU"},
    "JP": {"label": "Japan", "cc": "JP"},
    "CA": {"label": "Canada", "cc": "CA"},
    "SG": {"label": "Singapore", "cc": "SG"},
    "NZ": {"label": "New Zealand", "cc": "NZ"},
}


def placeholder_mode() -> bool:
    val = os.getenv("WATCHTOWER_PLACEHOLDER_MODE")
    if val is None:
        return bool(CONFIG.get("runtime", {}).get("placeholder_mode_default", True))
    return val.strip().lower() in {"1", "true", "yes", "on"}


# -----------------------------
# Utilities
# -----------------------------
def now_utc_iso() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()


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
    ttl = (datetime.utcnow() + timedelta(days=ttl_days)).date().isoformat()
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
    fp = feedparser.parse(url)
    items = []
    cutoff = datetime.utcnow() - timedelta(hours=since_hours)
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
        items.append(
            {
                "title": getattr(e, "title", "")[:200],
                "url": link,
                "summary": getattr(e, "summary", "")[:500],
                "source": url,
            }
        )
    return items


def _poll_nvd_api(url: str, since_hours: int, ignore: dict) -> list:
    cutoff = datetime.utcnow() - timedelta(hours=since_hours)
    params = {
        "pubStartDate": cutoff.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
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
    cutoff = (datetime.utcnow() - timedelta(hours=since_hours)).date()
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
    if country:
        for it in items:
            it["country"] = country
    return items


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

    Returns (executive_summary: str, findings: list).
    Each finding: {title, summary, risk_score, domains, references: [{title, url}]}
    References point back to URLs from news_items so Top Findings are citable.
    """
    if placeholder_mode() or not GROQ_API_KEY:
        return "", []

    kev_block = [
        {
            "cve": it["title"].split("\u2014")[0].strip(),
            "description": it.get("summary", "")[:200],
        }
        for it in kev_items[:15]
    ]
    nvd_block = [
        {"cve": it["title"], "description": it.get("summary", "")[:150]}
        for it in nvd_items[:20]
    ]
    article_block = [
        {
            "headline": it["title"][:150],
            "source": tldextract.extract(it.get("url", "")).registered_domain
            or "unknown",
            "snippet": (it.get("extracted_text", "") or it.get("summary", ""))[:400],
            "url": it.get("url", ""),
        }
        for it in news_items[:30]
    ]

    domain_keys = ", ".join(_TAXONOMY.keys())
    prompt = {
        "task": "infrasec_briefing",
        "exploited_vulnerabilities": kev_block,
        "recent_cves": nvd_block,
        "news_articles": article_block,
        "instructions": (
            "You are a senior threat intelligence analyst. "
            "Review all inputs: exploited vulnerabilities (CISA KEV), recent CVEs (NVD), "
            "and news articles. Produce: "
            "(1) executive_summary: 2-3 sentences covering the overall threat landscape — "
            "dominant themes, most at-risk technology stacks, and the single most urgent "
            "action item for a security team. "
            "(2) findings: JSON array of up to 12 distinct threat or vulnerability findings. "
            "For each finding: title (under 100 chars), summary (1-2 sentence analyst note "
            "on what is affected, exploit/patch status, urgency), risk_score (integer 0-100: "
            "base 40 for known CVE, +30 if actively exploited in the wild, +15 if PoC exists, "
            "+15 if critical infrastructure), domains (array of matching keys from: "
            + domain_keys
            + "), references (array of {title, url} — cite ONLY urls that appear verbatim "
            "in the news_articles input, 1-3 most relevant per finding). "
            'Output ONLY strict JSON, no markdown fences: {"executive_summary":"...",'
            '"findings":[{"title":"...","summary":"...","risk_score":0,"domains":[],'
            '"references":[{"title":"...","url":"..."}]}]}'
        ),
    }

    try:
        content, _ = groq_chat(
            [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst. Output strict JSON only. No markdown fences.",
                },
                {"role": "user", "content": json.dumps(prompt)},
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
        return data.get("executive_summary", ""), data.get("findings", [])
    except Exception as exc:
        print(f"[WARN] Groq analysis failed: {exc}")
        return "", []


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


def build_geo_heatmap(cards: list) -> dict:
    """Country-keyed heatmap derived from source-country tags on feed items."""
    heat: dict = {}
    for c in cards:
        for cc in c.get("countries", []):
            if not cc:
                continue
            if cc not in heat:
                meta = COUNTRY_META.get(cc, {"label": cc, "cc": cc})
                heat[cc] = {
                    "label": meta["label"],
                    "cc": meta.get("cc", cc),
                    "max_score": 0,
                    "count": 0,
                }
            heat[cc]["count"] += 1
            heat[cc]["max_score"] = max(heat[cc]["max_score"], c["risk_score"])
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
    # Build URL → country lookup from polled/enriched items
    url_to_country: dict = {}
    if all_items:
        for it in all_items:
            cc = it.get("country", "")
            url = it.get("url", "")
            if cc and url:
                url_to_country[url] = cc

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

        # Derive countries from reference URLs that match polled item URLs
        countries = list(
            {url_to_country[r["url"]] for r in refs if r.get("url") in url_to_country}
        )

        cards.append(
            {
                "id": sha256(f.get("title", str(len(cards))))[:12],
                "risk_score": score,
                "domains": domains,
                "countries": countries,
                "title": f.get("title", "")[:140],
                "summary": f.get("summary", ""),
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


def _write_index_html(
    path: str,
    cards: list,
    heatmap: dict,
    geo_heatmap: dict,
    ts: str,
    executive: str = "",
    history: list = None,
):
    heat_cells = ""
    for bucket_id, data in heatmap.items():
        if data["count"] == 0 and bucket_id == "uncategorised":
            continue
        bg, fg = _heatmap_cell_color(data["max_score"], data["count"])
        score_txt = str(data["max_score"]) if data["count"] > 0 else "—"
        heat_cells += f"""
                    <div class=\"hm-cell\" style=\"background:{bg};color:{fg}\" title=\"{html.escape(data['label'])}: {data['count']} finding(s), max score {score_txt}\">
                        <span class=\"hm-label\">{html.escape(data['label'])}</span>
            <span class=\"hm-score\">{score_txt}</span>
          </div>"""

    # Build geo data JSON for SVG world map (injected into page as JS vars)
    geo_json = json.dumps({cc: gdata["max_score"] for cc, gdata in geo_heatmap.items()})
    geo_labels_json = json.dumps(
        {
            cc: f"{gdata['label']}: {gdata['count']} source(s), max score {gdata['max_score']}"
            for cc, gdata in geo_heatmap.items()
        }
    )

    history_section = ""
    if history:
        polled_vals = [e["counts"]["polled"] for e in history]
        cluster_vals = [e["counts"]["clusters"] for e in history]
        p_spark = _sparkline_svg(polled_vals, color="#0366d6")
        c_spark = _sparkline_svg(cluster_vals, color="#28a745")
        history_section = (
            f'<div class="history-panel">'
            f'<span class="hs-label">Fresh&nbsp;items</span>&nbsp;{p_spark}&nbsp;<span class="hs-val">{polled_vals[-1]}</span>'
            f'&emsp;<span class="hs-label">Clusters</span>&nbsp;{c_spark}&nbsp;<span class="hs-val">{cluster_vals[-1]}</span>'
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
        tags = " ".join(
            f'<span class="domain-tag">{html.escape(_TAXONOMY.get(d, {}).get("label", d))}</span>'
            for d in c.get("domains", [])
            if d != "uncategorised"
        )
        rows += f"""
        <details class="cluster">
          <summary><span class="badge" style="background:{badge_bg};color:{badge_fg}">{c['risk_score']}</span>{html.escape(c['title'])}<div class="domain-tags" style="margin:0 0 0 .5rem;display:inline">{tags}</div></summary>
          <div class="cluster-body">
            <p>{html.escape(c['summary'])}</p>
            <ul>{links}</ul>
          </div>
        </details>"""

    page_html = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Watchtower — InfraSec Briefing</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#c9d1d9}}
h1{{border-bottom:2px solid #30363d;padding-bottom:.4rem;color:#e6edf3}}
h2{{color:#e6edf3}}
a{{color:#58a6ff}}
p{{color:#c9d1d9}}
.heatmap{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;margin:1.2rem 0 2rem}}
.hm-cell{{border-radius:6px;padding:.6rem .5rem;text-align:center;border:1px solid rgba(255,255,255,.08)}}
.hm-label{{display:block;font-size:.68rem;font-weight:600;margin:.2rem 0}} .hm-score{{display:block;font-size:1.1rem;font-weight:700}}
.cluster{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:0;margin:1rem 0;overflow:hidden}}
.cluster summary{{list-style:none;padding:.75rem 1rem;cursor:pointer;display:flex;align-items:center;gap:.4rem;user-select:none;color:#c9d1d9}}
.cluster summary::-webkit-details-marker{{display:none}}
.cluster summary::before{{content:"▶";font-size:.7rem;transition:transform .15s;flex-shrink:0;color:#8b949e}}
.cluster[open] summary::before{{transform:rotate(90deg)}}
.cluster-body{{padding:.25rem 1rem 1rem;color:#c9d1d9}}
.badge{{border-radius:3px;padding:2px 8px;font-size:.8rem;font-weight:700;margin-right:.5rem}}
.domain-tags{{margin:.3rem 0 .6rem}} .domain-tag{{display:inline-block;background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:3px;font-size:.7rem;padding:1px 6px;margin:0 3px 3px 0}}
.executive{{background:#1c1a10;border-left:4px solid #d4a017;border-radius:4px;padding:.8rem 1.1rem;margin:1rem 0 1.8rem}}
.executive h2{{margin:0 0 .4rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:#d4a017}}
.executive p{{margin:0;line-height:1.75;font-size:.95rem;color:#c9d1d9}}
.hm-tabs{{display:flex;gap:8px;margin:.4rem 0 .8rem}}
.hm-tab{{background:#161b22;border:1px solid #30363d;border-radius:4px;padding:.3rem .9rem;cursor:pointer;font-size:.85rem;font-family:inherit;color:#c9d1d9}}
.hm-tab.active{{background:#1f6feb;color:#fff;border-color:#1f6feb}}
.history-panel{{background:#161b22;border:1px solid #30363d;border-radius:4px;padding:.45rem 1rem;margin:0 0 1.2rem;display:flex;align-items:center;gap:.8rem;flex-wrap:wrap}}
.hs-label{{color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.05em;font-size:.68rem}}
.hs-val{{font-weight:700;font-size:.85rem;color:#e6edf3}}
footer{{color:#8b949e;font-size:.8rem;margin-top:2rem;padding-top:.8rem;border-top:1px solid #30363d}}
</style>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/css/jsvectormap.min.css">
</head>
<body>
<h1>Watchtower — Infrastructure Security Briefing</h1>
<p>Generated <strong>{ts.replace('_', ' ')}</strong> UTC | <a href="latest.md">latest.md</a></p>
{f'<div class="executive"><h2>Analyst Summary</h2><p>{html.escape(executive)}</p></div>' if executive else ''}
<div class="hm-tabs"><button class="hm-tab active" onclick="switchTab('domain')">Domains</button> <button class="hm-tab" onclick="switchTab('geo')">Geography</button></div>
<div id="hm-domain" class="heatmap">{heat_cells}</div>
<div id="hm-geo" style="display:none;margin:1rem 0 2rem"><div id="world-map" style="height:340px"></div><div id="geo-legend" style="display:flex;flex-wrap:wrap;gap:6px;margin:.6rem 0 1rem"></div></div>
{history_section}
<h2>Top Findings</h2>
{rows}
<footer>Watchtower · local-safe placeholder mode: {{str(placeholder_mode()).lower()}}</footer>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/js/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.5.3/dist/maps/world.js"></script>
<script>
var GEO_DATA={geo_json};
var GEO_LABELS={geo_labels_json};
var _mapInit=false;
function initMap(){{
  if(_mapInit)return;_mapInit=true;
  new jsVectorMap({{selector:'#world-map',map:'world',backgroundColor:'#0d1117',zoomButtons:false,
    regionStyle:{{initial:{{fill:'#21262d',stroke:'#30363d',strokeWidth:0.5}},hover:{{fill:'#388bfd',cursor:'pointer'}}}},
    onRegionTooltipShow:function(e,tip,code){{tip.text(GEO_LABELS[code]||code,true);}},
    series:{{regions:[{{values:GEO_DATA,scale:['#1a3a1a','#8b0000'],normalizeFunction:'polynomial',attribute:'fill'}}]}}
  }});
  var leg=document.getElementById('geo-legend');
  Object.keys(GEO_DATA).sort(function(a,b){{return GEO_DATA[b]-GEO_DATA[a];}}).forEach(function(cc){{
    var el=document.createElement('span');
    el.style.cssText='background:#161b22;border:1px solid #30363d;border-radius:4px;padding:3px 10px;font-size:.75rem;color:#c9d1d9';
    el.textContent=GEO_LABELS[cc]||cc;
    leg.appendChild(el);
  }});
}}
function switchTab(t){{
  document.getElementById('hm-domain').style.display=t==='domain'?'grid':'none';
  document.getElementById('hm-geo').style.display=t==='geo'?'block':'none';
  document.querySelectorAll('.hm-tab').forEach(function(b,i){{b.classList.toggle('active',i===(t==='domain'?0:1));}});
  if(t==='geo')initMap();
}}
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
    for fcfg in feeds_cfg[: budgets["max_feeds_polled"]]:
        if time.monotonic() > run_deadline:
            print("[WARN] Runtime budget reached during feed polling")
            break
        polled.extend(poll_feed(fcfg, since_hours, ignore))

    polled, seen = deduplicate(polled, seen)
    save_seen(seen)

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
    executive, findings = groq_analyze_briefing(kev_items, nvd_items, news_items)
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

    ts = datetime.utcnow().strftime("%Y-%m-%d_%H-%M")
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
    geo_heatmap = build_geo_heatmap(cards)

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
    _write_index_html(index_html, cards, heatmap, geo_heatmap, ts, executive, history)

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
