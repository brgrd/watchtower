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
    while True:
        r = requests.get(url, params=params, headers=headers, timeout=30)
        if r.status_code == 429:
            time.sleep(30)
            continue
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
        if params["startIndex"] >= total:
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
    try:
        if feed_type == "json_api":
            if "nvd.nist.gov" in url or "services.nvd.nist.gov" in url:
                return _poll_nvd_api(url, since_hours, ignore)
            if "cisa.gov" in url and "known_exploited" in url:
                return _poll_cisa_kev(url, ignore, since_hours)

            r = requests.get(url, headers={"User-Agent": "Watchtower/1.0"}, timeout=30)
            r.raise_for_status()
            raw = r.json()
            entries = (
                raw
                if isinstance(raw, list)
                else raw.get("items", raw.get("entries", []))
            )
            out = []
            for e in entries:
                link = str(e.get("url", e.get("link", "")))
                if not link:
                    continue
                out.append(
                    {
                        "title": str(e.get("title", ""))[:200],
                        "url": link,
                        "summary": str(e.get("summary", e.get("description", "")))[
                            :500
                        ],
                        "source": url,
                    }
                )
            return out

        return _poll_rss(url, since_hours, ignore)
    except Exception as exc:
        print(f"[WARN] poll_feed failed for {url}: {exc}")
        return []


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


def request_action_plan(goal, budget, context):
    if placeholder_mode():
        return {
            "run_goal": goal,
            "budget": budget,
            "steps": [
                {
                    "tool": "CLUSTER",
                    "args": {"window_hours": CONFIG["budgets"].get("since_hours", 6)},
                }
            ],
        }

    sys_prompt = "You are a planner. Output strict JSON only."
    user = {
        "run_goal": goal,
        "budget": budget,
        "context": {"recent_sources": [s["url"] for s in context[:10]]},
        "schema": {
            "steps": [
                {"tool": "POLL_FEED", "args": {"feed_id": "str", "since_hours": "int"}},
                {"tool": "ADD_FEED", "args": {"url": "str", "category": "str"}},
                {"tool": "CLUSTER", "args": {"window_hours": "int"}},
                {"tool": "SELECT_SOURCES", "args": {"cluster_id": "str"}},
            ]
        },
    }

    content, _ = groq_chat(
        [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": json.dumps(user)},
        ],
        model=CONFIG["model"]["name"],
        temperature=0.1,
        max_tokens=600,
    )

    try:
        plan = json.loads(content)
        assert isinstance(plan.get("steps"), list)
        return plan
    except Exception:
        return {
            "run_goal": goal,
            "budget": budget,
            "steps": [{"tool": "CLUSTER", "args": {"window_hours": 6}}],
        }


def groq_summarize_clusters(cards: list, max_clusters: int = 8) -> tuple:
    """Single Groq call: (executive_summary_str, {card_id: summary_str}).

    Token budget: ~1500 input + ~900 output ≈ 2400 tokens per run.
    Returns empty strings/dict on placeholder mode or any failure.
    """
    if placeholder_mode() or not GROQ_API_KEY:
        return "", {}

    cluster_inputs = [
        {
            "id": c["id"],
            "title": c["title"],
            "risk_score": c["risk_score"],
            "domains": c.get("domains", []),
            "snippet": c.get("_raw_snippets", "")[:800],
        }
        for c in cards[:max_clusters]
    ]

    prompt = {
        "task": "infrasec_briefing_summary",
        "clusters": cluster_inputs,
        "instructions": (
            "For each cluster write a 2-sentence analyst summary covering: what is "
            "affected, exploitation/patch status, and urgency. "
            "Also write an executive_summary (3 sentences max) covering the overall "
            "threat picture, any notable geographic or actor patterns, and the top "
            "action item. "
            'Output ONLY strict JSON (no markdown): '
            '{"executive_summary":"...","summaries":{"<id>":"2-sentence summary..."}}'
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
            max_tokens=900,
        )
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```[a-z]*\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())
        data = json.loads(content)
        return data.get("executive_summary", ""), data.get("summaries", {})
    except Exception as exc:
        print(f"[WARN] Groq summarization failed: {exc}")
        return "", {}


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
        k: {"label": v["label"], "icon": v.get("icon", ""), "max_score": 0, "count": 0}
        for k, v in _TAXONOMY.items()
    }
    heat["uncategorised"] = {"label": "Other", "icon": "❓", "max_score": 0, "count": 0}
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
    # Aggregate raw text for Groq summarization (stripped from final output)
    raw_snippets = []
    for it in items[:3]:
        if it.get("summary"):
            raw_snippets.append(it["summary"][:300])
        if it.get("extracted_text"):
            raw_snippets.append(it["extracted_text"][:500])
    return {
        "id": sha256(key)[:12],
        "risk_score": score_cluster(key, items),
        "domains": domains,
        "title": items[0]["title"][:140] if items else key,
        "summary": "",
        "_raw_snippets": " | ".join(raw_snippets)[:1000],
        "sources": {
            "primary": [
                {"title": it["title"][:120], "url": it["url"]} for it in items[:5]
            ],
            "secondary": [],
        },
    }


# -----------------------------
# Dedup
# -----------------------------
def load_seen() -> set:
    d = load_json(SEEN_FILE, {"hashes": []})
    return set(d.get("hashes", []))


def save_seen(seen: set):
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


def _write_index_html(path: str, cards: list, heatmap: dict, ts: str, executive: str = ""):
    heat_cells = ""
    for bucket_id, data in heatmap.items():
        if data["count"] == 0 and bucket_id == "uncategorised":
            continue
        bg, fg = _heatmap_cell_color(data["max_score"], data["count"])
        score_txt = str(data["max_score"]) if data["count"] > 0 else "—"
        heat_cells += f"""
                    <div class=\"hm-cell\" style=\"background:{bg};color:{fg}\" title=\"{html.escape(data['label'])}: {data['count']} finding(s), max score {score_txt}\">
                        <span class=\"hm-icon\">{html.escape(data['icon'])}</span>
                        <span class=\"hm-label\">{html.escape(data['label'])}</span>
            <span class=\"hm-score\">{score_txt}</span>
          </div>"""

    rows = ""
    for c in cards:
        links = "".join(
            f'<li><a href="{html.escape(s["url"])}" target="_blank" rel="noopener noreferrer">{html.escape(s["title"])}</a></li>'
            for s in c["sources"]["primary"]
        )
        badge_bg, badge_fg = _heatmap_cell_color(c["risk_score"], 1)
        tags = " ".join(
            f'<span class="domain-tag">{html.escape(_TAXONOMY.get(d, {}).get("icon", ""))} {html.escape(_TAXONOMY.get(d, {}).get("label", d))}</span>'
            for d in c.get("domains", [])
            if d != "uncategorised"
        )
        rows += f"""
        <section class=\"cluster\">
                    <h2><span class=\"badge\" style=\"background:{badge_bg};color:{badge_fg}\">{c['risk_score']}</span>{html.escape(c['title'])}</h2>
          <div class=\"domain-tags\">{tags}</div>
                    <p>{html.escape(c['summary'])}</p>
          <ul>{links}</ul>
        </section>"""

    page_html = f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Watchtower — InfraSec Briefing</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#24292e}}
h1{{border-bottom:2px solid #e1e4e8;padding-bottom:.4rem}}
.heatmap{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px;margin:1.2rem 0 2rem}}
.hm-cell{{border-radius:6px;padding:.6rem .5rem;text-align:center;border:1px solid rgba(0,0,0,.08)}}
.hm-icon{{display:block;font-size:1.4rem}} .hm-label{{display:block;font-size:.68rem;font-weight:600;margin:.2rem 0}} .hm-score{{display:block;font-size:1.1rem;font-weight:700}}
.cluster{{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:1rem;margin:1rem 0}}
.badge{{border-radius:3px;padding:2px 8px;font-size:.8rem;font-weight:700;margin-right:.5rem}}
.domain-tags{{margin:.3rem 0 .6rem}} .domain-tag{{display:inline-block;background:#e1e4e8;border-radius:3px;font-size:.7rem;padding:1px 6px;margin:0 3px 3px 0}}
a{{color:#0366d6}}
.executive{{background:#fff8e1;border-left:4px solid #f9c74f;border-radius:4px;padding:.8rem 1.1rem;margin:1rem 0 1.8rem}}
.executive h2{{margin:0 0 .4rem;font-size:.8rem;text-transform:uppercase;letter-spacing:.07em;color:#7a5c00}}
.executive p{{margin:0;line-height:1.75;font-size:.95rem}}
</style>
</head>
<body>
<h1>🔭 Watchtower — Infrastructure Security Briefing</h1>
<p>Generated <strong>{ts.replace('_', ' ')}</strong> UTC | <a href="latest.md">latest.md</a></p>
{f'<div class="executive"><h2>Analyst Summary</h2><p>{html.escape(executive)}</p></div>' if executive else ''}
<h2>Domain Heat Map</h2>
<div class=\"heatmap\">{heat_cells}</div>
<h2>Top Findings</h2>
{rows}
<footer>Watchtower · local-safe placeholder mode: {str(placeholder_mode()).lower()}</footer>
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

    plan = request_action_plan(
        goal="Produce infrastructure security briefing",
        budget={
            "max_steps": budgets["max_agent_steps"],
            "max_url_fetches": budgets["max_url_fetches"],
            "max_new_feeds": budgets["max_new_feeds"],
        },
        context=polled,
    )

    polled = dispatch_plan(plan, polled, ignore, budgets, since_hours, run_deadline)

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

    # Groq: generate per-cluster summaries + executive narrative (single call)
    executive, summaries = groq_summarize_clusters(cards)
    for c in cards:
        if c["id"] in summaries and summaries[c["id"]]:
            c["summary"] = summaries[c["id"]]
        elif not c["summary"]:
            c["summary"] = f"{len(c['sources']['primary'])} related updates."
        c.pop("_raw_snippets", None)  # remove internal field before output

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
    _write_index_html(index_html, cards, heatmap, ts, executive)

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
            "plan_steps": len(plan.get("steps", [])),
            "placeholder_mode": placeholder_mode(),
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
