"""AI analysis and finding transformation helpers for Watchtower."""

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
import tldextract
import yaml

from agent.scoring import _TAXONOMY, _extract_cves, classify_domains
from agent.state import sha256

ROOT = os.path.dirname(os.path.dirname(__file__))
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


def _compact_text(s: str) -> str:
    return " ".join((s or "").split()).strip()


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
    if placeholder_mode():
        print("[INFO] Groq skipped: placeholder mode is on")
        return "", [], "placeholder"
    if not GROQ_API_KEY:
        print(
            "[WARN] Groq skipped: GROQ_API_KEY is not set — check GitHub repo secrets"
        )
        return "", [], "no_api_key"

    _now = datetime.now(timezone.utc)
    _months = [
        (_now.replace(day=1) - timedelta(days=30 * i)).strftime("%B %Y")
        for i in range(3)
    ]
    reporting_window = f"{_months[2]} – {_months[0]}"

    all_items = (kev_items or []) + (nvd_items or []) + (news_items or [])
    _build_corroboration_map(all_items)

    kev_block = [
        {
            "cve": it["title"].split("—")[0].strip(),
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
            "that represent the highest-risk items this period. "
            "Sentence 2 — identify specific infrastructure resources most exposed. "
            "Sentence 3 — state the most time-sensitive action with patch status. "
            "(2) findings: JSON array of up to 12 distinct findings. "
            "For each finding include title, summary, risk_score (0-100), domains from: "
            + domain_keys
            + ", references, priority, why_now, recommended_actions_24h, "
            "recommended_actions_7d, confidence. "
            'Output ONLY strict JSON: {"executive_summary":"...","findings":[...]} '
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
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            print(f"[WARN] Groq findings not a list, got {type(findings).__name__}")
            findings = []
        return data.get("executive_summary", ""), findings, "ok"
    except Exception as exc:
        print(f"[WARN] Groq analysis failed: {exc}")
        return "", [], f"error: {exc}"


_VALID_DOMAIN_KEYS = set(_TAXONOMY.keys()) | {"uncategorised"}
_HIGH_PROFILE_TARGETS: list = CONFIG.get("high_profile_targets", [])
_HP_LOWER: list = [t.lower() for t in _HIGH_PROFILE_TARGETS]


def _match_high_profile(text: str) -> list:
    tl = text.lower()
    return [_HIGH_PROFILE_TARGETS[i] for i, lw in enumerate(_HP_LOWER) if lw in tl]


def _findings_to_cards(findings: list, all_items: list = None) -> list:
    url_to_country: dict = {}
    domain_to_country: dict = {}
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


def _compute_delta(current_cards: list, last_cards: list) -> dict:
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


def groq_weekly_review(aggregate: dict) -> str:
    today_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if aggregate.get("weekly_summary_ts") == today_utc and aggregate.get(
        "weekly_summary"
    ):
        return aggregate["weekly_summary"]
    if placeholder_mode() or not GROQ_API_KEY:
        return aggregate.get("weekly_summary", "")
    top_cves_txt = (
        ", ".join(
            f"{item['cve']} (×{item['count']})"
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
