"""Scoring, clustering, and taxonomy helpers for Watchtower."""

import hashlib
import os
import re

import tldextract
import yaml

ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG = yaml.safe_load(
    open(os.path.join(ROOT, "agent", "config.yaml"), "r", encoding="utf-8")
)
_TAXONOMY = CONFIG.get("domain_taxonomy", {})

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def _compact_text(s: str) -> str:
    return " ".join((s or "").split()).strip()


def _extract_cves(s: str) -> list:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(s or "")})


def _contains_any(txt: str, terms: tuple) -> bool:
    low = (txt or "").lower()
    return any(t in low for t in terms)


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


def _is_exploitish(c: dict) -> bool:
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
    p = str(card.get("priority", "") or "").upper()
    if p in {"P1", "P2", "P3"}:
        return p
    rs = int(card.get("risk_score", 0))
    if rs >= 85:
        return "P1"
    if rs >= 60:
        return "P2"
    return "P3"


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
