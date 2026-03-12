"""Scoring, clustering, and taxonomy helpers for Watchtower."""

import hashlib
import ipaddress
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
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_HASH_RE = re.compile(r"\b([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")
_REGISTRY_RE = re.compile(
    r"\b(HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
    r"(?:\\[\w\s.\-]+){1,8})\b",
    re.I,
)
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the string is a valid, publicly routable IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _extract_iocs(corpus: str, source_domains: set = None) -> dict:
    """Extract network / host IOCs from article text.

    Returns a dict with three keys:
      ``ips``       — list of public IPv4 address strings (up to 12)
      ``hashes``    — list of ``{value, type}`` dicts (sha256=64 hex chars,
                       sha1=40, md5=32)  (up to 8)
      ``registry``  — list of Windows registry key path strings (up to 6)
    """
    source_domains = source_domains or set()

    ips: list = []
    seen_ips: set = set()
    for m in _IPV4_RE.finditer(corpus):
        ip_str = m.group(0)
        if ip_str not in seen_ips and _is_public_ip(ip_str):
            seen_ips.add(ip_str)
            ips.append(ip_str)

    hashes: list = []
    seen_hashes: set = set()
    for m in _HASH_RE.finditer(corpus):
        h = m.group(0).lower()
        if h not in seen_hashes:
            seen_hashes.add(h)
            htype = "sha256" if len(h) == 64 else "sha1" if len(h) == 40 else "md5"
            hashes.append({"value": h, "type": htype})

    registry = list(
        dict.fromkeys(m.group(0) for m in _REGISTRY_RE.finditer(corpus))
    )[:6]

    return {
        "ips": ips[:12],
        "hashes": hashes[:8],
        "registry": registry,
    }


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
