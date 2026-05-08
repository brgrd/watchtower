"""AI analysis and finding transformation helpers for Watchtower."""

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

import requests
import tldextract
import yaml

from agent.scoring import _TAXONOMY, _extract_cves, _extract_iocs, classify_domains
from agent.state import sha256

ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG = yaml.safe_load(
    open(os.path.join(ROOT, "agent", "config.yaml"), "r", encoding="utf-8")
)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_BASE = "https://api.groq.com/openai/v1"

# Last Groq call metadata — populated by groq_analyze_briefing(); read by eval.
_last_groq_meta: dict = {}


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
            "retries": attempt,
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
    mitre_tactics = (
        "Reconnaissance, Resource Development, Initial Access, Execution, Persistence, "
        "Privilege Escalation, Defense Evasion, Credential Access, Discovery, "
        "Lateral Movement, Collection, Command & Control, Exfiltration, Impact"
    )
    classification_rubric = (
        "PROBLEM_TYPE \u2014 pick the most specific match for the vulnerability's nature: "
        "rce (arbitrary code execution); "
        "privilege_escalation (authenticated entity gains rights it shouldn't \u2014 distinct from rce); "
        "auth_bypass (skipping authentication entirely \u2014 distinct from privilege_escalation); "
        "data_disclosure (reading private data \u2014 distinct from credential_compromise); "
        "data_tampering (unauthorized write/modify); "
        "credential_compromise (credentials, tokens, sessions, password hashes leaked or dumped); "
        "dos (resource exhaustion, infinite loops, crashes that prevent service); "
        "supply_chain (build pipeline, dependency graph, or release artifact compromised); "
        "crypto_weakness (broken or weak cryptographic primitives or implementations); "
        "misconfiguration (default credentials, exposed admin panels, public buckets, missing security headers). "
        "AFFECTS \u2014 pick the deepest (most-foundational) layer the attacker reaches: "
        "user_data (end-user accounts, credentials, files, sessions, identity, PII); "
        "application (specific application/product like Atlassian Confluence, Ivanti Connect Secure, Fortinet FortiGate); "
        "framework (reusable code library/framework like Next.js, Django, Spring, Rails); "
        "runtime (language platform/interpreter like Node.js, Python, JVM, .NET); "
        "service (hosted/cloud service like AWS IAM, Cloudflare, GitHub); "
        "network (network protocol or transport layer); "
        "foundation (OS kernel, libc, OpenSSL, OpenSSH, hardware/CPU microcode); "
        "build_pipeline (CI/CD systems, package registries, container build steps). "
        "RULES: Both fields required, every finding. "
        "If multiple problem types apply, pick the worst-case impact. "
        "If multiple affects layers apply, pick the deepest \u2014 a Linux glibc bug affects foundation even though it surfaces in applications. "
        "For data breaches and credential dumps, always use credential_compromise + user_data. "
        "If you are uncertain, set classification_confidence < 0.7 and explain in classification_reasoning. "
        "classification_reasoning must be one short sentence (<200 chars) explaining your choice."
    )
    prompt = {
        "task": "infrasec_briefing",
        "schema_version": "watchtower.groq.package.v3",
        "reporting_window": reporting_window,
        "exploited_vulnerabilities": kev_block,
        "recent_cves": nvd_block,
        "news_articles": article_block,
        "classification_rubric": classification_rubric,
        "instructions": (
            "You are a senior threat intelligence analyst writing a concise daily briefing "
            f"for the 24-hour period ending now ({reporting_window}). "
            "Review all inputs: exploited vulnerabilities (CISA KEV), recent CVEs (NVD), "
            "and news articles. Produce: "
            "(1) executive_summary: exactly 3 sentences grounded in the data provided. "
            "Sentence 1 \u2014 name the 2-3 specific CVE IDs, software products, or vendor platforms "
            "that represent the highest-risk items this period (e.g. 'CVE-2026-XXXX in Palo Alto PAN-OS' "
            "or 'Apache Tomcat RCE'). "
            "Sentence 2 \u2014 identify which specific infrastructure resources or system types are most "
            "exposed right now and why (e.g. internet-facing firewalls, container orchestration nodes, "
            "VPN appliances), referencing patch or exploitation status from the data. "
            "Sentence 3 \u2014 state the single most time-sensitive action: be specific about what to patch, "
            "isolate, or monitor, name the affected product/version, and state whether a patch is "
            "currently available or not. "
            "Do NOT use vague language like 'various systems' or 'multiple vendors' \u2014 always name names. "
            "CRITICAL: Finding titles and summaries must describe the technical nature of the vulnerability "
            "or attack technique, never alleged attacker nationality or threat-actor attribution. "
            "Do not use phrases like 'Iranian threat actor', 'Chinese APT', 'Russian hackers', "
            "'North Korean group', or any nation-state name as the subject of a finding title. "
            "Instead describe what the attack does: 'Spearphishing campaign targeting energy sector VPNs' "
            "NOT 'Iranian Cyber Activity'. If attribution appears in source articles, you may note it "
            "in the why_now field only, prefixed with 'Reported attribution (unverified): '. "
            "Keep the summary anchored to the reporting window and only reference items present in the input data. "
            "(2) findings: JSON array of up to 12 distinct threat or vulnerability findings. "
            "For each finding: title (under 100 chars), summary (1-2 sentence analyst note "
            "on what is affected, exploit/patch status, urgency), risk_score (integer 0-100: "
            "base 40 for known CVE, +30 if actively exploited in the wild, +15 if PoC exists, "
            "+15 if critical infrastructure), domains (array of matching keys from: "
            + domain_keys
            + "), references (array of {title, url} \u2014 cite urls from any of the three input "
            "blocks; 1-3 most relevant per finding), priority (P1|P2|P3), "
            "why_now (short sentence), recommended_actions_24h (array up to 4), "
            "recommended_actions_7d (array up to 3), confidence (0..1), "
            f"tactic_name (ONE MITRE ATT&CK tactic that best describes how this threat operates, "
            f"choose from: {mitre_tactics}), "
            "technique_name (short technique label, e.g. 'Exploit Public-Facing Application'), "
            "problem_type (apply classification_rubric \u2014 exact lowercase enum string), "
            "affects (apply classification_rubric \u2014 exact lowercase enum string), "
            "classification_confidence (0..1 \u2014 drop below 0.7 when uncertain), "
            "classification_reasoning (one sentence explaining the cell choice), "
            "cross_cutting (optional array of additional 'problem_type|affects' strings when "
            "the finding genuinely spans multiple cells; omit or empty array when the primary cell suffices). "
            'Output ONLY strict JSON, no markdown fences: {"executive_summary":"...",'
            '"findings":[{"title":"...","summary":"...","risk_score":0,"domains":[],'
            '"references":[{"title":"...","url":"..."}],"priority":"P2",'
            '"why_now":"...","recommended_actions_24h":[],"recommended_actions_7d":[],'
            '"confidence":0.6,"tactic_name":"Initial Access","technique_name":"...",'
            '"problem_type":"rce","affects":"framework","classification_confidence":0.85,'
            '"classification_reasoning":"...","cross_cutting":[]}]}'
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
        content, _meta = groq_chat(
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
        _last_groq_meta.update(_meta)
        _last_groq_meta["model"] = CONFIG["model"]["name"]
        _last_groq_meta["payload_chars"] = len(user_content)
        _last_groq_meta["parse_ok"] = True
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
        _last_groq_meta["parse_ok"] = False
        _last_groq_meta["error"] = str(exc)
        print(f"[WARN] Groq analysis failed: {exc}")
        return "", [], f"error: {exc}"


_VALID_DOMAIN_KEYS = set(_TAXONOMY.keys()) | {"uncategorised"}
_HIGH_PROFILE_TARGETS: list = CONFIG.get("high_profile_targets", [])
_HP_LOWER: list = [t.lower() for t in _HIGH_PROFILE_TARGETS]

# Classification taxonomy for the threat-matrix (problem_type × affects).
# Each finding is bucketed into exactly one cell defined by (problem_type, affects).
PROBLEM_TYPES: list = [
    "rce",
    "privilege_escalation",
    "auth_bypass",
    "data_disclosure",
    "data_tampering",
    "credential_compromise",
    "dos",
    "supply_chain",
    "crypto_weakness",
    "misconfiguration",
]
AFFECTS: list = [
    "user_data",
    "application",
    "framework",
    "runtime",
    "service",
    "network",
    "foundation",
    "build_pipeline",
]
_PROBLEM_TYPES_SET = set(PROBLEM_TYPES)
_AFFECTS_SET = set(AFFECTS)


def _normalize_classification(raw: str, valid_set: set, default: str) -> str:
    """Normalize a Groq-returned classification string to a canonical enum value.

    Handles common LLM variations: case differences, hyphens vs. underscores,
    and trailing whitespace.  Returns ``default`` when the value cannot be matched.
    """
    if not raw:
        return default
    key = str(raw).strip().lower().replace("-", "_").replace(" ", "_")
    if key in valid_set:
        return key
    # Some LLMs return "rce_in_framework" or similar compound — split and try first token
    if "_" in key:
        head = key.split("_", 1)[0]
        if head in valid_set:
            return head
    return default


def _normalize_cross_cutting(raw, primary_cell: str) -> list:
    """Coerce Groq's ``cross_cutting`` field to a clean list of ``"type|affects"`` strings.

    Strips the primary cell so we never duplicate it, drops invalid pairs.
    """
    if not raw or not isinstance(raw, list):
        return []
    result: list = []
    seen: set = {primary_cell}
    for entry in raw:
        if not isinstance(entry, str) or "|" not in entry:
            continue
        pt, af = entry.split("|", 1)
        pt = _normalize_classification(pt, _PROBLEM_TYPES_SET, "")
        af = _normalize_classification(af, _AFFECTS_SET, "")
        if not pt or not af:
            continue
        cell = f"{pt}|{af}"
        if cell in seen:
            continue
        seen.add(cell)
        result.append(cell)
    return result[:4]  # cap to keep cross-cutting bounded


def _match_high_profile(text: str) -> list:
    tl = text.lower()
    return [_HIGH_PROFILE_TARGETS[i] for i, lw in enumerate(_HP_LOWER) if lw in tl]


_CANONICAL_TACTICS: list = [
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
_TACTIC_ALIASES: dict = {
    # abbreviations / common LLM shorthand
    "recon": "Reconnaissance",
    "resource dev": "Resource Development",
    "resource-dev": "Resource Development",
    "initial access": "Initial Access",
    "exec": "Execution",
    "execute": "Execution",
    "persist": "Persistence",
    "priv esc": "Privilege Escalation",
    "privesc": "Privilege Escalation",
    "privilege-escalation": "Privilege Escalation",
    "def evasion": "Defense Evasion",
    "defense-evasion": "Defense Evasion",
    "evasion": "Defense Evasion",
    "cred access": "Credential Access",
    "credential-access": "Credential Access",
    "credentials": "Credential Access",
    "discovery": "Discovery",
    "lateral movement": "Lateral Movement",
    "lateral-movement": "Lateral Movement",
    "collect": "Collection",
    "c2": "Command & Control",
    "c&c": "Command & Control",
    "command and control": "Command & Control",
    "command-and-control": "Command & Control",
    "exfil": "Exfiltration",
    "data exfiltration": "Exfiltration",
    "impact": "Impact",
}
_CANONICAL_TACTICS_LOWER: dict = {t.lower(): t for t in _CANONICAL_TACTICS}


def _normalize_tactic(raw: str) -> str:
    """Coerce a Groq-returned tactic string to a canonical ATT&CK tactic name.

    Returns the canonical name, or empty string if unrecognized.
    """
    if not raw:
        return ""
    key = raw.strip().lower()
    if not key:
        return ""
    # Exact canonical match (case-insensitive)
    if key in _CANONICAL_TACTICS_LOWER:
        return _CANONICAL_TACTICS_LOWER[key]
    # Known alias
    if key in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[key]
    # Partial prefix match (e.g. "Privilege Esc" -> "Privilege Escalation")
    for canon_lower, canon in _CANONICAL_TACTICS_LOWER.items():
        if canon_lower.startswith(key) or key.startswith(canon_lower[:6]):
            return canon
    # Unrecognized — return empty so the chip is hidden rather than showing garbage
    return ""


# Vendor / product name list for zero-token regex extraction from article text.
# Ordered longest-match-first to avoid 'Cisco' matching before 'Cisco IOS XE'.
_KNOWN_PRODUCTS: list = [
    "Palo Alto PAN-OS",
    "Palo Alto Networks",
    "Fortinet FortiOS",
    "Fortinet FortiGate",
    "Fortinet",
    "Cisco IOS XE",
    "Cisco ASA",
    "Cisco Meraki",
    "Cisco NX-OS",
    "Cisco",
    "Ivanti Connect Secure",
    "Ivanti Pulse Secure",
    "Ivanti",
    "Microsoft Exchange",
    "Microsoft SharePoint",
    "Microsoft Teams",
    "Microsoft Windows",
    "Microsoft Azure",
    "Microsoft 365",
    "Microsoft",
    "VMware ESXi",
    "VMware vCenter",
    "VMware",
    "Apache Log4j",
    "Apache Struts",
    "Apache Tomcat",
    "Apache HTTP Server",
    "Apache",
    "Atlassian Confluence",
    "Atlassian Jira",
    "Atlassian",
    "GitLab",
    "GitHub Actions",
    "Jenkins",
    "TeamCity",
    "OpenSSH",
    "OpenSSL",
    "MOVEit Transfer",
    "MOVEit",
    "Progress Software",
    "Citrix ADC",
    "Citrix Gateway",
    "Citrix",
    "F5 BIG-IP",
    "F5 Networks",
    "SolarWinds Orion",
    "SolarWinds",
    "Juniper Junos",
    "Juniper Networks",
    "Check Point",
    "Barracuda ESG",
    "Barracuda",
    "Zimbra",
    "Pulse Connect Secure",
    "SAP NetWeaver",
    "SAP",
    "Oracle WebLogic",
    "Oracle",
    "JetBrains TeamCity",
    "JetBrains",
    "Kubernetes",
    "Docker",
    "containerd",
    "Nginx",
    "HAProxy",
    "Redis",
    "Elasticsearch",
    "MongoDB",
    "PHP",
    "Python",
    "Node.js",
    "Java",
    "Chrome",
    "Firefox",
    "Safari",
    "Edge",
    "Android",
    "iOS",
    "macOS",
    "Linux kernel",
    "Linux",
    "Windows Server",
    "Windows 11",
    "Windows 10",
    "GPT-4",
    "ChatGPT",
    "Claude",
    "Gemini",
    "AWS",
    "Azure",
    "GCP",
    "Google Cloud",
]
_VERSION_RE = re.compile(
    r"\b(v?\d{1,3}\.\d{1,4}(?:\.\d{1,4}){0,2}(?:[.-][a-zA-Z0-9]+)?)\b"
)
_DATE_RE = re.compile(
    r"\b(20(?:2[3-9]|3[0-9])-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))\b"
)


def _enrich_cards_from_sources(cards: list, all_items: list) -> None:
    """Zero-token enrichment pass: correlate cards back to source article text.

    For each card, locates the original fetched articles whose URLs match the
    card's cited references, then runs lightweight regex extraction to surface:
    - CVE IDs found in article text (beyond what Groq cited)
    - Software product / vendor mentions from a curated list
    - Version strings (v1.2.3 patterns)
    - Article publication dates
    - First meaningful sentence from the article (the 'lede')

    All extracted data is appended to card['enrichment'] as structured fields.
    No network calls, no model calls — purely in-memory over already-fetched text.
    """
    if not all_items:
        return

    # Build fast lookup: url -> item (for text retrieval)
    url_to_item: dict = {it.get("url", ""): it for it in all_items if it.get("url")}

    for card in cards:
        if not isinstance(card, dict):
            continue
        refs = card.get("sources", {}).get("primary", [])
        ref_urls = [
            r.get("url", "") for r in refs if isinstance(r, dict) and r.get("url")
        ]

        # Collect all article text available for this card
        corpus_parts: list = []
        corpus_items_for_ioc: list = []
        article_dates: list = []
        for url in ref_urls:
            item = url_to_item.get(url)
            if not item:
                continue
            text = (item.get("extracted_text", "") or item.get("summary", "") or "")[
                :1500
            ]
            title = item.get("title", "")
            pub = item.get("published_at", "") or item.get("pub_date", "")
            if text:
                corpus_parts.append(f"{title}. {text}")
                corpus_items_for_ioc.append({"text": text, "url": url, "title": title})
            if pub:
                article_dates.append(str(pub)[:10])

        if not corpus_parts:
            # No source text available — still mark enrichment attempted
            card["enrichment"] = {"source_count": 0}
            continue

        corpus = " ".join(corpus_parts)

        # CVEs from article text (supplement Groq-cited ones)
        corpus_cves = sorted(set(_extract_cves(corpus)))
        card_cves = sorted(
            set(_extract_cves(card.get("title", "") + " " + card.get("summary", "")))
        )
        extra_cves = [c for c in corpus_cves if c not in card_cves]

        # Product/vendor mentions (longest match first, deduplicated)
        found_products: list = []
        seen_lower: set = set()
        corpus_lower = corpus.lower()
        for prod in _KNOWN_PRODUCTS:
            if prod.lower() in corpus_lower and prod.lower() not in seen_lower:
                found_products.append(prod)
                # Mark any shorter sub-string as already covered
                for part in prod.split():
                    seen_lower.add(part.lower())
                seen_lower.add(prod.lower())

        # Version strings
        versions = list(dict.fromkeys(_VERSION_RE.findall(corpus)))[:6]

        # Dates in article text
        text_dates = list(dict.fromkeys(_DATE_RE.findall(corpus)))[:4]
        all_dates = sorted(set(article_dates + text_dates), reverse=True)[:4]

        # Lede: first sentence ≥ 40 chars from the article body
        lede = ""
        for part in corpus_parts:
            for sent in re.split(r"(?<=[.!?])\s+", part):
                sent = sent.strip()
                if len(sent) >= 40:
                    lede = sent[:280]
                    break
            if lede:
                break

        # IOCs: public IPs, file hashes, Windows registry keys
        # Raw values never rendered in HTML — only stored in ioc_ledger.json
        iocs = _extract_iocs(corpus_items_for_ioc)

        card["enrichment"] = {
            "source_count": len(corpus_parts),
            "cves": card_cves + extra_cves,
            "extra_cves": extra_cves,
            "products": found_products[:8],
            "versions": versions,
            "dates": all_dates,
            "lede": lede,
            "iocs": iocs,
        }


# Nation-state / threat-actor attribution patterns — used to flag finding titles
# that inherit attribution language from source articles.  Attribution is unverified
# when derived from news articles and should be surfaced as such, not presented as fact.
_ATTRIBUTION_RE = re.compile(
    r"\b(iranian|chinese|russian|north[\s-]?korean|dprk|prc|apt[\s-]?\d+"
    r"|lazarus|cozy[\s-]?bear|fancy[\s-]?bear|sandworm|volt[\s-]?typhoon"
    r"|salt[\s-]?typhoon|silk[\s-]?typhoon|scattered[\s-]?spider"
    r"|killnet|darkside|lockbit(?![\s-]?vuln|[\s-]?ransomware[\s-]?patch))",
    re.I,
)


def _quality_score(card: dict) -> int:
    """Score Groq-generated card signal quality 0–4 (1 point each).

    1. Title longer than 20 characters
    2. CVE ID or product name present in enrichment
    3. Summary longer than 60 characters
    4. why_now field is non-empty

    Cards scoring below 2 are excluded by _findings_to_cards as low-signal noise.
    """
    score = 0
    if len(card.get("title", "")) > 20:
        score += 1
    enrichment = card.get("enrichment", {}) or {}
    if enrichment.get("cves") or enrichment.get("products"):
        score += 1
    if len(card.get("summary", "")) > 60:
        score += 1
    if card.get("why_now", "").strip():
        score += 1
    return score


def _findings_to_cards(findings: list, all_items: list = None) -> list:
    url_to_country: dict = {}
    domain_to_country: dict = {}
    cve_to_status: dict = {}
    kev_cves: set = set()
    cve_to_source_count: dict = {}
    if all_items:
        for it in all_items:
            cc = it.get("country", "")
            url = it.get("url", "")
            if cc and url:
                url_to_country[url] = cc
                dom = tldextract.extract(url).registered_domain
                if dom and dom not in domain_to_country:
                    domain_to_country[dom] = cc
            is_kev_source = (
                it.get("source_id") == "cisa_kev"
                or "known_exploited" in it.get("source", "")
            )
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
                    "no_fix_explicit": existing.get("no_fix_explicit")
                    or it.get("no_fix_explicit", False),
                }
                if is_kev_source:
                    kev_cves.add(cve_id)
                cve_to_source_count[cve_id] = cve_to_source_count.get(cve_id, 0) + 1

    cards = []
    for f in findings:
        if not isinstance(f, dict):
            print(f"[WARN] Finding is not a dict, skipping: {type(f).__name__}")
            continue
        try:
            score = max(0, min(100, int(f.get("risk_score", 40))))
        except (ValueError, TypeError):
            score = 40

        raw_domains = f.get("domains", [])
        domains = [d for d in raw_domains if d in _VALID_DOMAIN_KEYS]
        if not domains:
            domains = ["uncategorised"]

        refs = f.get("references", [])
        if not isinstance(refs, list):
            refs = []
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
                url_to_country.get(r.get("url"))
                or domain_to_country.get(
                    tldextract.extract(r.get("url", "")).registered_domain
                )
                for r in refs
                if isinstance(r, dict) and r.get("url")
            }
            - {None}
        )

        finding_cves = _extract_cves(f.get("title", "") + " " + f.get("summary", ""))
        corroboration_count = (
            max(cve_to_source_count.get(c, 1) for c in finding_cves)
            if finding_cves
            else 1
        )
        patch_available = False
        workaround_available = False
        exploited_in_wild = False
        no_fix_explicit = False
        for cve_id in finding_cves:
            st = cve_to_status.get(cve_id, {})
            patch_available = patch_available or st.get("patch_available", False)
            workaround_available = workaround_available or st.get(
                "workaround_available", False
            )
            exploited_in_wild = exploited_in_wild or st.get("exploited_in_wild", False)
            no_fix_explicit = no_fix_explicit or st.get("no_fix_explicit", False)
        if patch_available:
            patch_status = "patched"
        elif workaround_available:
            patch_status = "workaround"
        elif exploited_in_wild or no_fix_explicit:
            patch_status = "no_fix"
        else:
            patch_status = "unknown"

        matched_targets = _match_high_profile(
            f.get("title", "") + " " + f.get("summary", "")
        )
        attribution_flag = bool(
            _ATTRIBUTION_RE.search(f.get("title", "") + " " + f.get("summary", ""))
        )
        is_kev = bool(set(finding_cves) & kev_cves)

        problem_type = _normalize_classification(
            f.get("problem_type", ""), _PROBLEM_TYPES_SET, ""
        )
        affects = _normalize_classification(
            f.get("affects", ""), _AFFECTS_SET, ""
        )
        try:
            cls_conf = float(f.get("classification_confidence", 0.0))
            cls_conf = max(0.0, min(1.0, cls_conf))
        except (ValueError, TypeError):
            cls_conf = 0.0
        # If Groq omitted classification entirely, mark low confidence so Pass 2
        # picks it up downstream.
        if not problem_type or not affects:
            problem_type = problem_type or "misconfiguration"
            affects = affects or "application"
            cls_conf = min(cls_conf, 0.4)
        primary_cell = f"{problem_type}|{affects}"
        cls_reasoning = str(f.get("classification_reasoning", ""))[:200]
        cross_cutting = _normalize_cross_cutting(
            f.get("cross_cutting", []), primary_cell
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
                "attribution_flag": attribution_flag,
                "is_kev": is_kev,
                "corroboration_count": corroboration_count,
                "tactic_name": _normalize_tactic(
                    str(f.get("tactic_name", "")) if f.get("tactic_name") else ""
                ),
                "technique_name": (
                    str(f.get("technique_name", ""))[:80]
                    if f.get("technique_name")
                    else ""
                ),
                "problem_type": problem_type,
                "affects": affects,
                "classification_confidence": cls_conf,
                "classification_reasoning": cls_reasoning,
                "cross_cutting": cross_cutting,
                "classification_history": [],
                "sources": {
                    "primary": [
                        {
                            "title": r.get("title", r.get("url", ""))[:120],
                            "url": r.get("url", ""),
                        }
                        for r in refs
                        if isinstance(r, dict) and r.get("url")
                    ],
                    "secondary": [],
                },
            }
        )
    result = sorted(cards, key=lambda c: c["risk_score"], reverse=True)
    _enrich_cards_from_sources(result, all_items)
    _before = len(result)
    result = [c for c in result if _quality_score(c) >= 2]
    if len(result) < _before:
        print(
            f"[QUALITY DROP] {_before - len(result)} low-signal card(s) filtered "
            f"(quality gate: title length, CVE/product, summary, why_now)"
        )
    return result


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


_AUDIT_CONFIDENCE_THRESHOLD = 0.7
_AUDIT_PEER_LIMIT = 4


def _pick_audit_peers(card: dict, all_cards: list, n: int = _AUDIT_PEER_LIMIT) -> list:
    """Pick up to ``n`` peers that share the same cell as the candidate card.

    Peer selection is by simple title-token Jaccard so we don't need an
    embedding model — fully free-tier compatible.  Peers must be confidently
    classified (>= threshold) so we're comparing against trustworthy anchors.
    """
    cell = (card.get("problem_type", ""), card.get("affects", ""))
    if not cell[0] or not cell[1]:
        return []

    def _tokens(c: dict) -> set:
        s = (c.get("title", "") + " " + c.get("summary", "")).lower()
        return {t for t in re.findall(r"[a-z0-9]{4,}", s)}

    candidate_tokens = _tokens(card)
    candidates: list = []
    for c in all_cards:
        if c is card:
            continue
        if (c.get("problem_type"), c.get("affects")) != cell:
            continue
        if float(c.get("classification_confidence", 0.0) or 0.0) < _AUDIT_CONFIDENCE_THRESHOLD:
            continue
        peer_tokens = _tokens(c)
        union = candidate_tokens | peer_tokens
        if not union:
            continue
        jaccard = len(candidate_tokens & peer_tokens) / len(union)
        candidates.append((jaccard, c))
    candidates.sort(key=lambda x: -x[0])
    return [c for _, c in candidates[:n]]


def audit_low_confidence_findings(cards: list) -> int:
    """Phase 8 — Groq Pass 2.

    For every card with ``classification_confidence < threshold``, call Groq a
    second time with peer findings already in that cell as context.  If Groq
    suggests a different (problem_type, affects) cell, move the card and
    append a ``classification_history`` entry.

    Skipped silently in placeholder mode or when the API key is missing.
    Returns the number of cards re-classified.
    """
    if placeholder_mode() or not GROQ_API_KEY:
        return 0

    moved = 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    candidates = [
        c for c in cards
        if isinstance(c, dict)
        and float(c.get("classification_confidence", 1.0) or 1.0) < _AUDIT_CONFIDENCE_THRESHOLD
    ]
    if not candidates:
        return 0

    print(f"[INFO] Pass 2 audit: {len(candidates)} low-confidence finding(s) to review")

    for card in candidates:
        peers = _pick_audit_peers(card, cards)
        if not peers:
            # Without peers we have no context to improve on; record the attempt
            # so observability shows the audit ran.
            card.setdefault("classification_history", []).append(
                {
                    "ts": today,
                    "from": f'{card.get("problem_type")}|{card.get("affects")}',
                    "to": f'{card.get("problem_type")}|{card.get("affects")}',
                    "reason": "pass2_audit_no_peers",
                }
            )
            continue

        peer_lines = "\n".join(
            f"{i+1}. {(p.get('title') or '')[:80]} — {(p.get('summary') or '')[:140]}"
            for i, p in enumerate(peers)
        )
        prompt = (
            f"You previously classified this finding as "
            f"{card.get('problem_type')} × {card.get('affects')} "
            f"(confidence {float(card.get('classification_confidence', 0.0) or 0.0):.2f}).\n"
            f"Reasoning: \"{card.get('classification_reasoning', '')}\"\n\n"
            f"Title: {card.get('title', '')}\n"
            f"Summary: {(card.get('summary') or '')[:240]}\n\n"
            f"Peers in that cell:\n{peer_lines}\n\n"
            "Question: does this finding belong with these peers? "
            "If a different cell fits better, suggest one. "
            "Use the same enums from the classification rubric "
            "(problem_type ∈ rce|privilege_escalation|auth_bypass|data_disclosure|"
            "data_tampering|credential_compromise|dos|supply_chain|crypto_weakness|"
            "misconfiguration; affects ∈ user_data|application|framework|runtime|"
            "service|network|foundation|build_pipeline).\n"
            'Output strict JSON only: {"confirmed": bool, "suggested_problem_type": "..."|null, '
            '"suggested_affects": "..."|null, "reason": "..."}'
        )
        try:
            content, meta = groq_chat(
                [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity classifier. Output strict JSON only. No markdown fences.",
                    },
                    {"role": "user", "content": prompt},
                ],
                model=CONFIG["model"]["name"],
                temperature=0.1,
                max_tokens=200,
            )
        except Exception as exc:
            print(f"[WARN] Pass 2 audit call failed for '{card.get('title','')[:60]}': {exc}")
            continue

        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```[a-z]*\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())
        try:
            decision = json.loads(content)
        except json.JSONDecodeError:
            print(f"[WARN] Pass 2 audit returned invalid JSON for '{card.get('title','')[:60]}'")
            continue

        old_cell = f'{card.get("problem_type")}|{card.get("affects")}'
        if decision.get("confirmed") is True:
            card.setdefault("classification_history", []).append(
                {"ts": today, "from": old_cell, "to": old_cell, "reason": "pass2_audit_confirmed"}
            )
            # Bump confidence to threshold so this card stops triggering Pass 2 later
            card["classification_confidence"] = max(
                float(card.get("classification_confidence", 0.0) or 0.0), _AUDIT_CONFIDENCE_THRESHOLD
            )
            continue

        new_pt = _normalize_classification(
            decision.get("suggested_problem_type", ""), _PROBLEM_TYPES_SET, ""
        )
        new_af = _normalize_classification(
            decision.get("suggested_affects", ""), _AFFECTS_SET, ""
        )
        if not new_pt or not new_af:
            continue
        new_cell = f"{new_pt}|{new_af}"
        if new_cell == old_cell:
            continue

        card["problem_type"] = new_pt
        card["affects"] = new_af
        card["classification_confidence"] = max(
            float(card.get("classification_confidence", 0.0) or 0.0), _AUDIT_CONFIDENCE_THRESHOLD
        )
        card.setdefault("classification_history", []).append(
            {
                "ts": today,
                "from": old_cell,
                "to": new_cell,
                "reason": "pass2_audit_moved",
                "rationale": str(decision.get("reason", ""))[:240],
            }
        )
        card["recategorized_within_24h"] = True
        moved += 1
        print(
            f"[INFO] Pass 2 moved '{(card.get('title') or '')[:60]}' "
            f"{old_cell} → {new_cell}"
        )

    return moved


_WEEKLY_AUDIT_INTERVAL_DAYS = 7
_WEEKLY_AUDIT_MIN_CELL_SIZE = 3


def audit_cells_weekly(cards: list, last_audit: dict | None) -> tuple:
    """Phase 9 — Groq Pass 3.

    Once per ``_WEEKLY_AUDIT_INTERVAL_DAYS`` days, walk every non-empty cell
    that has at least ``_WEEKLY_AUDIT_MIN_CELL_SIZE`` findings.  For each
    cell, ask Groq if any members are mis-grouped; move outliers and mark
    them with ``recategorized_within_24h`` so the bubble vocabulary surfaces
    a small ``↻`` badge.

    Returns ``(moved_count, last_audit_state)``.  Skipped silently in
    placeholder mode or when GROQ_API_KEY is missing.
    """
    last_audit = last_audit or {}

    if placeholder_mode() or not GROQ_API_KEY:
        return 0, last_audit

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    last_ts = last_audit.get("ts")
    if last_ts:
        try:
            last_dt = datetime.strptime(last_ts, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - last_dt) < timedelta(
                days=_WEEKLY_AUDIT_INTERVAL_DAYS
            ):
                return 0, last_audit
        except ValueError:
            pass

    cards_by_id: dict = {c.get("id", ""): c for c in cards if isinstance(c, dict)}
    cells: dict = {}
    for c in cards_by_id.values():
        pt = c.get("problem_type", "")
        af = c.get("affects", "")
        if not pt or not af:
            continue
        cells.setdefault(f"{pt}|{af}", []).append(c)

    auditable = [
        (k, members) for k, members in cells.items()
        if len(members) >= _WEEKLY_AUDIT_MIN_CELL_SIZE
    ]
    if not auditable:
        # Nothing dense enough to warrant an audit; advance the timestamp so we
        # don't keep checking every run for the next week.
        last_audit = {
            **last_audit,
            "ts": today,
            "cells_checked": 0,
            "moved": 0,
        }
        return 0, last_audit

    print(f"[INFO] Pass 3 weekly audit: {len(auditable)} dense cell(s) to review")
    moved = 0

    for cell_key, members in auditable:
        listing = "\n".join(
            f"{i+1}. id={m.get('id','')} | {(m.get('title') or '')[:80]} — "
            f"{(m.get('summary') or '')[:140]}"
            for i, m in enumerate(members)
        )
        prompt = (
            f"Cell: {cell_key.replace('|', ' × ')}\n"
            "These findings are all classified into the same cell. "
            "Are any mis-grouped relative to the rest? "
            "If so, output the index and a better cell. "
            "Use the same enums from the classification rubric.\n\n"
            f"Findings:\n{listing}\n\n"
            'Output strict JSON only: {"moves": ['
            '{"id": "...", "to_problem_type": "...", "to_affects": "...", "reason": "..."}'
            "], \"audit_summary\": \"...\"}. "
            "Empty moves array means all findings fit."
        )
        try:
            content, meta = groq_chat(
                [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity classifier auditing a peer group. Output strict JSON only. No markdown fences.",
                    },
                    {"role": "user", "content": prompt},
                ],
                model=CONFIG["model"]["name"],
                temperature=0.1,
                max_tokens=400,
            )
        except Exception as exc:
            print(f"[WARN] Pass 3 audit call failed for {cell_key}: {exc}")
            continue

        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```[a-z]*\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())
        try:
            decision = json.loads(content)
        except json.JSONDecodeError:
            print(f"[WARN] Pass 3 audit returned invalid JSON for {cell_key}")
            continue

        for move in decision.get("moves", []) or []:
            if not isinstance(move, dict):
                continue
            target = cards_by_id.get(move.get("id", ""))
            if not target:
                continue
            new_pt = _normalize_classification(
                move.get("to_problem_type", ""), _PROBLEM_TYPES_SET, ""
            )
            new_af = _normalize_classification(
                move.get("to_affects", ""), _AFFECTS_SET, ""
            )
            if not new_pt or not new_af:
                continue
            old_cell = f'{target.get("problem_type")}|{target.get("affects")}'
            new_cell = f"{new_pt}|{new_af}"
            if new_cell == old_cell:
                continue
            target["problem_type"] = new_pt
            target["affects"] = new_af
            target.setdefault("classification_history", []).append(
                {
                    "ts": today,
                    "from": old_cell,
                    "to": new_cell,
                    "reason": "pass3_weekly_audit",
                    "rationale": str(move.get("reason", ""))[:240],
                }
            )
            target["recategorized_within_24h"] = True
            moved += 1
            print(
                f"[INFO] Pass 3 moved '{(target.get('title') or '')[:60]}' "
                f"{old_cell} → {new_cell}"
            )

    last_audit = {
        "ts": today,
        "cells_checked": len(auditable),
        "moved": moved,
    }
    return moved, last_audit


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
