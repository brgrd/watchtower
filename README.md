# Watchtower — Infrastructure Security Briefing

Automated threat intelligence briefing for infrastructure security. Runs on GitHub Actions twice daily, aggregates 24 public feeds through an LLM analysis pipeline, and publishes a ranked HTML briefing to GitHub Pages — no infrastructure, no cost.

---

## How It Works

Each run follows a fixed pipeline:

1. **Poll** — 24 feeds are queried: NVD, CISA KEV, vendor security blogs, threat intelligence RSS, and international CERTs (NCSC, BSI, ACSC).
2. **Deduplicate** — Items are hashed and checked against a 14-day seen-hash store. CVEs appearing across multiple sources are merged into a single item before analysis.
3. **Enrich** — EPSS scores are fetched from FIRST.org for any extracted CVE IDs. CISA KEV membership is checked. Products, versions, and IOCs are extracted from article text.
4. **Analyze** — Up to 120 items (newest-first) are sent to Groq (`llama-3.3-70b-versatile`) for structured threat analysis. The model returns findings with risk scores, MITRE ATT&CK tactics, recommended actions, and source citations.
5. **Score** — Findings are scored and ranked by domain (OS/Kernel, Cloud/IAM, Containers, Identity, Supply Chain, etc.). Persistence boosts are applied to findings seen across multiple consecutive runs.
6. **Render** — An HTML briefing is written to `reports/index.html` and committed back to the repository.
7. **Publish** — GitHub Pages serves the briefing from the `reports/` directory.

The pipeline runs at **06:00 and 18:00 ET** via a scheduled cron job that gates on the New York hour. State files are committed back to the repository after each run so deduplication and persistence tracking survive across ephemeral Actions runners.

---

## Briefing Features

**Finding cards** — Each finding includes a risk score (0–100), priority (P1/P2/P3), MITRE ATT&CK tactic, patch status, CISA KEV and EPSS badges, corroboration count, persistence shelf badge, and recommended actions for the next 24h and 7 days.

**KPI bar** — Live counts of total findings, P1s, actively-exploited findings, high-profile target matches, and control-plane findings. P1 and Exploited tiles show a `+N ↑` / `−N ↓` delta from the previous run.

**Alerts tab** — Surfaces three signal categories without requiring daily check-ins: persistent findings (seen 3+ runs), elevated findings (score rose ≥ 10 points), and P1/attribution findings.

**Catch-up view** — Detects gaps since last visit (> 4 hours) and injects a collapsible strip of new findings since that timestamp.

**Threat constellation** — SVG node map showing which security domains are active, with finding counts and velocity indicators per node.

**Forensics tab** — CVE reference index with NVD links, kill-chain coverage bar, affected products, and IOC ledger.

**7-day history** — Per-day accordion showing historical findings with risk scores and priorities.

**Feed health panel** — Per-feed success/failure tracking. Feeds with repeated failures are automatically deprioritized.

---

## Required Secret

| Secret | Purpose |
|--------|---------|
| `GROQ_API_KEY` | LLM analysis via Groq free tier (`llama-3.3-70b-versatile`) |

Set this in **Settings → Secrets and variables → Actions** on your fork.

Without `GROQ_API_KEY` the runner raises a `RuntimeError` and exits. No partial output is written.

---

## State Files

State is committed to the repository after every run. These files persist across the ephemeral Actions runners:

| File | Purpose |
|------|---------|
| `state/finding_shelf.json` | Per-finding persistence tracking: run count, first/last seen, resolved status |
| `state/feed_health.json` | Per-feed success/failure counters and last-seen timestamps |
| `state/ioc_ledger.json` | IOC observations across runs (IPs, hashes, registry keys) |
| `state/epss_cache.json` | 24-hour EPSS score cache (FIRST.org API) |
| `state/ledger.jsonl` | Append-only run metrics log |
| `state/last_run_ts.json` | Timestamp of last successful run for adaptive window sizing |
| `state/weekly_aggregate.json` | 7-day summary rebuilt each run |

`state/seen_hashes.json` is excluded from commits (too large; reconstructed automatically on fresh clone via `bootstrap_seen_from_reports()`).

---

## Data Sources

All sources are free and require no API key unless noted.

| Source | Type | Notes |
|--------|------|-------|
| NVD | JSON API | CVE database; optional `NVD_API_KEY` for higher rate limits |
| CISA KEV | JSON API | Known Exploited Vulnerabilities catalog |
| FIRST.org EPSS | JSON API | Exploitation probability scores |
| NCSC (UK), BSI (Germany), ACSC (Australia) | RSS | International CERT advisories |
| Talos, Unit 42, Malwarebytes | RSS | Threat intelligence blogs |
| BleepingComputer, Krebs, The Hacker News, Dark Reading, SecurityWeek, CyberScoop, The Record, PortSwigger | RSS | Security news |
| Cloudflare, AWS, GCP, GitHub, Microsoft, Snyk | RSS | Vendor security blogs and advisories |

---

## Repository Layout

```
agent/
  runner.py        — Pipeline orchestrator
  analysis.py      — Groq API integration, card construction, quality gate
  ingest.py        — Feed polling, URL validation, CVE deduplication
  scoring.py       — Domain taxonomy, risk scoring, heatmap
  state.py         — All JSON persistence helpers
  html_builder.py  — Full HTML/SVG briefing renderer
  config.yaml      — Feed list, model config, domain taxonomy, high-profile targets
reports/
  index.html       — Published briefing (GitHub Pages root)
  latest.md        — Latest briefing in Markdown
state/             — Persistent run state (committed)
tests/             — pytest unit tests
```
