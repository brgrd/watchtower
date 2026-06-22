# Watchtower Pipeline Eval — 2026-06-22T23:39:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 57 |
| After dedup + CVE merge | 41 |
| Sent to Groq | 30 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/57 (26.3%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 6.7 / 15 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `gcp_security` | 30 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 6 |
| `cyberscoop` | 3 |
| `securityweek` | 2 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-20 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-21 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-21 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 4 | 0 |