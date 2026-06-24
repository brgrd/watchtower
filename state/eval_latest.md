# Watchtower Pipeline Eval — 2026-06-24T09:47:47Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 174 |
| After dedup + CVE merge | 150 |
| Sent to Groq | 18 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/174 (8.6%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 13.7 / 30 |
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
| `bsi_germany` | 131 |
| `gcp_security` | 30 |
| `cisa_kev` | 4 |
| `securityweek` | 3 |
| `thehackernews` | 2 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 4 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-23 | 12 | ? | 0% | 0% | 12 | 0 |
| 2026-06-23 | 2 | 2 | 100% | 100% | 2 | 0 |
| 2026-06-23 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-24 | 15 | ? | 0% | 0% | 10 | 0 |