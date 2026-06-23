# Watchtower Pipeline Eval — 2026-06-23T12:12:55Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 167 |
| After dedup + CVE merge | 166 |
| Sent to Groq | 12 |
| Groq findings returned | 0 |
| Final cards rendered | 12 |
| **Pipeline yield** | **12/167 (7.2%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**12 cards** — P1: 0, P2: 0, P3: 12

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 1.7 / 0 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 12 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **12** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 154 |
| `securityweek` | 7 |
| `thehackernews` | 3 |
| `snyk_blog` | 2 |
| `bleepingcomputer` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-21 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-21 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-21 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-06-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 4 | 0 |
| 2026-06-22 | 15 | ? | 0% | 0% | 15 | 0 |