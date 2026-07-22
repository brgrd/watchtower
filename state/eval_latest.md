# Watchtower Pipeline Eval — 2026-07-22T00:00:55Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 41 |
| After dedup + CVE merge | 38 |
| Sent to Groq | 28 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/41 (36.6%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 24.3 / 45 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **14** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.1 | Mean shelf_days: 0.1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 20% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bleepingcomputer` | 6 |
| `thehackernews` | 6 |
| `cyberscoop` | 5 |
| `cisa_kev` | 4 |
| `securityweek` | 4 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-19 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | ? | 100% | 33% | 3 | 0 |
| 2026-07-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | ? | 100% | 0% | 1 | 0 |
| 2026-07-21 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-21 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-21 | 3 | 2 | 100% | 33% | 3 | 0 |