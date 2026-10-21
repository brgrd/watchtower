# Watchtower Pipeline Eval — 2026-10-21T23:13:16Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 272 |
| After dedup + CVE merge | 267 |
| Sent to Groq | 25 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/272 (5.5%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 12.7 / 30 |
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
| `bsi_germany` | 203 |
| `thehackernews` | 12 |
| `bleepingcomputer` | 10 |
| `securityweek` | 10 |
| `darkreading` | 8 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-20 | 15 | ? | 0% | 0% | 1 | 0 |
| 2026-10-20 | 1 | ? | 0% | 0% | 1 | 0 |
| 2026-10-20 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-10-21 | 2 | ? | 0% | 0% | 1 | 0 |