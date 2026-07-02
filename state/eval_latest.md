# Watchtower Pipeline Eval — 2026-07-02T12:17:29Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 232 |
| After dedup + CVE merge | 231 |
| Sent to Groq | 15 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/232 (6.5%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 16.7 / 45 |
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
| `bsi_germany` | 215 |
| `bleepingcomputer` | 6 |
| `thehackernews` | 4 |
| `securityweek` | 4 |
| `github_changelog` | 2 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-30 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-06-30 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-01 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 33% | 2 | 0 |