# Watchtower Pipeline Eval — 2026-06-18T00:23:43Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 36 |
| After dedup + CVE merge | 23 |
| Sent to Groq | 18 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/36 (41.7%)** |

## Groq
_Groq not called this run (placeholder mode or no API key)._

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 2 / 0 |
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
| `github_changelog` | 8 |
| `thehackernews` | 5 |
| `bleepingcomputer` | 4 |
| `ms_security_blog` | 4 |
| `msrc_update_guide` | 4 |
| _(+21 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-15 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-06-15 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-06-16 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-16 | 3 | 2 | 67% | 100% | 3 | 0 |
| 2026-06-16 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-17 | 13 | ? | 0% | 0% | 13 | 0 |
| 2026-06-17 | 15 | ? | 0% | 0% | 15 | 0 |