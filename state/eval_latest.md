# Watchtower Pipeline Eval — 2026-06-27T10:18:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 15 |
| After dedup + CVE merge | 15 |
| Sent to Groq | 1 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/15 (6.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,625 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8032

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 93 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `msrc_update_guide` | 14 |
| `bleepingcomputer` | 1 |
| `cisa_alerts` | 0 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-25 | 3 | 3 | 100% | 100% | 2 | 0 |
| 2026-06-25 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-26 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-26 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-26 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-26 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-06-26 | 3 | 3 | 100% | 0% | 3 | 0 |