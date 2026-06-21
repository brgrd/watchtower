# Watchtower Pipeline Eval — 2026-06-21T23:25:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 1 |
| After dedup + CVE merge | 1 |
| Sent to Groq | 1 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/1 (100.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,641 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8009

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 42 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 0% generic

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
| `bleepingcomputer` | 1 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| `cisa_alerts` | 0 |
| `ncsc_uk` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-19 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-20 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-06-21 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-21 | ? | ? | ?% | ?% | ? | ? |
| 2026-06-21 | 2 | 1 | 100% | 0% | 2 | 0 |