# Watchtower Pipeline Eval — 2026-07-13T00:05:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 37 |
| After dedup + CVE merge | 29 |
| Sent to Groq | 28 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/37 (8.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,961 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7158

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 41.7 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 34 |
| `bleepingcomputer` | 2 |
| `msrc_update_guide` | 1 |
| `gh_security_blog` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-11 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-12 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-12 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-12 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-12 | 3 | ? | 100% | 0% | 3 | 0 |