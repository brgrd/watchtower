# Watchtower Pipeline Eval — 2026-06-18T10:45:31Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 118 |
| After dedup + CVE merge | 118 |
| Sent to Groq | 11 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/118 (2.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 19,938 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5847

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 93.3 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 41.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `bsi_germany` | 87 |
| `msrc_update_guide` | 19 |
| `securityweek` | 5 |
| `bleepingcomputer` | 2 |
| `ms_security_blog` | 2 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-15 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-06-16 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-16 | 3 | 2 | 67% | 100% | 3 | 0 |
| 2026-06-16 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-17 | 13 | ? | 0% | 0% | 13 | 0 |
| 2026-06-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 15 | 0 |