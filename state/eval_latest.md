# Watchtower Pipeline Eval — 2026-07-31T21:16:44Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 290 |
| After dedup + CVE merge | 281 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/290 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,294 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6449

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 134 |
| `bsi_germany` | 89 |
| `gcp_security` | 30 |
| `thehackernews` | 7 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-29 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-29 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-31 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-31 | 3 | ? | 100% | 0% | 3 | 0 |