# Watchtower Pipeline Eval — 2026-08-07T22:48:50Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 211 |
| After dedup + CVE merge | 208 |
| Sent to Groq | 8 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/211 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 16,888 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5996

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 77 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 100% specific, 0% generic

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
| `nvd` | 132 |
| `gcp_security` | 30 |
| `bsi_germany` | 10 |
| `thehackernews` | 7 |
| `bleepingcomputer` | 5 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-06 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-08-06 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 3 | ? | 100% | 100% | 3 | 0 |