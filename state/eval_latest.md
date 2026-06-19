# Watchtower Pipeline Eval — 2026-06-19T21:17:14Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 147 |
| After dedup + CVE merge | 129 |
| Sent to Groq | 120 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/147 (2.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,604 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6778

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 100% specific, 0% generic

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
| `msrc_update_guide` | 61 |
| `bsi_germany` | 34 |
| `gcp_security` | 30 |
| `thehackernews` | 7 |
| `bleepingcomputer` | 6 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-17 | 13 | ? | 0% | 0% | 13 | 0 |
| 2026-06-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 14 | 0 |