# Watchtower Pipeline Eval — 2026-04-15T22:55:29Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 191 |
| After dedup + CVE merge | 189 |
| Sent to Groq | 29 |
| Groq findings returned | 4 |
| Passed quality gate | 4 |
| Final cards rendered | 4 |
| **Pipeline yield** | **4/191 (2.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,230 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8341

## Card Quality

**4 cards** — P1: 4, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 4 |

### Reasoning Quality

- **`why_now` avg length**: 73 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 8 total — 50% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 144 |
| `securityweek` | 9 |
| `bleepingcomputer` | 8 |
| `cloudflare_blog` | 6 |
| `therecord` | 5 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-12 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-15 | 3 | 2 | 100% | 0% | 1 | 0 |
| 2026-04-15 | 3 | 1 | 100% | 33% | 3 | 0 |