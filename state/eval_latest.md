# Watchtower Pipeline Eval — 2026-08-09T21:41:10Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 28 |
| After dedup + CVE merge | 28 |
| Sent to Groq | 28 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/28 (53.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,594 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7625

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
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
| EPSS | 2 | 13% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 28 |
| `bleepingcomputer` | 0 |
| `krebs` | 0 |
| `cisa_kev` | 0 |
| `cloudflare_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-08 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-08 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-08 | 1 | 1 | 100% | 0% | 1 | 0 |
| 2026-08-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-09 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-09 | 3 | 1 | 100% | 67% | 3 | 0 |
| 2026-08-09 | 3 | 2 | 100% | 33% | 3 | 0 |