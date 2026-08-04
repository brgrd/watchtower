# Watchtower Pipeline Eval — 2026-08-04T21:21:18Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 274 |
| After dedup + CVE merge | 268 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/274 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,484 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6632

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 67% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 28.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 2 | 67% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 182 |
| `bsi_germany` | 33 |
| `securityweek` | 10 |
| `cloudflare_blog` | 7 |
| `thehackernews` | 6 |
| _(+21 more)_ | … |

**9 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-02 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-03 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-08-03 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-03 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-08-03 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-04 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-04 | 3 | 3 | 100% | 0% | 3 | 0 |