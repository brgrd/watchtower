# Watchtower Pipeline Eval — 2026-04-15T22:01:18Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 225 |
| After dedup + CVE merge | 223 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/225 (1.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,696 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8239

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 27.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 165 |
| `bsi_germany` | 12 |
| `securityweek` | 10 |
| `bleepingcomputer` | 8 |
| `cloudflare_blog` | 6 |
| _(+19 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-15 | 3 | 2 | 100% | 0% | 1 | 0 |