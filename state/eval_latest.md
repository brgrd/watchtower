# Watchtower Pipeline Eval — 2026-07-26T23:06:42Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 8 |
| After dedup + CVE merge | 8 |
| Sent to Groq | 8 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/8 (25.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,108 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7611

## Card Quality

**2 cards** — P1: 0, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 55 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 0% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 7 |
| `bleepingcomputer` | 1 |
| `cisa_kev` | 0 |
| `thehackernews` | 0 |
| `cisa_alerts` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-25 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-07-25 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-25 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-07-26 | 3 | 3 | 100% | 0% | 3 | 0 |