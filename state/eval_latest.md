# Watchtower Pipeline Eval — 2026-06-01T12:45:57Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 296 |
| After dedup + CVE merge | 294 |
| Sent to Groq | 27 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/296 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,732 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7426

## Card Quality

**2 cards** — P1: 0, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

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
| `bsi_germany` | 172 |
| `nvd` | 106 |
| `bleepingcomputer` | 4 |
| `thehackernews` | 3 |
| `securityweek` | 3 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-31 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-31 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-31 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 0% | 3 | 0 |