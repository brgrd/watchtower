# Watchtower Pipeline Eval — 2026-05-21T23:12:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 178 |
| After dedup + CVE merge | 169 |
| Sent to Groq | 29 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/178 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,805 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7242

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 80.5 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 0% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 127 |
| `darkreading` | 7 |
| `bleepingcomputer` | 6 |
| `cisa_alerts` | 6 |
| `bsi_germany` | 6 |
| _(+21 more)_ | … |

**6 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-19 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-05-19 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-20 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |