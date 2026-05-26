# Watchtower Pipeline Eval — 2026-05-26T23:18:03Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 399 |
| After dedup + CVE merge | 395 |
| Sent to Groq | 26 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/399 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,949 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7155

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 108 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 240 |
| `bsi_germany` | 114 |
| `cisa_alerts` | 8 |
| `github_changelog` | 6 |
| `darkreading` | 6 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-21 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-23 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-23 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-24 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-25 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-26 | 2 | 1 | 100% | 0% | 2 | 0 |