# Watchtower Pipeline Eval — 2026-05-16T10:23:12Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 28 |
| After dedup + CVE merge | 28 |
| Sent to Groq | 9 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/28 (7.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,050 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7060

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 38.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 19 |
| `nvd` | 4 |
| `github_changelog` | 1 |
| `cisa_kev` | 1 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |