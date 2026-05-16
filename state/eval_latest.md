# Watchtower Pipeline Eval — 2026-05-16T11:59:58Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 26 |
| After dedup + CVE merge | 26 |
| Sent to Groq | 7 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/26 (11.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,695 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7360

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 19 |
| `nvd` | 3 |
| `cisa_kev` | 1 |
| `github_changelog` | 1 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-16 | 2 | 1 | 100% | 100% | 2 | 0 |