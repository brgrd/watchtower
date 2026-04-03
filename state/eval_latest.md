# Watchtower Pipeline Eval — 2026-04-03T22:47:27Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 195 |
| After dedup + CVE merge | 195 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/195 (1.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,762 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8503

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 50 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 54 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 75% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 158 |
| `darkreading` | 8 |
| `securityweek` | 6 |
| `bleepingcomputer` | 5 |
| `therecord` | 5 |
| _(+19 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-29 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-29 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-03-30 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-03-31 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-04-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-03 | 3 | 3 | 100% | 0% | 3 | 0 |