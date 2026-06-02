# Watchtower Pipeline Eval — 2026-06-02T23:56:52Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 224 |
| After dedup + CVE merge | 218 |
| Sent to Groq | 29 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/224 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 16,571 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6053

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 34 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 67% specific, 33% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 169 |
| `github_changelog` | 10 |
| `bleepingcomputer` | 9 |
| `darkreading` | 8 |
| `securityweek` | 7 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-31 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-06-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-06-02 | 3 | 3 | 100% | 0% | 3 | 0 |