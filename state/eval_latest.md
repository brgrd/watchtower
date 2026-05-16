# Watchtower Pipeline Eval — 2026-05-16T00:01:48Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 169 |
| After dedup + CVE merge | 166 |
| Sent to Groq | 26 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/169 (1.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,978 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6896

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 140 |
| `bleepingcomputer` | 7 |
| `msrc_update_guide` | 4 |
| `github_changelog` | 3 |
| `cyberscoop` | 3 |
| _(+21 more)_ | … |

**13 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 100% | 3 | 0 |