# Watchtower Pipeline Eval — 2026-08-07T21:49:31Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 205 |
| After dedup + CVE merge | 203 |
| Sent to Groq | 27 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/205 (1.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,744 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7436

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 53 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 148 |
| `bsi_germany` | 15 |
| `thehackernews` | 9 |
| `bleepingcomputer` | 5 |
| `github_changelog` | 5 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-05 | 3 | ? | 67% | 100% | 3 | 0 |
| 2026-08-06 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-08-06 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |