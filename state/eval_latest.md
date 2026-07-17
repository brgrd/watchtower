# Watchtower Pipeline Eval — 2026-07-17T00:07:31Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 234 |
| After dedup + CVE merge | 230 |
| Sent to Groq | 18 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/234 (1.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,560 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6976

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 100 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.3 | Mean shelf_days: 0.3

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 185 |
| `msrc_update_guide` | 12 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 5 |
| `github_changelog` | 4 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-15 | 3 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-16 | 3 | 2 | 100% | 33% | 1 | 0 |
| 2026-07-16 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-16 | 3 | 1 | 100% | 33% | 3 | 0 |