# Watchtower Pipeline Eval — 2026-08-07T23:41:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 212 |
| After dedup + CVE merge | 206 |
| Sent to Groq | 5 |
| Groq findings returned | 0 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/212 (2.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,345 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6866

## Card Quality

**5 cards** — P1: 0, P2: 0, P3: 5

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 77 / 75 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **1** | Persistent (>5): **3** | Resolved: **0**
- Mean run_count: 5.2 | Mean shelf_days: 64.6

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 143 |
| `gcp_security` | 30 |
| `github_changelog` | 7 |
| `bleepingcomputer` | 5 |
| `thehackernews` | 5 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-06 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-07 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-07 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-08-07 | 3 | 1 | 100% | 0% | 3 | 0 |