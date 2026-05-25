# Watchtower Pipeline Eval — 2026-05-25T12:42:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 16 |
| After dedup + CVE merge | 15 |
| Sent to Groq | 15 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/16 (18.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,818 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6640

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 80 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 72.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `securityweek` | 6 |
| `thehackernews` | 4 |
| `msrc_update_guide` | 3 |
| `darkreading` | 2 |
| `bleepingcomputer` | 1 |
| _(+20 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-21 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-23 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-23 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-24 | 1 | 1 | 100% | 100% | 1 | 0 |