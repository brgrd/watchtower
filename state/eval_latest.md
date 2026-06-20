# Watchtower Pipeline Eval — 2026-06-20T11:24:25Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 33 |
| After dedup + CVE merge | 33 |
| Sent to Groq | 17 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/33 (9.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,809 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7363

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 16 |
| `msrc_update_guide` | 13 |
| `bleepingcomputer` | 1 |
| `thehackernews` | 1 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 15 | 0 |