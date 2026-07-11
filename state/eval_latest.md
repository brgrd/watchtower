# Watchtower Pipeline Eval — 2026-07-11T21:00:34Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 172 |
| After dedup + CVE merge | 172 |
| Sent to Groq | 25 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/172 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,592 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7687

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 57 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 100% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `msrc_update_guide` | 142 |
| `nvd` | 25 |
| `bleepingcomputer` | 2 |
| `thehackernews` | 2 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-09 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-10 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-10 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-11 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-11 | 3 | 3 | 100% | 0% | 3 | 0 |