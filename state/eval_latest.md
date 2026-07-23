# Watchtower Pipeline Eval — 2026-07-23T12:44:58Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 553 |
| After dedup + CVE merge | 550 |
| Sent to Groq | 2 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/553 (0.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,906 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7889

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 50% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 38.5 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 67% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 1 | 50% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 245 |
| `nvd` | 242 |
| `msrc_update_guide` | 45 |
| `bleepingcomputer` | 5 |
| `thehackernews` | 5 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-21 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-22 | 15 | ? | 0% | 0% | 6 | 1 |
| 2026-07-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-23 | 2 | 1 | 100% | 0% | 1 | 0 |