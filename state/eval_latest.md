# Watchtower Pipeline Eval — 2026-07-14T09:12:01Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 242 |
| After dedup + CVE merge | 242 |
| Sent to Groq | 24 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/242 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,835 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7601

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 85 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 25 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 25% specific, 50% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 1 | 50% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 121 |
| `nvd` | 106 |
| `msrc_update_guide` | 6 |
| `thehackernews` | 3 |
| `securityweek` | 2 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-12 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | ? | 100% | 0% | 2 | 0 |
| 2026-07-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-13 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-07-14 | 3 | 1 | 100% | 100% | 3 | 0 |