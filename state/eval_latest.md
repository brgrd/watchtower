# Watchtower Pipeline Eval — 2026-06-02T10:52:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 316 |
| After dedup + CVE merge | 316 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/316 (0.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,592 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7743

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 90.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 33% specific, 0% generic

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
| `bsi_germany` | 127 |
| `nvd` | 94 |
| `msrc_update_guide` | 85 |
| `securityweek` | 4 |
| `thehackernews` | 2 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-31 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-31 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-06-01 | 2 | ? | 100% | 0% | 2 | 0 |
| 2026-06-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-02 | 2 | 1 | 100% | 50% | 1 | 0 |