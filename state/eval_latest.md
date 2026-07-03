# Watchtower Pipeline Eval — 2026-07-03T10:47:02Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 283 |
| After dedup + CVE merge | 283 |
| Sent to Groq | 120 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/283 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,509 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6876

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 80 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 62 chars (100% ≥ 60 chars, considered substantive)
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
| `nvd` | 82 |
| `msrc_update_guide` | 61 |
| `securityweek` | 4 |
| `bleepingcomputer` | 2 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-01 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 33% | 2 | 0 |
| 2026-07-02 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 100% | 3 | 0 |