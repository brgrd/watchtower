# Watchtower Pipeline Eval — 2026-07-03T23:14:20Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 466 |
| After dedup + CVE merge | 423 |
| Sent to Groq | 120 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/466 (3.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 13,161 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6960

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `msrc_update_guide` | 328 |
| `nvd` | 127 |
| `thehackernews` | 5 |
| `bleepingcomputer` | 2 |
| `bsi_germany` | 2 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 33% | 2 | 0 |
| 2026-07-02 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-07-03 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-03 | 1 | 1 | 100% | 100% | 0 | 0 |