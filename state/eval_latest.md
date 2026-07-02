# Watchtower Pipeline Eval — 2026-07-02T23:18:00Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 248 |
| After dedup + CVE merge | 242 |
| Sent to Groq | 24 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/248 (1.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 12,894 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6910

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 63.3 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 39 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 194 |
| `bsi_germany` | 17 |
| `msrc_update_guide` | 6 |
| `thehackernews` | 5 |
| `darkreading` | 5 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-01 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-01 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-01 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-07-02 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-02 | 3 | 1 | 100% | 33% | 2 | 0 |
| 2026-07-02 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-02 | 3 | 3 | 100% | 0% | 3 | 0 |