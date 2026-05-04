# Watchtower Pipeline Eval — 2026-05-04T22:11:11Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 412 |
| After dedup + CVE merge | 412 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/412 (0.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,157 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8346

## Card Quality

**3 cards** — P1: 1, P2: 2, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 67% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 71.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 17% specific, 0% generic

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
| `nvd` | 192 |
| `bsi_germany` | 183 |
| `bleepingcomputer` | 9 |
| `securityweek` | 8 |
| `thehackernews` | 7 |
| _(+19 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-29 | 3 | 1 | 100% | 33% | 2 | 0 |
| 2026-04-30 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-01 | 2 | 2 | 100% | 0% | 0 | 0 |
| 2026-05-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-03 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-03 | 3 | ? | 100% | 0% | 3 | 0 |