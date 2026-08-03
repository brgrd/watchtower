# Watchtower Pipeline Eval — 2026-08-03T23:13:20Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 219 |
| After dedup + CVE merge | 211 |
| Sent to Groq | 27 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/219 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,108 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6744

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 54.3 chars (33% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 149 |
| `bsi_germany` | 26 |
| `securityweek` | 7 |
| `bleepingcomputer` | 5 |
| `thehackernews` | 5 |
| _(+21 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-02 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-02 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-08-02 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-08-03 | 3 | 3 | 100% | 0% | 2 | 0 |
| 2026-08-03 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-03 | 2 | 1 | 100% | 100% | 2 | 0 |