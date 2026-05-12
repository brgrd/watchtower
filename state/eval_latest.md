# Watchtower Pipeline Eval — 2026-05-12T00:06:19Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 370 |
| After dedup + CVE merge | 361 |
| Sent to Groq | 28 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/370 (0.8%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 17,675 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5798

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 66.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 50 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 33% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 312 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 4 |
| `therecord` | 4 |
| _(+21 more)_ | … |

**15 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-08 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-08 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-05-09 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-11 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-05-11 | 15 | ? | 0% | 0% | 14 | 0 |