# Watchtower Pipeline Eval — 2026-06-14T00:18:08Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 10 |
| After dedup + CVE merge | 10 |
| Sent to Groq | 10 |
| Groq findings returned | 5 |
| Passed quality gate | 5 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/10 (50.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,377 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6729

## Card Quality

**5 cards** — P1: 1, P2: 4, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 77 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 20% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 75 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 100% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.4 | Mean shelf_days: 0.4

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 20% |
| NVD (CVE) | 1 | 20% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 5 |
| `bleepingcomputer` | 2 |
| `thehackernews` | 1 |
| `cyberscoop` | 1 |
| `securityweek` | 1 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-11 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-06-11 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-12 | 2 | 2 | 100% | 0% | 2 | 0 |
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-12 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-06-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-06-13 | 3 | 3 | 100% | 100% | 3 | 0 |