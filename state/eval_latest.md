# Watchtower Pipeline Eval — 2026-03-28T22:40:57Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 51 |
| After dedup + CVE merge | 51 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/51 (5.9%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,752 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10467

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 83 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 48 |
| `bleepingcomputer` | 1 |
| `thehackernews` | 1 |
| `securityweek` | 1 |
| `cisa_alerts` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-24 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-25 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-26 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-27 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-28 | 3 | 1 | 100% | 100% | 2 | 0 |