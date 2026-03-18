# Watchtower Pipeline Eval — 2026-03-18T22:42:13Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 210 |
| After dedup + CVE merge | 209 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/210 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,694 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 9998

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 22.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 40% specific, 60% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 2 | 67% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 120 |
| `bsi_germany` | 46 |
| `securityweek` | 10 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 5 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-18 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-03-18 | 2 | 2 | 100% | 0% | 2 | 0 |