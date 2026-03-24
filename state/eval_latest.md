# Watchtower Pipeline Eval — 2026-03-24T10:05:54Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 191 |
| After dedup + CVE merge | 189 |
| Sent to Groq | 30 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/191 (0.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 6,220 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10302

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 131 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 0% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 146 |
| `bsi_germany` | 32 |
| `bleepingcomputer` | 3 |
| `darkreading` | 3 |
| `thehackernews` | 2 |
| _(+19 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-03-20 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-03-20 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-03-21 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-03-22 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-03-22 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-03-23 | 3 | 2 | 100% | 0% | 3 | 0 |