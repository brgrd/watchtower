# Watchtower Pipeline Eval — 2026-04-16T10:23:46Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 137 |
| After dedup + CVE merge | 137 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/137 (2.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,747 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8482

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 46.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 100% specific, 0% generic

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
| `nvd` | 68 |
| `bsi_germany` | 54 |
| `bleepingcomputer` | 4 |
| `securityweek` | 3 |
| `darkreading` | 2 |
| _(+19 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-14 | 3 | 3 | 100% | 100% | 0 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-14 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-15 | 3 | 2 | 100% | 0% | 1 | 0 |
| 2026-04-15 | 3 | 1 | 100% | 33% | 3 | 0 |
| 2026-04-15 | 4 | 4 | 100% | 0% | 4 | 0 |