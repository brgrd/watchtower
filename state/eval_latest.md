# Watchtower Pipeline Eval — 2026-04-14T10:23:39Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 212 |
| After dedup + CVE merge | 211 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/212 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,111 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7879

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 33 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **3** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 3 | 100% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 113 |
| `nvd` | 79 |
| `cisa_kev` | 7 |
| `thehackernews` | 4 |
| `securityweek` | 3 |
| _(+19 more)_ | … |

**14 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-09 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-10 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-04-11 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-11 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-12 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-13 | 3 | 3 | 100% | 33% | 3 | 0 |