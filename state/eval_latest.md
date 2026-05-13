# Watchtower Pipeline Eval — 2026-05-13T11:34:43Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 221 |
| After dedup + CVE merge | 221 |
| Sent to Groq | 19 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/221 (1.4%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 10,762 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7481

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 23 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 0% generic

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
| `bsi_germany` | 156 |
| `msrc_update_guide` | 36 |
| `nvd` | 18 |
| `securityweek` | 6 |
| `thehackernews` | 2 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-09 | 2 | 1 | 100% | 0% | 1 | 0 |
| 2026-05-11 | 2 | 1 | 100% | 50% | 2 | 0 |
| 2026-05-11 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-05-12 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-05-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-12 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-13 | 1 | 1 | 100% | 0% | 0 | 0 |