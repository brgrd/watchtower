# Watchtower Pipeline Eval — 2026-04-26T10:58:28Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 22 |
| After dedup + CVE merge | 22 |
| Sent to Groq | 22 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/22 (13.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,742 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8471

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 61 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 22 |
| `cisa_alerts` | 0 |
| `krebs` | 0 |
| `bleepingcomputer` | 0 |
| `cisa_kev` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-22 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-04-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-23 | 3 | 1 | 100% | 0% | 2 | 0 |
| 2026-04-24 | 5 | 5 | 100% | 0% | 5 | 0 |
| 2026-04-25 | 3 | 3 | 100% | 0% | 1 | 0 |
| 2026-04-25 | 5 | ? | 100% | 0% | 5 | 0 |
| 2026-04-26 | 3 | 1 | 100% | 0% | 3 | 0 |