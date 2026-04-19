# Watchtower Pipeline Eval — 2026-04-19T22:50:04Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 15 |
| After dedup + CVE merge | 15 |
| Sent to Groq | 15 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/15 (20.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,084 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8153

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 32.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 0% generic

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
| `nvd` | 12 |
| `bleepingcomputer` | 3 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| `krebs` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-16 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-04-19 | 3 | ? | 100% | 0% | 3 | 0 |