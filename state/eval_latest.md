# Watchtower Pipeline Eval — 2026-04-19T10:53:40Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 9 |
| After dedup + CVE merge | 9 |
| Sent to Groq | 9 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/9 (33.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 5,535 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8526

## Card Quality

**3 cards** — P1: 0, P2: 3, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 75.3 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 0% specific, 100% generic

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
| `nvd` | 9 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| `bleepingcomputer` | 0 |
| `krebs` | 0 |
| _(+19 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-04-15 | 4 | 4 | 100% | 0% | 4 | 0 |
| 2026-04-16 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-04-17 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-04-18 | 3 | 3 | 100% | 100% | 3 | 0 |