# Watchtower Pipeline Eval — 2026-08-05T09:42:46Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 321 |
| After dedup + CVE merge | 320 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/321 (0.6%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,314 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7197

## Card Quality

**2 cards** — P1: 2, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 75 / 75 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 68 chars (100% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 50% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 2 | Mean shelf_days: 1

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 2 | 100% |
| CISA KEV | 2 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 187 |
| `bsi_germany` | 117 |
| `cyberscoop` | 4 |
| `bleepingcomputer` | 3 |
| `cisa_kev` | 3 |
| _(+21 more)_ | … |

**17 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-03 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-03 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-08-03 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-08-04 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-08-04 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-08-04 | 3 | 1 | 100% | 67% | 3 | 0 |
| 2026-08-04 | 3 | 3 | 100% | 0% | 3 | 0 |