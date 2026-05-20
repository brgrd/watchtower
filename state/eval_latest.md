# Watchtower Pipeline Eval — 2026-05-20T23:22:43Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 204 |
| After dedup + CVE merge | 191 |
| Sent to Groq | 29 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/204 (1.5%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 19,085 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5461

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 58 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 3 | 100% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 115 |
| `gcp_security` | 30 |
| `bsi_germany` | 9 |
| `cisa_kev` | 7 |
| `darkreading` | 7 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-19 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-19 | 3 | 2 | 100% | 33% | 3 | 0 |
| 2026-05-19 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-20 | 3 | 3 | 100% | 100% | 3 | 0 |