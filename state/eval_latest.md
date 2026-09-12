# Watchtower Pipeline Eval — 2026-09-12T10:37:06Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 122 |
| After dedup + CVE merge | 119 |
| Sent to Groq | 119 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/122 (12.3%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 55.7 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 15 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **15** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 7% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 94 |
| `msrc_update_guide` | 17 |
| `cisa_kev` | 4 |
| `cyberscoop` | 2 |
| `darkreading` | 2 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-09 | 15 | ? | 0% | 0% | 3 | 0 |
| 2026-09-10 | 11 | ? | 0% | 0% | 4 | 0 |
| 2026-09-10 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-10 | 6 | ? | 0% | 0% | 5 | 0 |
| 2026-09-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-11 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-11 | 7 | ? | 0% | 0% | 7 | 0 |