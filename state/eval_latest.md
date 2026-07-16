# Watchtower Pipeline Eval — 2026-07-16T22:11:16Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 274 |
| After dedup + CVE merge | 271 |
| Sent to Groq | 18 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/274 (1.1%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 18,457 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 5809

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 76.7 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 30.3 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 3 total — 33% specific, 67% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 67% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 1 | 33% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 157 |
| `bsi_germany` | 52 |
| `msrc_update_guide` | 12 |
| `bleepingcomputer` | 10 |
| `cisa_alerts` | 10 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-14 | 3 | 1 | 100% | 100% | 1 | 0 |
| 2026-07-15 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 0% | 2 | 0 |
| 2026-07-15 | 2 | 1 | 100% | 50% | 1 | 0 |
| 2026-07-15 | 3 | 2 | 100% | 0% | 2 | 0 |
| 2026-07-16 | 3 | 2 | 100% | 33% | 1 | 0 |
| 2026-07-16 | 3 | 3 | 100% | 0% | 3 | 0 |