# Watchtower Pipeline Eval — 2026-10-24T23:05:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 38 |
| After dedup + CVE merge | 36 |
| Sent to Groq | 36 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/38 (39.5%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 56 / 70 |
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
| EPSS | 4 | 27% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 34 |
| `thehackernews` | 3 |
| `bleepingcomputer` | 1 |
| `cisa_kev` | 0 |
| `krebs` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-21 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-22 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-22 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-10-23 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-10-23 | 14 | ? | 0% | 0% | 8 | 0 |
| 2026-10-24 | 2 | ? | 0% | 0% | 0 | 0 |
| 2026-10-24 | 15 | ? | 0% | 0% | 13 | 0 |