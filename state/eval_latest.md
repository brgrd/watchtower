# Watchtower Pipeline Eval — 2026-09-27T22:00:57Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 162 |
| After dedup + CVE merge | 153 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/162 (1.2%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 50% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 151 |
| `bleepingcomputer` | 3 |
| `cisa_alerts` | 2 |
| `cisa_kev` | 2 |
| `thehackernews` | 1 |
| _(+21 more)_ | … |

**18 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-09-23 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-09-23 | 4 | ? | 0% | 0% | 3 | 0 |
| 2026-09-24 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-24 | 12 | ? | 0% | 0% | 7 | 0 |
| 2026-09-25 | 9 | ? | 0% | 0% | 3 | 0 |
| 2026-09-26 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-09-26 | 1 | ? | 0% | 0% | 1 | 0 |