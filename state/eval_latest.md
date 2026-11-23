# Watchtower Pipeline Eval — 2026-11-23T00:44:55Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 3 |
| After dedup + CVE merge | 3 |
| Sent to Groq | 3 |
| Groq findings returned | 0 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/3 (100.0%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**3 cards** — P1: 0, P2: 0, P3: 3

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 10 / 0 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

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
| `bleepingcomputer` | 3 |
| `cisa_alerts` | 0 |
| `cisa_kev` | 0 |
| `krebs` | 0 |
| `gh_security_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-17 | 9 | ? | 0% | 0% | 4 | 2 |
| 2026-11-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-19 | 6 | ? | 0% | 0% | 3 | 1 |
| 2026-11-20 | 8 | ? | 0% | 0% | 8 | 0 |
| 2026-11-21 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-11-21 | 4 | ? | 0% | 0% | 1 | 1 |
| 2026-11-22 | 15 | ? | 0% | 0% | 15 | 0 |