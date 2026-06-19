# Watchtower Pipeline Eval — 2026-06-19T23:09:49Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 140 |
| After dedup + CVE merge | 97 |
| Sent to Groq | 97 |
| Groq findings returned | 0 |
| Final cards rendered | 15 |
| **Pipeline yield** | **15/140 (10.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 14,604 chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6778

## Card Quality

**15 cards** — P1: 0, P2: 0, P3: 15

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 40 / 40 |
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
| EPSS | 15 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `msrc_update_guide` | 89 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 6 |
| `thehackernews` | 6 |
| `securityweek` | 2 |
| _(+21 more)_ | … |

**16 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-06-17 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-06-18 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-06-18 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-06-18 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 15 | ? | 0% | 0% | 14 | 0 |
| 2026-06-19 | 3 | 3 | 100% | 100% | 3 | 0 |