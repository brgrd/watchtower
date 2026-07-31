# Watchtower Pipeline Eval — 2026-07-31T23:11:57Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 234 |
| After dedup + CVE merge | 225 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/234 (1.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 15,301 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 6436

## Card Quality

**3 cards** — P1: 3, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 50 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

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
| `nvd` | 141 |
| `gcp_security` | 30 |
| `bsi_germany` | 28 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 7 |
| _(+21 more)_ | … |

**12 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-07-29 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-30 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-07-31 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-07-31 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-07-31 | 3 | 2 | 100% | 100% | 3 | 0 |