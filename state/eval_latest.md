# Watchtower Pipeline Eval — 2026-11-17T22:10:52Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 648 |
| After dedup + CVE merge | 640 |
| Sent to Groq | 9 |
| Groq findings returned | 0 |
| Final cards rendered | 9 |
| **Pipeline yield** | **9/648 (1.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**9 cards** — P1: 0, P2: 0, P3: 9

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 58.3 / 70 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 9 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **3** | Persistent (>5): **2** | Resolved: **0**
- Mean run_count: 3 | Mean shelf_days: 22.7

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 481 |
| `bsi_germany` | 58 |
| `gcp_security` | 30 |
| `cisa_alerts` | 12 |
| `github_changelog` | 10 |
| _(+21 more)_ | … |

**8 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-11-12 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-11-13 | 9 | ? | 0% | 0% | 7 | 1 |
| 2026-11-13 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-14 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-15 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-11-16 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-11-17 | 3 | ? | 0% | 0% | 3 | 0 |