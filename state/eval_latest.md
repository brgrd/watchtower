# Watchtower Pipeline Eval — 2026-09-03T09:38:12Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 114 |
| After dedup + CVE merge | 113 |
| Sent to Groq | 5 |
| Groq findings returned | 0 |
| Final cards rendered | 5 |
| **Pipeline yield** | **5/114 (4.4%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**5 cards** — P1: 0, P2: 0, P3: 5

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 18 / 15 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 5 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **4** | Evolving (2–5): **1** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1.2 | Mean shelf_days: 0.2

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 0 | 0% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 93 |
| `nvd` | 8 |
| `cisa_kev` | 7 |
| `thehackernews` | 2 |
| `darkreading` | 2 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-08-31 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 2 | ? | 0% | 0% | 2 | 0 |
| 2026-09-01 | 9 | ? | 0% | 0% | 9 | 0 |
| 2026-09-02 | 2 | ? | 0% | 0% | 0 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-02 | 3 | ? | 0% | 0% | 3 | 0 |
| 2026-09-03 | 15 | ? | 0% | 0% | 15 | 0 |