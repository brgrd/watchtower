# Watchtower Pipeline Eval — 2026-10-24T00:34:51Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 413 |
| After dedup + CVE merge | 404 |
| Sent to Groq | 2 |
| Groq findings returned | 0 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/413 (0.5%)** |

## Groq
- **Model**: `unknown`
- **Payload**: ? chars
- **Parse**: ✗  |  **Retries**: 0
- **Rate limit remaining** — requests: ?, tokens: ?

## Card Quality

**2 cards** — P1: 0, P2: 0, P3: 2

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 52.5 / 45 |
| Tactic coverage | 0% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 0 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 0 total — 0% specific, 0% generic

### Persistence

- New (run=1): **0** | Evolving (2–5): **2** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 3.5 | Mean shelf_days: 25.5

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 2 | 100% |
| NVD (CVE) | 0 | 0% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `nvd` | 342 |
| `gcp_security` | 30 |
| `bleepingcomputer` | 7 |
| `aws_security_bulletins` | 7 |
| `darkreading` | 5 |
| _(+21 more)_ | … |

**11 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-10-20 | 7 | ? | 0% | 0% | 6 | 0 |
| 2026-10-21 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-10-21 | 15 | ? | 0% | 0% | 15 | 0 |
| 2026-10-22 | 1 | ? | 0% | 0% | 0 | 0 |
| 2026-10-22 | 5 | ? | 0% | 0% | 5 | 0 |
| 2026-10-23 | 2 | ? | 0% | 0% | 1 | 0 |
| 2026-10-23 | 14 | ? | 0% | 0% | 8 | 0 |