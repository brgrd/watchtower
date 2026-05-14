# Watchtower Pipeline Eval — 2026-05-14T10:28:47Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 75 |
| After dedup + CVE merge | 73 |
| Sent to Groq | 30 |
| Groq findings returned | 2 |
| Passed quality gate | 2 |
| Final cards rendered | 2 |
| **Pipeline yield** | **2/75 (2.7%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 11,966 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7023

## Card Quality

**2 cards** — P1: 1, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 65 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 2 |

### Reasoning Quality

- **`why_now` avg length**: 45 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 4 total — 50% specific, 0% generic

### Persistence

- New (run=1): **2** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
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
| `nvd` | 62 |
| `bleepingcomputer` | 3 |
| `thehackernews` | 3 |
| `securityweek` | 3 |
| `aws_security_bulletins` | 2 |
| _(+21 more)_ | … |

**19 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-12 | 3 | 2 | 100% | 100% | 3 | 0 |
| 2026-05-12 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-12 | 1 | 1 | 100% | 100% | 1 | 0 |
| 2026-05-13 | 1 | 1 | 100% | 0% | 0 | 0 |
| 2026-05-13 | 3 | 3 | 100% | 0% | 3 | 0 |
| 2026-05-13 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-14 | 2 | 1 | 100% | 0% | 2 | 0 |