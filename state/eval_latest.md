# Watchtower Pipeline Eval — 2026-05-24T10:02:46Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 3 |
| After dedup + CVE merge | 3 |
| Sent to Groq | 3 |
| Groq findings returned | 1 |
| Passed quality gate | 1 |
| Final cards rendered | 1 |
| **Pipeline yield** | **1/3 (33.3%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 8,113 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 8093

## Card Quality

**1 cards** — P1: 1, P2: 0, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 70 / 70 |
| Tactic coverage | 100% |
| CVE coverage | 100% |
| Patch status | unknown: 1 |

### Reasoning Quality

- **`why_now` avg length**: 57 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 2 total — 50% specific, 50% generic

### Persistence

- New (run=1): **1** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 1 | 100% |
| NVD (CVE) | 1 | 100% |
| CISA KEV | 0 | 0% |

## Feed Yield

| Feed | Items |
|------|------:|
| `darkreading` | 2 |
| `msrc_update_guide` | 1 |
| `gh_security_blog` | 0 |
| `bleepingcomputer` | 0 |
| `krebs` | 0 |
| _(+20 more)_ | … |

**20 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-20 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-20 | 3 | 2 | 100% | 0% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 33% | 3 | 0 |
| 2026-05-21 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-21 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-23 | 3 | 3 | 100% | 100% | 3 | 0 |
| 2026-05-23 | 3 | 1 | 100% | 0% | 3 | 0 |