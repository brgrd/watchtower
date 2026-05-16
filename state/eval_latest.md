# Watchtower Pipeline Eval — 2026-05-16T22:58:44Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 48 |
| After dedup + CVE merge | 48 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/48 (6.2%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 9,591 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 7676

## Card Quality

**3 cards** — P1: 1, P2: 1, P3: 1

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 60 / 60 |
| Tactic coverage | 100% |
| CVE coverage | 0% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 59 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 5 total — 60% specific, 0% generic

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
| `nvd` | 44 |
| `bleepingcomputer` | 2 |
| `thehackernews` | 1 |
| `darkreading` | 1 |
| `gh_security_blog` | 0 |
| _(+21 more)_ | … |

**21 feeds returned 0 items this run.**

## 7-Run Trend

| Date | Cards | P1 | Tactic% | CVE% | New | Persistent |
|------|---------|----|---------|------|-----|------------|
| 2026-05-15 | 3 | ? | 100% | 0% | 3 | 0 |
| 2026-05-15 | 3 | ? | 100% | 100% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-16 | 2 | 1 | 100% | 100% | 2 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 100% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |
| 2026-05-16 | 3 | 1 | 100% | 0% | 3 | 0 |