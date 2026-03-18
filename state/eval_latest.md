# Watchtower Pipeline Eval — 2026-03-18T20:15:09Z

## Pipeline Yield

| Stage | Count |
|-------|------:|
| Items polled (raw) | 301 |
| After dedup + CVE merge | 300 |
| Sent to Groq | 30 |
| Groq findings returned | 3 |
| Passed quality gate | 3 |
| Final cards rendered | 3 |
| **Pipeline yield** | **3/301 (1.0%)** |

## Groq
- **Model**: `llama-3.3-70b-versatile`
- **Payload**: 7,693 chars
- **Parse**: ✓  |  **Retries**: 0
- **Rate limit remaining** — requests: 999, tokens: 10039

## Card Quality

**3 cards** — P1: 2, P2: 1, P3: 0

| Metric | Value |
|--------|-------|
| Risk score mean / p90 | 90 / 100 |
| Tactic coverage | 100% |
| CVE coverage | 33% |
| Patch status | unknown: 3 |

### Reasoning Quality

- **`why_now` avg length**: 56.7 chars (0% ≥ 60 chars, considered substantive)
- **Recommended actions**: 6 total — 50% specific, 50% generic

### Persistence

- New (run=1): **3** | Evolving (2–5): **0** | Persistent (>5): **0** | Resolved: **0**
- Mean run_count: 1 | Mean shelf_days: 0

## Enrichment Hit Rates

| Source | Hits | Rate |
|--------|-----:|-----:|
| EPSS | 3 | 100% |
| NVD (CVE) | 1 | 33% |
| CISA KEV | 2 | 67% |

## Feed Yield

| Feed | Items |
|------|------:|
| `bsi_germany` | 155 |
| `nvd` | 103 |
| `securityweek` | 10 |
| `bleepingcomputer` | 7 |
| `thehackernews` | 6 |
| _(+19 more)_ | … |

**10 feeds returned 0 items this run.**