# Watchtower Upgrades Tracker

Prioritized by **impact × simplicity**. Free-tier architecture only (GitHub Actions, Groq free, public APIs).

Keep each item open until code, tests, and docs are complete.

---

## Pending

### High Priority

- [x] **Extend CARDS JS object**
  - `CARDS` holds only `{id, title, risk_score, priority, domains, summary, sources}`. Fields already on every card but missing: `shelf_days`, `run_count`, `tactic_name`, `recommended_actions_24h`, `first_seen_ts`.
  - Blocks the catch-up view, Alerts tab content, and action aggregation. Trivial to fix.
  - Scope: 6-line change to `card_data` builder in [agent/html_builder.py](agent/html_builder.py).

- [ ] **Alerts tab — real content from render-time data**
  - Currently a placeholder ("Reserved module slot"). All prerequisite data exists at render time; no new backend needed. Replace with three panels:
    1. **Persistent** — `run_count ≥ 3`, sorted descending, labeled "Seen N runs".
    2. **Elevated** — `risk_score` increased ≥10 from last run (from `delta["elevated"]`), labeled with delta.
    3. **P1 / Attribution** — all P1 cards + `attribution_flag: true` cards.
  - Scope: `_build_alerts_html(cards, delta)` in [agent/html_builder.py](agent/html_builder.py); wired into `_write_index_html`.

- [x] **CISA KEV explicit card badge**
  - CISA KEV data is polled and fed to Groq but never surfaces as a card-level badge. Confirmed KEV-listed CVEs are categorically more urgent than news-sourced findings — CISA confirmation means active in-the-wild exploitation.
  - Derive `is_kev: bool` at card build time: true when `source_category == "vulns"` and `source_id == "cisa_kev"`. Render red `CISA KEV` chip before the priority pill.
  - Scope: `_findings_to_cards()` in [agent/runner.py](agent/runner.py); `.kev-badge` CSS + render in [agent/html_builder.py](agent/html_builder.py).

- [ ] **Priority Actions aggregation panel**
  - Every card has `recommended_actions_24h` (up to 4 items). Across 15 findings many are structurally identical. Analysts who only scan the top miss them.
  - Deduplicate and count `recommended_actions_24h` across all P1 and P2 cards. Show the top 5–7 as a numbered list in a "Priority Actions" panel between the KPI grid and threat map. Group by first 40 chars; show occurrence count as a chip.
  - Scope: `_build_priority_actions_html(cards)` in [agent/html_builder.py](agent/html_builder.py); pure Python Counter.

- [ ] **Groq model fallback list**
  - 5-attempt retry handles rate limits but has no fallback model. If `llama-3.3-70b-versatile` is deprecated or over quota the run silently produces a blank briefing.
  - Add `model_fallback` list to [agent/config.yaml](agent/config.yaml). After exhausting retries on primary, try each fallback in order. Set `groq_status = "fallback:<model>"` in run metrics.
  - Scope: [agent/analysis.py](agent/analysis.py) + [agent/config.yaml](agent/config.yaml); ~30 lines.

- [ ] **Finding quality gate (post-Groq filter)**
  - Groq occasionally produces low-signal findings: vague title, single-sentence summary, no CVE, no technique. These inflate count without adding value.
  - `_quality_score(card)`: score on title length > 20 chars, CVE or product name present, summary > 60 chars, `why_now` present. Cards below threshold (default: 2/4 met) logged as `[QUALITY DROP]` and excluded.
  - Scope: [agent/scoring.py](agent/scoring.py) or [agent/analysis.py](agent/analysis.py); no new deps; count logged in `run_metrics`.

- [ ] **Tactic normalization tests**
  - `_normalize_tactic()` covers ~15 alias paths but has zero test coverage. A single Groq prompt change silently breaks all tactic chips and the kill-chain coverage bar.
  - Parameterized cases: exact match, alias match (c2, privesc, evasion, lateral-movement variants), prefix match, garbage input, empty string, `None`.
  - Scope: `tests/test_tactic_normalization.py` — ~30 lines; `_normalize_tactic` already importable from [agent/analysis.py](agent/analysis.py).

---

### Medium Priority

- [ ] **EPSS exploitation probability badge**
  - Patch status is "unknown" for the vast majority of findings. EPSS from `api.first.org/data/v1/epss?cve=CVE-XXXX` (free, no key) gives real probability-of-exploitation per CVE, refreshed daily. Stronger real-world predictor than CVSS alone.
  - High-EPSS findings (> 0.4) get a distinct badge even at moderate CVSS. Cache in `state/epss_cache.json` (TTL 24h).
  - Scope: `_enrich_epss(cards)` in [agent/ingest.py](agent/ingest.py); `.epss-badge` CSS variant; called after enrichment pass in `_run()`.

- [ ] **"Since your last visit" catch-up view**
  - After > 4 hours away, render a collapsible `<details>` strip at top: "Catch-up since [timestamp] — N new findings". Closes the passive-monitor check-in friction problem at zero backend cost.
  - Requires `first_seen_ts` in CARDS (see item above).
  - Scope: JS-only in [agent/html_builder.py](agent/html_builder.py); sets `wt.last_visit` on DOMContentLoaded.

- [ ] **Shelf life CVE key**
  - Shelf keys are `sha256(title)[:16]`. Two articles about the same CVE get separate shelf entries, diluting persistence signals.
  - Use the primary CVE ID as shelf key (`"cve:CVE-2026-XXXXX"`) when extractable; fall back to title hash.
  - Scope: `_update_shelf()` in [agent/runner.py](agent/runner.py) — 5-line change using `_extract_cves()` already available.

- [ ] **Shelf life decay and resolved-finding suppression**
  - Shelf boosts scores indefinitely (up to +20) and never downgrades. A patched CVE still accumulates persistence boost across subsequent runs.
  - Add `resolved` flag when `patch_status == "patched"`: zero the boost, change badge to grey `Nd (resolved)`. Prune shelf entry 7 days post-resolution.
  - Scope: `_update_shelf()` in [agent/runner.py](agent/runner.py); `.shelf-badge--resolved` CSS variant in [agent/html_builder.py](agent/html_builder.py).

- [ ] **Corroboration count badge**
  - `corroboration_count` is computed per cluster and passed to Groq but never shown. A finding cited by 5 independent sources is more credible than a single-source finding at the same score.
  - Show `N sources` chip on cards where `corroboration_count ≥ 2`. Single-source: no badge.
  - Scope: pass `corroboration_count` through `_findings_to_cards()` → card dict → [agent/html_builder.py](agent/html_builder.py) render.

- [ ] **KPI P1 delta and exploited delta**
  - "Trend 24h" shows overall ±N count change — too coarse. A flat overall count with 3 new P1s is a different situation.
  - Add `+N ↑` / `−N ↓` sub-labels under the P1 and Exploited KPI tiles, computed from `delta["new"]` / `delta["elevated"]` filtered by priority/exploited flag.
  - Scope: `_write_index_html` in [agent/html_builder.py](agent/html_builder.py); `delta` dict is already an argument.

- [ ] **Dead feed detection**
  - `feed_health.json` tracks HTTP success/failure but a feed returning HTTP 200 with 0 new items is indistinguishable from healthy. Stale feeds silently narrow coverage.
  - Track `last_item_ts` per feed. Flag feeds where `last_item_ts` is > 72h ago with a "Stale" badge in the Feeds tab. Separate from "failed" coloring.
  - Scope: `_update_feed_health()` in [agent/runner.py](agent/runner.py); stale badge CSS in [agent/html_builder.py](agent/html_builder.py).

- [ ] **Constellation node count labels**
  - Nodes are heat-colored but show no count. Users must click to discover how many findings map to each domain.
  - Add a small count text inside each node disc (0.65rem, bottom-aligned). Zero-count nodes: no label. Count > 9: "9+".
  - Scope: `_build_threat_map_svg()` in [agent/html_builder.py](agent/html_builder.py); `<text>` element per node using `heatmap` counts.

- [ ] **Briefing staleness warning**
  - If the page is opened and the generated timestamp is > 28h old (e.g., Actions failure), users may act on stale data.
  - On DOMContentLoaded, parse the existing header timestamp. If > 28h, inject a yellow "⚠ Briefing may be stale — generated N hours ago" banner.
  - Scope: 8-line JS in [agent/html_builder.py](agent/html_builder.py); uses the timestamp already in the DOM.

- [ ] **Unread count in browser tab title**
  - `document.title = "[2 P1] Watchtower — InfraSec Briefing"` gives a passive signal to users with the tab open in the background.
  - Scope: 3-line JS addition; zero risk.

- [ ] **Coverage push: `ingest.py` (19%) and `state.py` (31%)**
  - Both sit on the critical data path (feed fetch, CVE merge, all persistence). Regressions produce silent bad output.
  - Target: `ingest.py` → 40%, `state.py` → 55%. Focus on `_merge_by_cve()` edge cases, `bootstrap_seen_from_reports()`, `_update_ioc_ledger()`, `_purge_seen_ttl()` boundary conditions.
  - Scope: additions to `tests/test_ingest.py` and `tests/test_state.py`.

---

### Lower Priority

- [ ] **Domain sparklines in the Overview rail**
  - Replace static domain score bars with 7-day inline SVG sparklines. A 3-day rising trend is a different signal than a one-day spike at the same current score. All data already in `history_days`.
  - Scope: `_build_domain_rank_html()` in [agent/html_builder.py](agent/html_builder.py); inline `<svg><polyline>` per row (~30px tall).

- [ ] **Interactive constellation — blast-radius path highlighting**
  - On node click, highlight directed paths to all reachable downstream domains via `_TM_EDGES`. Makes blast-radius reasoning visual rather than implicit.
  - Scope: JS-only change to `selectDomain()` and SVG edge rendering in [agent/html_builder.py](agent/html_builder.py).

- [ ] **Client-side keyword watchlist in Alerts tab**
  - Keyword input (CVE IDs, vendor names, product keywords) in the Alerts tab. JS scans `CARDS` and adds `.watchlist-match` ring on matches; scrolls into view. Terms stored in `localStorage.wt.watchlist`.
  - Scope: JS + CSS in [agent/html_builder.py](agent/html_builder.py); zero backend.

- [ ] **Push digest / webhook alerts**
  - Notify when: P1 count exceeds threshold, a watchlist keyword matches a new finding, or a finding persists N consecutive runs.
  - Scope: new `agent/notify.py` (email via `smtplib` + Slack/Teams webhook); `notifications:` block in [agent/config.yaml](agent/config.yaml); wired into `_run()` post-card-build.

- [ ] **Watchlist / follow mode (persistent)**
  - CVE IDs, vendor names, product keywords, MITRE techniques in `config.yaml` or `watchlist.yaml`. Matched findings pinned to top of Top Findings; dismissed via `state/dismissed.json`.
  - Scope: filter pass in `_run()` after card build; `wt.dismissed` `localStorage` key for UI dismiss.

- [ ] **GitHub Advisory Database enrichment**
  - Free public GraphQL, 60 req/hr unauthenticated. For CVE-linked package findings, provides affected ecosystem + package name + vulnerable version ranges.
  - Adds `affected_packages: [{ecosystem, package, vulnerable_ranges}]` to enrichment. Renders in "Extracted context" block. Useful for supply-chain domain findings.
  - Scope: `_enrich_ghsa(cards)` in [agent/ingest.py](agent/ingest.py); `state/ghsa_cache.json` (TTL 24h).

- [ ] **Feed geographic distribution**
  - Feeds carry `country` metadata but it's never aggregated. A `US 45% | EU 30% | APAC 15%` bar in the Feeds/Metrics panel identifies coverage blind spots.
  - Scope: aggregate by `source_country` in `run_metrics` dict in [agent/runner.py](agent/runner.py); small bar HTML in `run_metrics_html`.

- [ ] **Groq token budget display**
  - Estimate prompt token count before each Groq call (~4 chars/token). Show in Feeds/Metrics bar. Flag `⚠ Near limit` when > 80% of model context window.
  - Scope: `_estimate_tokens(payload)` in [agent/analysis.py](agent/analysis.py); `groq_token_est` in `run_metrics`; chip in `run_metrics_html`.

- [ ] **Print-friendly briefing view**
  - `@media print` CSS: hide rail, search bar, navigation; expand all `<details>`; single-column layout. Zero runtime cost; enables PDF sharing.
  - Scope: CSS block in [agent/html_builder.py](agent/html_builder.py).

- [ ] **Rendering.py coverage (14%)**
  - Lowest-covered module, handles the Markdown report output path. Add smoke tests for `render_briefing_md()` and `render_latest_md()`.
  - Scope: `tests/test_rendering.py`.

---

## Completed

| Item | Notes |
|------|-------|
| DST-safe ET handling | `America/New_York` conversion in state/rendering |
| Deterministic seen-hash retention | Timestamped map schema, deterministic pruning |
| Harden private host validation | `ipaddress`-based CIDR checks + localhost blocking |
| Modularize `runner.py` | Split into ingest, analysis, scoring, rendering, state, html_builder |
| Resolve planner direction | Static planner indirection removed from runtime |
| Align mode defaults | README and runtime config match |
| Initial coverage gate | >22% gate passing; planner tests added |
| Structured run metrics | Feed reliability, model failures, parse failures |
| Schema validation | Pre-write artifact validation |
| Feed health scoring | Auto-disable/retry policy for noisy sources |
| Velocity / acceleration signal | `_compute_velocity()`, ↑↑/↑/↓ chips, constellation glow |
| MITRE ATT&CK mapping | `tactic_name` + `technique_name` per finding; 14-button filter strip; Groq prompt v2 |
| AI Threat domain tag | 30 signals; priority-first classifier; constellation node |
| Tactic contract enforcement | `_normalize_tactic()` with alias map + prefix fallback |
| Kill-chain coverage bar | 14-pip coverage bar (Python-rendered) |
| Finding shelf life | `finding_shelf.json`; +5/run boost (capped +20); orange `Nd` badge |
| Split runner.py HTML rendering | `html_builder.py` extracted; runner shrunk from ~3 200 to ~1 760 lines |
| CVE-anchored deduplication | `_merge_by_cve()` union-find grouping before Groq |
| Groq retry with backoff | 5-attempt loop with `Retry-After` header reads *(model fallback still pending)* |
| Forensics tab | CVE Reference Index, Kill-Chain Breakdown, Affected Products, IOC Intelligence |
| IOC extraction redesign | Context snippets only in HTML; raw values in `ioc_ledger.json` |
| Attribution language guard | `_ATTRIBUTION_RE`; `attribution_flag` on cards; `⚠ Attribution Unverified` badge |
| CVE NVD links | Forensics CVE Reference Index links to `nvd.nist.gov` |
| Memory/bootstrap | `bootstrap_seen_from_reports()` reconstructs dedup state on fresh clone |
| Selected Domain panel enrichment | Risk chip, P1 badge, summary snippet, source links per finding |
| Removed 14-day heatmap | Replaced by 7-Day History accordion with richer data |
| Patch status badge | "Status Unknown" suppressed; badge only for patched/workaround/no_fix |
| Extend CARDS JS object | Added `tactic`, `shelf_days`, `run_count`, `first_seen_ts`, `actions_24h` to every card in `CARDS`; `first_seen_ts` set in `_update_shelf()` |
| CISA KEV explicit card badge | `is_kev: bool` derived via CVE-set intersection in `_findings_to_cards()`; red `CISA KEV` chip rendered before priority pill; 4 targeted tests |

---

## Change Log

- 2026-03-12: Tracker created from project review recommendations.
- 2026-03-12: Implemented modular split into `ingest.py`, `analysis.py`, `scoring.py`, `rendering.py`, and `state.py`; production runner wired to split modules.
- 2026-03-12: Re-reviewed remaining items; corrected planner status to open; added ordered execution plan.
- 2026-03-12: Removed static planner indirection from runtime path.
- 2026-03-12: DST-safe ET conversion; deterministic seen-hash retention; hardened private-host validation; aligned config defaults; recovered coverage gate (23.35%).
- 2026-03-12: Structured run metrics, schema validation, feed health tracking, CVE badges, search/filter bar.
- 2026-03-12: Velocity/acceleration signal, `ai_threat` domain, MITRE ATT&CK tactic chips + filter strip. 151 tests, 31% coverage.
- 2026-03-12: `_normalize_tactic()`, kill-chain coverage bar, `_update_shelf()` with scoring boost and shelf badge.
- 2026-03-12: Extracted `html_builder.py`; added `_merge_by_cve()` union-find. All tests pass, 40% coverage.
- 2026-03-12: Forensics tab (CVE index, kill-chain, affected products, IOC intelligence). 290 tests, 40% coverage.
- 2026-03-12: IOC redesign — context snippets only in HTML; raw values in `ioc_ledger.json`.
- 2026-03-12: Attribution language guard; CVE NVD links; memory/bootstrap; Selected Domain panel enrichment; removed 14-day heatmap; patch status badge cleanup. 290 tests, 39% coverage.
- 2026-03-13: **CISA KEV badge** — `is_kev: bool` derived in `_findings_to_cards()` via CVE-set intersection against KEV source items; red `CISA KEV` chip rendered in card header before priority pill; `.kev-badge` CSS added; 4 parameterized tests. 294 tests pass.
- 2026-03-13: **CARDS JS object extended** — added `tactic`, `shelf_days`, `run_count`, `first_seen_ts`, `actions_24h` to every entry. `first_seen_ts` (date string) now set on card in `_update_shelf()`; `card_data` builder updated in `html_builder.py`. 290 tests pass.
- 2026-03-13: Full codebase review. Restructured tracker: dropped phase numbering, reorganized all pending items by impact × simplicity. Added 15 new items (CARDS JS enrichment, Alerts tab, CISA KEV badge, Priority Actions panel, staleness warning, corroboration badge, dead feed detection, node count labels, GHSA enrichment, geo distribution, token budget, print view, watchlist).
