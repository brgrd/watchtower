# Watchtower Upgrades Tracker

Prioritized by **impact × simplicity**. Free-tier architecture only (GitHub Actions, Groq free, public APIs).

Keep each item open until code, tests, and docs are complete.

---

## Pending

### High Priority

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

- [ ] **"Since your last visit" catch-up view**
  - After > 4 hours away, render a collapsible `<details>` strip at top: "Catch-up since [timestamp] — N new findings". Closes the passive-monitor check-in friction problem at zero backend cost.
  - Requires `first_seen_ts` in CARDS (already present).
  - Scope: JS-only in [agent/html_builder.py](agent/html_builder.py); sets `wt.last_visit` on DOMContentLoaded.

- [ ] **Shelf life CVE key**
  - Shelf keys are `sha256(title)[:16]`. Two articles about the same CVE get separate shelf entries, diluting persistence signals.
  - Use the primary CVE ID as shelf key (`"cve:CVE-2026-XXXXX"`) when extractable; fall back to title hash.
  - Scope: `_update_shelf()` in [agent/runner.py](agent/runner.py) — 5-line change using `_extract_cves()` already available.

- [ ] **Shelf life decay and resolved-finding suppression**
  - Shelf boosts scores indefinitely (up to +20) and never downgrades. A patched CVE still accumulates persistence boost across subsequent runs.
  - Add `resolved` flag when `patch_status == "patched"`: zero the boost, change badge to grey `Nd (resolved)`. Prune shelf entry 7 days post-resolution.
  - Scope: `_update_shelf()` in [agent/runner.py](agent/runner.py); `.shelf-badge--resolved` CSS variant in [agent/html_builder.py](agent/html_builder.py).

- [ ] **KPI P1 delta and exploited delta**
  - "Trend 24h" shows overall ±N count change — too coarse. A flat overall count with 3 new P1s is a different situation.
  - Add `+N ↑` / `−N ↓` sub-labels under the P1 and Exploited KPI tiles, computed from `delta["new"]` / `delta["elevated"]` filtered by priority/exploited flag.
  - Scope: `_write_index_html` in [agent/html_builder.py](agent/html_builder.py); `delta` dict is already an argument.

- [ ] **Dead feed detection**
  - `feed_health.json` tracks HTTP success/failure but a feed returning HTTP 200 with 0 new items is indistinguishable from healthy. Stale feeds silently narrow coverage.
  - Track `last_item_ts` per feed. Flag feeds where `last_item_ts` is > 72h ago with a "Stale" badge in the Feeds tab. Separate from "failed" coloring.
  - Scope: `_update_feed_health()` in [agent/runner.py](agent/runner.py); stale badge CSS in [agent/html_builder.py](agent/html_builder.py).

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

- [ ] **Stack keyword filter**
  - Any visitor can type stack terms (product names, CVE IDs, tech keywords) into a filter input; matching cards are highlighted and pulled to the top of Top Findings. Terms persist in `localStorage` between visits — no account or login needed.
  - URL param `?filter=kubernetes,nginx` pre-applies on load for shareable/bookmarkable filtered views.
  - Scope: JS + CSS in [agent/html_builder.py](agent/html_builder.py); zero backend.

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
| EPSS exploitation probability badge | `_enrich_epss()` in `ingest.py`; batched FIRST.org API; 24h cache in `state/epss_cache.json`; orange `EPSS XX%` chip for ≥ 0.4; wired into `_run()`; 5 targeted tests |
| Corroboration count badge | `cve_to_source_count` map in `_findings_to_cards()`; `N sources` blue chip for ≥ 2; 4 targeted tests |
| Constellation node count labels | `cnts` dict in `_build_threat_map_svg()`; `<text>` count label inside each node disc; "9+" for counts > 9 |
| Alerts tab | Three panels: Persistent (run_count ≥ 3), Elevated (delta ≥ 10), P1/Attribution; click-to-scroll to finding card; 10 targeted tests |
| Adaptive data window + 2x/day cadence | `last_run_ts.json` tracks last poll; `since_hours` expands to cover any gap; pre-Groq cap 120 items newest-first; gate changed to 06:00/18:00 ET; `since_hours: 12`; `window_h` chip in Run Metrics bar |
| Priority Actions aggregation panel | `_build_priority_actions_html(cards)` — deduplicates `recommended_actions_24h` across P1/P2 cards via Counter; top 7 shown with `N×` chip; rendered between hp-panel and threat map; 6 targeted tests |

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
- 2026-03-13: **EPSS badge + Corroboration badge + Constellation node counts** — `_enrich_epss()` in `ingest.py` with batched FIRST.org API and 24h cache; `cve_to_source_count` map in `_findings_to_cards()` for corroboration; `cnts` dict + `<text>` label in constellation SVG; all three wired and rendered; 9 new targeted tests (303 total).
- 2026-03-17: Cleaned up tracker: removed completed items from Pending; cut push alerts, watchlist/follow, GHSA enrichment, feed geo distribution, and Groq token budget display; replaced client-side watchlist + follow mode with unified Stack keyword filter (no login required, localStorage + URL param).
- 2026-03-17: **Alerts tab** — `_build_alerts_html(cards, delta)` in `html_builder.py`; three panels (Persistent, Elevated, P1/Attribution); click-to-scroll JS with highlight; 10 targeted tests (307 total). Dead code removed: `rendering.py`, `planning.py`, `test_planning.py`, `_build_calendar_html`, `_build_corroboration_map`, dead `rendering_mod` import.
- 2026-03-17: **Adaptive data window** — `last_run_ts.json` checkpoint; `since_hours = max(config, gap+2)` auto-expands for missed runs and weekend gaps; pre-Groq 120-item cap (newest-first); schedule changed to 2x/day (06:00/18:00 ET); `since_hours: 12`; `window_h` chip in Run Metrics bar. 307 tests pass.
- 2026-03-17: **Priority Actions panel** — `_build_priority_actions_html(cards)` deduplicates `recommended_actions_24h` across P1/P2 cards; Counter grouping on first 40 chars; top 7 with `N×` occurrence chip; rendered between hp-panel and threat map. 313 tests pass.
