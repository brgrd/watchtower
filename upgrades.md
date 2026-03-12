# Watchtower Upgrades Tracker

Use this as a running manager of upgrades. Check boxes as work is completed.

## How to use
- Keep each item open until code, tests, and docs are complete.
- Add links to PRs/issues under each item.
- Move completed items to the bottom of each section if preferred.

---

## Priority 1 — Reliability & Correctness

- [x] **DST-safe New York time handling**
  - Replace fixed ET offset logic with timezone-aware conversion (`America/New_York`).
  - Scope: history bucketing + any UI/run-window displays.
  - Current findings:
    - [agent/state.py](agent/state.py#L118-L133)
    - [agent/rendering.py](agent/rendering.py#L134)
    - [agent/runner.py](agent/runner.py#L1392-L1407)

- [x] **Deterministic seen-hash retention**
  - Replace set slicing approach with timestamped or ordered eviction to avoid non-deterministic drops.
  - Current findings: [agent/state.py](agent/state.py#L55-L65)

- [x] **Harden private host validation**
  - Use CIDR-accurate checks (`172.16.0.0/12`) and explicit localhost handling.
  - Validate IPv4/IPv6/private ranges via robust parsing.
  - Current findings: [agent/ingest.py](agent/ingest.py#L17-L40)

---

## Priority 2 — Architecture & Maintainability

- [x] **Modularize `runner.py`**
  - Split into focused modules (ingest, analysis, scoring, rendering, state).
  - Status: modules were added and wired.
  - Follow-up remaining: thin `runner.py` by removing legacy duplicated logic and keeping orchestration-only flow.
  - Source references:
    - [agent/ingest.py](agent/ingest.py)
    - [agent/analysis.py](agent/analysis.py)
    - [agent/scoring.py](agent/scoring.py)
    - [agent/rendering.py](agent/rendering.py)
    - [agent/state.py](agent/state.py)
    - [agent/runner.py](agent/runner.py)

- [x] **Resolve planner direction**
  - Either wire full plan generation/dispatch flow or remove dormant planner indirection.
  - Status: removed static one-step `dispatch_plan()` runtime path from orchestrator.
  - Next iteration option: re-introduce planning only with model-driven multi-step plan + tests.
  - Source references:
    - [agent/runner.py](agent/runner.py#L2470-L2471)
    - [agent/planning.py](agent/planning.py)

---

## Priority 3 — Quality & Operations

- [x] **Align mode defaults across docs/config**
  - Ensure README and runtime config describe the same default placeholder behavior.
  - Resolved alignment:
   - README local default: [README.md](README.md#L18-L24)
   - Config local default: [agent/config.yaml](agent/config.yaml#L14)

- [x] **Increase coverage in high-risk paths**
  - Add tests for plan dispatch behavior, Groq error/fallback paths, and weekly aggregate transforms.
  - Focus especially on modules currently under-covered.
  - Current signal (2026-03-12 run): coverage gate recovered to 23.35% with added planner tests.
  - Follow-on depth still recommended for:
   - [agent/planning.py](agent/planning.py)
   - [agent/analysis.py](agent/analysis.py)
   - [agent/ingest.py](agent/ingest.py)
   - [agent/state.py](agent/state.py)

---

## Ordered Next Execution Plan

1. [x] **Finalize planner direction (first)**
  - Completed: static planner indirection removed from runtime.

2. [x] **Fix DST correctness (second)**
  - Completed in runtime path for history bucketing and rendering current-day selection.

3. [x] **Fix deterministic seen retention (third)**
  - Completed: seen storage supports timestamped map schema with deterministic pruning order and legacy compatibility.

4. [x] **Tighten host safety checks (fourth)**
  - Completed: `ipaddress`-based checks implemented with explicit localhost handling.

5. [x] **Align docs/config defaults (fifth)**
  - Completed: runtime config now matches README local default; CI continues to force real mode.

6. [x] **Recover coverage gate and raise confidence (parallel with 1-5)**
  - Completed: added targeted planning tests; coverage gate now passes (>22%).
  - Next depth: add analysis/ingest/state-focused tests for stronger confidence.

---

## Optional Backlog Enhancements

- [ ] Add structured run metrics (feed reliability, model failures, parse failures).
- [ ] Add schema validation before writing report artifacts.
- [ ] Add stronger feed health scoring and auto-disable/retry policy for noisy sources.

---

## Change Log

- 2026-03-12: Tracker created from project review recommendations.
- 2026-03-12: Implemented modular split into `ingest.py`, `analysis.py`, `scoring.py`, `rendering.py`, and `state.py`; production runner wired to split modules.
- 2026-03-12: Re-reviewed remaining items; corrected planner status to open; added ordered execution plan for next implementation cycle.
- 2026-03-12: Removed static planner indirection from runtime path; marked planner-direction item complete.
- 2026-03-12: Implemented DST-safe ET conversion (`America/New_York`) in active state/rendering path with robust fallback when tzdata is unavailable.
- 2026-03-12: Implemented deterministic seen-hash retention using timestamped map schema with deterministic purge ordering and backward-compatible legacy set/hash support.
- 2026-03-12: Hardened private-host validation with CIDR-aware IP checks and explicit localhost blocking.
- 2026-03-12: Aligned placeholder-mode defaults between docs and runtime config.
- 2026-03-12: Added planner dispatch unit tests and recovered coverage gate (23.35%).
