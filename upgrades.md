# Watchtower Upgrades Tracker

Use this as a running manager of upgrades. Check boxes as work is completed.

## How to use
- Keep each item open until code, tests, and docs are complete.
- Add links to PRs/issues under each item.
- Move completed items to the bottom of each section if preferred.

---

## Priority 1 — Reliability & Correctness

- [ ] **DST-safe New York time handling**
  - Replace fixed ET offset logic with timezone-aware conversion (`America/New_York`).
  - Scope: history bucketing + any UI/run-window displays.
  - Source reference: [agent/runner.py](agent/runner.py#L1387-L1402)

- [ ] **Deterministic seen-hash retention**
  - Replace set slicing approach with timestamped or ordered eviction to avoid non-deterministic drops.
  - Source reference: [agent/runner.py](agent/runner.py#L1001-L1008)

- [ ] **Harden private host validation**
  - Use CIDR-accurate checks (`172.16.0.0/12`) and explicit localhost handling.
  - Validate IPv4/IPv6/private ranges via robust parsing.
  - Source reference: [agent/runner.py](agent/runner.py#L114-L130)

---

## Priority 2 — Architecture & Maintainability

- [x] **Modularize `runner.py`**
  - Split into focused modules (ingest, analysis, scoring, rendering, state).
  - Keep orchestration in a thin entrypoint.
  - Source reference: [agent/runner.py](agent/runner.py)

- [x] **Resolve planner direction**
  - Either wire full plan generation/dispatch flow or remove dormant planner indirection.
  - Current static usage should be replaced with real intent.
  - Source reference: [agent/runner.py](agent/runner.py#L2419-L2420), [agent/planning.py](agent/planning.py)

---

## Priority 3 — Quality & Operations

- [ ] **Align mode defaults across docs/config**
  - Ensure README and runtime config describe the same default placeholder behavior.
  - Source reference: [README.md](README.md#L18-L24), [agent/config.yaml](agent/config.yaml#L14)

- [ ] **Increase coverage in high-risk paths**
  - Add tests for plan dispatch behavior, Groq error/fallback paths, and weekly aggregate transforms.
  - Focus especially on modules currently under-covered.
  - Source reference: [agent/planning.py](agent/planning.py), [agent/runner.py](agent/runner.py)

---

## Optional Backlog Enhancements

- [ ] Add structured run metrics (feed reliability, model failures, parse failures).
- [ ] Add schema validation before writing report artifacts.
- [ ] Add stronger feed health scoring and auto-disable/retry policy for noisy sources.

---

## Change Log

- 2026-03-12: Tracker created from project review recommendations.
- 2026-03-12: Implemented modular split into `ingest.py`, `analysis.py`, `scoring.py`, `rendering.py`, and `state.py`; production runner wired to split modules.
