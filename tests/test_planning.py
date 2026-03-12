"""Unit tests for planner dispatch behavior."""

import time

import pytest

from agent.planning import dispatch_plan

pytestmark = pytest.mark.unit


def test_dispatch_poll_feed_adds_items():
    polled = []
    ignore = {}
    budgets = {"max_agent_steps": 5}
    feeds_cfg = [{"id": "nvd", "enabled": True}]

    def poll_feed_fn(fcfg, since_hours, _ignore):
        assert fcfg["id"] == "nvd"
        assert since_hours == 12
        return [{"title": "x"}]

    out = dispatch_plan(
        plan={
            "steps": [
                {"tool": "POLL_FEED", "args": {"feed_id": "nvd", "since_hours": 12}}
            ]
        },
        polled=polled,
        ignore=ignore,
        budgets=budgets,
        since_hours=6,
        run_deadline=time.monotonic() + 10,
        feeds_cfg=feeds_cfg,
        poll_feed_fn=poll_feed_fn,
    )

    assert len(out) == 1


def test_dispatch_add_feed_ok_polls_new_feed(monkeypatch):
    polled = []
    ignore = {}
    budgets = {"max_agent_steps": 5, "max_new_feeds": 3}
    feeds_cfg = [{"id": "base", "enabled": True}]

    def fake_tool_add_feed(url, category, feeds_cfg, max_new):
        feeds_cfg.append(
            {"id": "dynamic_1", "enabled": True, "url": url, "category": category}
        )
        return True, "Feed added"

    monkeypatch.setattr("agent.planning.tool_add_feed", fake_tool_add_feed)

    calls = {"count": 0}

    def poll_feed_fn(fcfg, since_hours, _ignore):
        calls["count"] += 1
        assert fcfg["id"] == "dynamic_1"
        assert since_hours == 6
        return [{"title": "new"}]

    out = dispatch_plan(
        plan={
            "steps": [
                {
                    "tool": "ADD_FEED",
                    "args": {"url": "https://example.com/feed", "category": "osint"},
                }
            ]
        },
        polled=polled,
        ignore=ignore,
        budgets=budgets,
        since_hours=6,
        run_deadline=time.monotonic() + 10,
        feeds_cfg=feeds_cfg,
        poll_feed_fn=poll_feed_fn,
    )

    assert calls["count"] == 1
    assert len(out) == 1


def test_dispatch_add_feed_skip_does_not_poll(monkeypatch):
    monkeypatch.setattr(
        "agent.planning.tool_add_feed", lambda **kwargs: (False, "skip")
    )

    def poll_feed_fn(*_args, **_kwargs):
        raise AssertionError("poll_feed_fn should not be called when add feed fails")

    out = dispatch_plan(
        plan={
            "steps": [{"tool": "ADD_FEED", "args": {"url": "https://example.com/feed"}}]
        },
        polled=[],
        ignore={},
        budgets={"max_agent_steps": 5, "max_new_feeds": 0},
        since_hours=6,
        run_deadline=time.monotonic() + 10,
        feeds_cfg=[],
        poll_feed_fn=poll_feed_fn,
    )

    assert out == []


def test_dispatch_ignores_unknown_tool():
    out = dispatch_plan(
        plan={"steps": [{"tool": "UNKNOWN_TOOL", "args": {}}]},
        polled=[],
        ignore={},
        budgets={"max_agent_steps": 5},
        since_hours=6,
        run_deadline=time.monotonic() + 10,
        feeds_cfg=[],
        poll_feed_fn=lambda *_args: [],
    )
    assert out == []


def test_dispatch_respects_runtime_deadline():
    out = dispatch_plan(
        plan={"steps": [{"tool": "POLL_FEED", "args": {"feed_id": "nvd"}}]},
        polled=[],
        ignore={},
        budgets={"max_agent_steps": 5},
        since_hours=6,
        run_deadline=time.monotonic() - 1,
        feeds_cfg=[{"id": "nvd", "enabled": True}],
        poll_feed_fn=lambda *_args: [{"title": "never"}],
    )
    assert out == []


def test_dispatch_respects_step_budget():
    calls = {"count": 0}

    def poll_feed_fn(_fcfg, _since_hours, _ignore):
        calls["count"] += 1
        return [{"title": "item"}]

    out = dispatch_plan(
        plan={
            "steps": [
                {"tool": "POLL_FEED", "args": {"feed_id": "nvd"}},
                {"tool": "POLL_FEED", "args": {"feed_id": "nvd"}},
            ]
        },
        polled=[],
        ignore={},
        budgets={"max_agent_steps": 1},
        since_hours=6,
        run_deadline=time.monotonic() + 10,
        feeds_cfg=[{"id": "nvd", "enabled": True}],
        poll_feed_fn=poll_feed_fn,
    )
    assert calls["count"] == 1
    assert len(out) == 1
