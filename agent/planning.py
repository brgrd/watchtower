"""Plan dispatcher for Watchtower."""

import sys
import time

from agent.toolbelt import tool_add_feed


def dispatch_plan(
    plan: dict,
    polled: list,
    ignore: dict,
    budgets: dict,
    since_hours: int,
    run_deadline: float,
    feeds_cfg: list,
    poll_feed_fn,
) -> list:
    steps = plan.get("steps", [])
    step_budget = budgets.get("max_agent_steps", 20)

    for i, step in enumerate(steps[:step_budget]):
        if time.monotonic() > run_deadline:
            print("[WARN] Runtime budget reached during plan dispatch.")
            break

        tool = step.get("tool", "")
        args = step.get("args", {})

        if tool == "POLL_FEED":
            feed_id = args.get("feed_id")
            sh = int(args.get("since_hours", since_hours))
            for fcfg in feeds_cfg:
                if fcfg.get("id") == feed_id and fcfg.get("enabled"):
                    extra = poll_feed_fn(fcfg, sh, ignore)
                    polled.extend(extra)
                    print(f"[POLL_FEED] {feed_id}: +{len(extra)} items")
                    break

        elif tool == "ADD_FEED":
            ok, reason = tool_add_feed(
                url=args.get("url", ""),
                category=args.get("category", "osint"),
                feeds_cfg=feeds_cfg,
                max_new=budgets.get("max_new_feeds", 3),
            )
            print(f"[ADD_FEED] {'OK' if ok else 'SKIP'}: {reason}")
            if ok:
                extra = poll_feed_fn(feeds_cfg[-1], since_hours, ignore)
                polled.extend(extra)

        elif tool in ("CLUSTER", "SELECT_SOURCES"):
            pass

        else:
            print(
                f"[WARN] Unknown plan tool '{tool}' at step {i} — skipped",
                file=sys.stderr,
            )

    return polled
