"""Resource and behavioural limits: budgets, rate limits, loop detection."""

from __future__ import annotations

import json
import time
from typing import Any

from ..policy import Policy, matches_any, register_policy
from ..types import Action, Checkpoint, Decision, SessionState


@register_policy("budget")
class BudgetPolicy(Policy):
    """Caps on how much work one agent run may do.

    ``tool_costs`` maps tool-name globs to a unit cost (dollars, credits,
    tokens - whatever you meter). The call that would exceed ``max_cost`` is denied.
    """

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def __init__(self, max_tool_calls: int | None = None, max_cost: float | None = None,
                 tool_costs: dict[str, float] | None = None, default_cost: float = 0.0,
                 max_duration_s: float | None = None, **kw: Any):
        super().__init__(**kw)
        self.max_tool_calls = max_tool_calls
        self.max_cost = max_cost
        self.tool_costs = tool_costs or {}
        self.default_cost = default_cost
        self.max_duration_s = max_duration_s

    def cost_of(self, tool: str | None) -> float:
        for pattern, cost in self.tool_costs.items():
            if matches_any(tool, [pattern]):
                return float(cost)
        return self.default_cost

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:
        if self.max_tool_calls is not None and len(state.tool_calls) >= self.max_tool_calls:
            return self.deny(f"tool-call budget exhausted ({self.max_tool_calls})")
        if self.max_cost is not None and state.cost + self.cost_of(action.tool) > self.max_cost:
            return self.deny(f"cost budget exceeded ({state.cost:.2f} + {self.cost_of(action.tool):.2f} > {self.max_cost})")
        if self.max_duration_s is not None and time.time() - state.started_at > self.max_duration_s:
            return self.deny(f"run exceeded max duration of {self.max_duration_s}s")
        return None

    def on_executed(self, action: Action, state: SessionState) -> None:
        state.cost += self.cost_of(action.tool)


@register_policy("rate_limit")
class RateLimitPolicy(Policy):
    """``limits: {send_email: {max_calls: 3, per_seconds: 60}}``"""

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def __init__(self, limits: dict[str, dict[str, float]], **kw: Any):
        super().__init__(**kw)
        self.limits = limits

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:
        now = time.time()
        for pattern, lim in self.limits.items():
            if not matches_any(action.tool, [pattern]):
                continue
            window = float(lim.get("per_seconds", 60))
            recent = [t for (name, _, t) in state.tool_calls
                      if matches_any(name, [pattern]) and now - t <= window]
            if len(recent) >= int(lim["max_calls"]):
                return self.deny(f"rate limit for '{pattern}': {int(lim['max_calls'])} per {window:g}s")
        return None


@register_policy("loop_detection")
class LoopDetectionPolicy(Policy):
    """Stops agents that keep making the same call (a classic runaway failure)."""

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def __init__(self, max_identical_calls: int = 3, max_calls_per_tool: int | None = None, **kw: Any):
        super().__init__(**kw)
        self.max_identical = max_identical_calls
        self.max_per_tool = max_calls_per_tool

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:
        key = _key(action.tool, action.args)
        identical = sum(1 for (n, a, _) in state.tool_calls if _key(n, a) == key)
        if identical >= self.max_identical:
            return self.deny(f"loop detected: identical call to '{action.tool}' made {identical} times")
        if self.max_per_tool is not None:
            same_tool = sum(1 for (n, _, _) in state.tool_calls if n == action.tool)
            if same_tool >= self.max_per_tool:
                return self.deny(f"'{action.tool}' called {same_tool} times (limit {self.max_per_tool})")
        return None


def _key(tool: str | None, args: dict[str, Any]) -> str:
    return f"{tool}:{json.dumps(args, sort_keys=True, default=str)}"
