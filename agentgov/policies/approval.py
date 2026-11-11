"""Human-in-the-loop gates for high-impact actions."""

from __future__ import annotations

from typing import Any

from ..policy import Policy, matches_any, register_policy, tool_selected
from ..types import Action, Checkpoint, Decision, SessionState

_OPS = {
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: a in b,
}


@register_policy("approval")
class ApprovalPolicy(Policy):
    """Require approval for selected tools.

    * ``tools`` / ``tags``: always require approval for matching tools.
    * ``conditions``: require approval only when an argument condition holds,
      e.g. ``{"issue_refund": {"amount": {"gt": 100}}}``.
    """

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def __init__(self, tools: list[str] | None = None, tags: list[str] | None = None,
                 conditions: dict[str, dict[str, dict[str, Any]]] | None = None, **kw: Any):
        super().__init__(**kw)
        self.tools = tools or []
        self.tags = tags or []
        self.conditions = conditions or {}

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:
        if tool_selected(action, self.tools, self.tags):
            return self.require_approval(f"'{action.tool}' always requires human approval")
        for pattern, arg_conds in self.conditions.items():
            if not matches_any(action.tool, [pattern]):
                continue
            for arg, ops in arg_conds.items():
                if arg not in action.args:
                    continue
                for op, threshold in ops.items():
                    try:
                        hit = _OPS[op](_num(action.args[arg]), threshold)
                    except (TypeError, ValueError):
                        hit = True  # un-evaluable -> fail closed
                    if hit:
                        return self.require_approval(
                            f"{action.tool}.{arg}={action.args[arg]!r} meets approval condition {op} {threshold}")
        return None


def _num(v: Any) -> Any:
    if isinstance(v, (int, float)):
        return v
    try:
        return float(v)
    except (TypeError, ValueError):
        return v
