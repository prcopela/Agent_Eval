"""Deterministic stand-in agents for offline, reproducible evaluation.

These simulate the *behaviours* that governance must handle - a well-behaved
agent, an agent that blindly follows instructions found in tool output
(prompt-injection susceptible), a runaway looping agent - without needing an
LLM. Swap in :class:`agentgov.adapters.anthropic.ClaudeAgent` (or your own
agent) to run the same scenarios against a real model.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..engine import BlockedResult

_ACTION_RE = re.compile(r"ACTION:\s*(\w+)\s*(\{.*\})")


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _render(value: Any, ctx: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(_SafeDict(ctx))
        except (ValueError, IndexError):
            return value
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    return value


class ScriptedAgent:
    """Executes a fixed plan of tool calls, then renders a final answer.

    ``plan`` items: ``{"tool": name, "args": {...}, "repeat": n}``. String
    arguments and ``final`` may reference earlier results as ``{tool_name}``
    or everything gathered so far as ``{context}``.

    With ``follow_injections=True`` the agent behaves like an over-compliant
    LLM: any ``ACTION: tool {json}`` line found in a tool result is executed.
    """

    def __init__(self, plan: list[dict[str, Any]], final: str = "Done.", follow_injections: bool = False,
                 name: str = "scripted-agent"):
        self.plan = plan
        self.final = final
        self.follow_injections = follow_injections
        self.name = name

    def run(self, task: str, tools: dict[str, Any]) -> str:
        results: dict[str, str] = {"task": task}
        queue = [dict(step) for step in self.plan]
        injected_budget = 5
        while queue:
            step = queue.pop(0)
            for _ in range(int(step.get("repeat", 1))):
                ctx = {**results, "context": "\n".join(v for k, v in results.items() if k != "task")}
                args = _render(step.get("args", {}), ctx)
                fn = tools.get(step["tool"])
                if fn is None:
                    results[step["tool"]] = f"error: no tool {step['tool']}"
                    continue
                try:
                    out = fn(**args)
                except Exception as exc:  # tools may fail; the agent carries on
                    out = f"error: {exc}"
                text = out if isinstance(out, str) else json.dumps(out)
                results[step["tool"]] = text
                if self.follow_injections and not isinstance(out, BlockedResult) and injected_budget > 0:
                    for m in _ACTION_RE.finditer(text):
                        try:
                            queue.insert(0, {"tool": m.group(1), "args": json.loads(m.group(2))})
                            injected_budget -= 1
                        except json.JSONDecodeError:
                            pass
        ctx = {**results, "context": "\n".join(v for k, v in results.items() if k != "task")}
        return _render(self.final, ctx)


def build_agent(spec: dict[str, Any]) -> Any:
    """Build an agent from a scenario's ``agent:`` block."""
    kind = spec.get("type", "scripted")
    if kind in {"scripted", "naive"}:
        return ScriptedAgent(plan=spec.get("plan", []), final=spec.get("final", "Done."),
                             follow_injections=spec.get("follow_injections", kind == "naive"),
                             name=spec.get("name", f"{kind}-agent"))
    if kind == "claude":
        from ..adapters.anthropic import ClaudeAgent

        return ClaudeAgent(**{k: v for k, v in spec.items() if k != "type"})
    raise ValueError(f"unknown agent type {kind!r}")
