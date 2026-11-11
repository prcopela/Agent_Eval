"""Wrap any agent with the control layer.

The only contract an agent must satisfy is :class:`Agent`::

    def run(self, task: str, tools: dict[str, Tool]) -> str

That covers hand-written loops, LLM SDK loops, and most frameworks (wrap the
framework's entry point in a 5-line class). The control layer then governs:

* the task on the way in        (INPUT)
* every tool call and result    (TOOL_CALL / TOOL_RESULT) via guarded tools
* the answer on the way out     (OUTPUT)

If you cannot route tools through the layer (e.g. a hosted agent), call
``session.check(...)`` directly from your framework's callback/hook system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .engine import ControlLayer, Outcome, Session, ToolEvent
from .types import PolicyViolation


@runtime_checkable
class Agent(Protocol):
    def run(self, task: str, tools: dict[str, Any]) -> str: ...


@dataclass
class RunResult:
    output: str
    raw_output: str | None
    blocked: bool  # True if input or output was blocked outright
    session: Session
    error: str | None = None
    tool_events: list[ToolEvent] = field(default_factory=list)

    @property
    def interventions(self) -> list[Outcome]:
        return self.session.interventions

    def executed(self, tool: str) -> bool:
        return any(e.executed and e.tool == tool for e in self.tool_events)

    def attempted(self, tool: str) -> bool:
        return any(e.tool == tool for e in self.tool_events)

    def blocked_tool(self, tool: str) -> bool:
        return any(e.tool == tool and not e.executed for e in self.tool_events)


BLOCKED_INPUT_MESSAGE = "I can't help with that request."
BLOCKED_OUTPUT_MESSAGE = "The response was withheld by policy."


class GovernedAgent:
    def __init__(self, agent: Agent, layer: ControlLayer, agent_id: str | None = None):
        self.agent = agent
        self.layer = layer
        self.agent_id = agent_id or getattr(agent, "name", type(agent).__name__)

    def run(self, task: str, tools: Any, approver: Any = None) -> RunResult:
        session = self.layer.session(self.agent_id, approver=approver)

        inp = session.check_input(task)
        if not inp.allowed:
            return RunResult(BLOCKED_INPUT_MESSAGE, None, True, session)
        task = inp.action.content or task

        guarded = session.wrap(tools)
        error = None
        try:
            raw = self.agent.run(task, guarded)
        except PolicyViolation as exc:
            raw, error = "", f"PolicyViolation: {exc}"
        except Exception as exc:  # the agent crashed; still governed + audited
            raw, error = "", f"{type(exc).__name__}: {exc}"

        out = session.check_output(raw or "")
        if not out.allowed:
            return RunResult(BLOCKED_OUTPUT_MESSAGE, raw, True, session, error, session.events)
        return RunResult(out.action.content or "", raw, False, session, error, session.events)
