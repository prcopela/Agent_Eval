"""Core data types shared by every part of the control layer.

The control layer is agent-agnostic: it never looks inside an agent. Instead,
every agent - whatever framework or model it uses - is observed at four
*checkpoints*, and each observation is an :class:`Action`.

    INPUT        a task / user message arrives at the agent
    TOOL_CALL    the agent wants to execute a tool (before it runs)
    TOOL_RESULT  a tool returned data (before the agent sees it)
    OUTPUT       the agent produced a final answer (before the user sees it)

Policies inspect actions and return :class:`Decision` objects.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any


class Checkpoint(str, Enum):
    INPUT = "input"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    OUTPUT = "output"


class Verdict(str, Enum):
    """Policy verdicts, ordered from least to most restrictive."""

    ALLOW = "allow"
    MODIFY = "modify"  # allowed, but the action was rewritten (e.g. redacted)
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {
    Verdict.ALLOW: 0,
    Verdict.MODIFY: 1,
    Verdict.REQUIRE_APPROVAL: 2,
    Verdict.DENY: 3,
}


@dataclass(frozen=True)
class Action:
    """One observable step of an agent."""

    checkpoint: Checkpoint
    tool: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    content: str | None = None  # text for INPUT / TOOL_RESULT / OUTPUT
    tags: frozenset[str] = frozenset()  # tool tags, e.g. {"egress", "destructive"}
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_args(self, args: dict[str, Any]) -> "Action":
        return replace(self, args=args)

    def with_content(self, content: str) -> "Action":
        return replace(self, content=content)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint": self.checkpoint.value,
            "tool": self.tool,
            "args": self.args,
            "content": self.content,
            "tags": sorted(self.tags),
        }


@dataclass
class Decision:
    """A single policy's opinion about an action."""

    verdict: Verdict
    policy: str
    reason: str = ""
    modified: Action | None = None  # set when verdict == MODIFY

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "policy": self.policy, "reason": self.reason}


@dataclass
class SessionState:
    """Mutable per-run state that stateful policies (budgets, loops, taint) read."""

    agent_id: str
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float = field(default_factory=time.time)
    steps: int = 0
    tool_calls: list[tuple[str, dict[str, Any], float]] = field(default_factory=list)
    cost: float = 0.0
    tainted: bool = False  # set when untrusted / injected content entered the context
    taint_reasons: list[str] = field(default_factory=list)
    scratch: dict[str, Any] = field(default_factory=dict)  # free space for custom policies

    def taint(self, reason: str) -> None:
        self.tainted = True
        self.taint_reasons.append(reason)


class PolicyViolation(Exception):
    """Raised by guarded tools (on_deny='raise') when an action is blocked."""

    def __init__(self, outcome: "Any"):
        self.outcome = outcome
        super().__init__(outcome.summary())
