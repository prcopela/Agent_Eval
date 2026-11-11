"""The control layer: evaluates policies at every checkpoint and enforces the result.

Decision combination ("most restrictive wins")::

    DENY  >  REQUIRE_APPROVAL  >  MODIFY  >  ALLOW

* Policies run in order. A MODIFY rewrites the action that later policies see
  (so a redaction is visible to every subsequent check).
* The first DENY short-circuits evaluation.
* REQUIRE_APPROVAL is resolved by the configured *approver* once all policies
  have run. Approvers fail closed: no approver means "deny".
* ``mode="monitor"`` evaluates and audits everything but enforces nothing -
  use it to shadow-test a new policy set against live traffic.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .audit import AuditLog
from .policy import Policy
from .tools import Tool, as_tools
from .types import Action, Checkpoint, Decision, PolicyViolation, SessionState, Verdict

Approver = Callable[[Action, list[Decision]], bool]


def deny_all(action: Action, decisions: list[Decision]) -> bool:
    return False


def approve_all(action: Action, decisions: list[Decision]) -> bool:
    return True


def console_approver(action: Action, decisions: list[Decision]) -> bool:
    reasons = "; ".join(d.reason for d in decisions if d.verdict == Verdict.REQUIRE_APPROVAL)
    answer = input(f"\n[APPROVAL NEEDED] {action.tool}({action.args})\n  why: {reasons}\n  approve? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


@dataclass
class Outcome:
    original: Action
    action: Action  # effective action after modifications
    verdict: Verdict  # final, after approval resolution
    decisions: list[Decision]
    approval_requested: bool = False
    approved: bool | None = None
    enforced: bool = True

    @property
    def allowed(self) -> bool:
        return not self.enforced or self.verdict in (Verdict.ALLOW, Verdict.MODIFY)

    @property
    def would_block(self) -> bool:
        return self.verdict == Verdict.DENY

    @property
    def reasons(self) -> list[str]:
        return [f"{d.policy}: {d.reason}" for d in self.decisions if d.verdict != Verdict.ALLOW]

    def summary(self) -> str:
        what = self.original.tool or self.original.checkpoint.value
        return f"{self.verdict.value.upper()} {what}" + (f" - {'; '.join(self.reasons)}" if self.reasons else "")


class BlockedResult(str):
    """Returned by a guarded tool instead of raising (``on_deny='return'``).

    It *is* a string, so naive agents can treat it as an ordinary tool result,
    while adapters can ``isinstance``-check it to report an error to the model.
    """

    outcome: Outcome

    def __new__(cls, outcome: Outcome) -> "BlockedResult":
        obj = super().__new__(cls, f"[BLOCKED BY GOVERNANCE] {'; '.join(outcome.reasons) or 'denied'}")
        obj.outcome = outcome
        return obj


@dataclass
class ToolEvent:
    tool: str
    args: dict[str, Any]
    outcome: Outcome
    executed: bool
    result: Any = None
    error: str | None = None


class ControlLayer:
    """Configuration + policies shared by many agent sessions."""

    def __init__(self, policies: Iterable[Policy] = (), *, mode: str = "enforce",
                 approver: Approver | None = None, audit: AuditLog | None = None,
                 tool_tags: dict[str, list[str]] | None = None):
        if mode not in {"enforce", "monitor"}:
            raise ValueError("mode must be 'enforce' or 'monitor'")
        self.policies = list(policies)
        self.mode = mode
        self.approver = approver or deny_all
        self.audit = audit if audit is not None else AuditLog()
        self.tool_tags = tool_tags or {}

    @classmethod
    def from_config(cls, path_or_dict: Any, **overrides: Any) -> "ControlLayer":
        from .config import load_config

        return load_config(path_or_dict, **overrides)

    def session(self, agent_id: str = "agent", approver: Approver | None = None) -> "Session":
        return Session(self, SessionState(agent_id=agent_id), approver or self.approver)

    def govern(self, agent: Any, agent_id: str | None = None) -> "GovernedAgent":
        from .runner import GovernedAgent

        return GovernedAgent(agent, self, agent_id=agent_id)


class Session:
    """One governed agent run. Holds the state that stateful policies need."""

    def __init__(self, layer: ControlLayer, state: SessionState, approver: Approver):
        self.layer = layer
        self.state = state
        self.approver = approver
        self.events: list[ToolEvent] = []
        self.outcomes: list[Outcome] = []

    # -- core ------------------------------------------------------------------
    def check(self, action: Action) -> Outcome:
        self.state.steps += 1
        current = action
        decisions: list[Decision] = []
        for policy in self.layer.policies:
            if not policy.applies_to(current):
                continue
            d = policy.evaluate(current, self.state)
            if d is None:
                continue
            decisions.append(d)
            if d.verdict == Verdict.MODIFY and d.modified is not None:
                current = d.modified
            if d.verdict == Verdict.DENY:
                break

        worst = max((d.verdict for d in decisions), key=lambda v: v.severity, default=Verdict.ALLOW)
        outcome = Outcome(original=action, action=current, verdict=worst, decisions=decisions,
                          enforced=self.layer.mode == "enforce")

        if worst == Verdict.REQUIRE_APPROVAL:
            outcome.approval_requested = True
            if outcome.enforced:
                try:
                    outcome.approved = bool(self.approver(current, decisions))
                except Exception:  # an approver failure must never fail open
                    outcome.approved = False
                outcome.verdict = Verdict.ALLOW if outcome.approved else Verdict.DENY

        if not outcome.enforced:  # monitor mode: observe only, never rewrite
            outcome.action = action

        self.outcomes.append(outcome)
        self.layer.audit.record(
            session_id=self.state.session_id,
            agent_id=self.state.agent_id,
            mode=self.layer.mode,
            action=action.to_dict(),
            decisions=[d.to_dict() for d in decisions],
            verdict=outcome.verdict.value,
            approval_requested=outcome.approval_requested,
            approved=outcome.approved,
        )
        return outcome

    # -- convenience checkpoints ----------------------------------------------
    def check_input(self, text: str) -> Outcome:
        return self.check(Action(Checkpoint.INPUT, content=text))

    def check_output(self, text: str) -> Outcome:
        return self.check(Action(Checkpoint.OUTPUT, content=text))

    def call_tool(self, tool: Tool, args: dict[str, Any], on_deny: str = "return") -> Any:
        """Run one tool call through the full TOOL_CALL -> execute -> TOOL_RESULT pipeline."""
        call = Action(Checkpoint.TOOL_CALL, tool=tool.name, args=dict(args), tags=tool.tags)
        outcome = self.check(call)
        if not outcome.allowed:
            self.events.append(ToolEvent(tool.name, dict(args), outcome, executed=False))
            if on_deny == "raise":
                raise PolicyViolation(outcome)
            return BlockedResult(outcome)

        eff_args = outcome.action.args
        event = ToolEvent(tool.name, eff_args, outcome, executed=True)
        self.events.append(event)
        self.state.tool_calls.append((tool.name, eff_args, time.time()))
        for p in self.layer.policies:
            p.on_executed(outcome.action, self.state)
        try:
            result = tool.fn(**eff_args)
        except Exception as exc:
            event.error = f"{type(exc).__name__}: {exc}"
            raise

        res_outcome = self.check(Action(Checkpoint.TOOL_RESULT, tool=tool.name, args=eff_args,
                                        content=_to_text(result), tags=tool.tags))
        if not res_outcome.allowed:
            event.result = BlockedResult(res_outcome)
            return event.result
        if res_outcome.action.content != _to_text(result):
            result = res_outcome.action.content  # redacted / annotated
        event.result = result
        return result

    def wrap(self, tools: Any, on_deny: str = "return") -> dict[str, Tool]:
        """Return guarded copies of ``tools``. Hand these to *any* agent framework."""
        guarded: dict[str, Tool] = {}
        def make(t: Tool) -> Callable[..., Any]:
            def fn(**kwargs: Any) -> Any:
                return self.call_tool(t, kwargs, on_deny=on_deny)

            return fn

        for name, t in as_tools(tools, self.layer.tool_tags).items():
            guarded[name] = Tool(t.name, make(t), t.description, t.tags, t.schema())
        return guarded

    # -- reporting ---------------------------------------------------------------
    @property
    def interventions(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.verdict != Verdict.ALLOW or o.approval_requested]


def _to_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    import json

    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return str(result)
