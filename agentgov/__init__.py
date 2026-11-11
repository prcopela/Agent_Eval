"""agentgov - a generalized governance / control layer for AI agents.

Quick start::

    from agentgov import ControlLayer
    layer = ControlLayer.from_config("policies/support_agent.yaml")
    result = layer.govern(my_agent).run("Refund order A-200", my_tools)
"""

from . import policies  # noqa: F401  (registers built-in policies)
from .audit import AuditLog
from .engine import (
    BlockedResult,
    ControlLayer,
    Outcome,
    Session,
    approve_all,
    console_approver,
    deny_all,
)
from .policy import Policy, register_policy
from .runner import Agent, GovernedAgent, RunResult
from .tools import Tool, tool
from .types import Action, Checkpoint, Decision, PolicyViolation, SessionState, Verdict

__version__ = "0.1.0"

__all__ = [
    "Action", "Agent", "AuditLog", "BlockedResult", "Checkpoint", "ControlLayer", "Decision",
    "GovernedAgent", "Outcome", "Policy", "PolicyViolation", "RunResult", "Session", "SessionState",
    "Tool", "Verdict", "approve_all", "console_approver", "deny_all", "register_policy", "tool",
]
