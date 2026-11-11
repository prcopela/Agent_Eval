"""Policy base class and registry.

A policy is a small, single-purpose rule. Write one by subclassing
:class:`Policy`, declaring which checkpoints it cares about, and implementing
:meth:`Policy.evaluate`. Return ``None`` to abstain (equivalent to ALLOW).

Register it with ``@register_policy("my_type")`` so it can be referenced from
YAML governance files.
"""

from __future__ import annotations

import fnmatch
from typing import Any, Callable, ClassVar, Iterable

from .types import Action, Checkpoint, Decision, SessionState, Verdict

_REGISTRY: dict[str, type["Policy"]] = {}


def register_policy(type_name: str) -> Callable[[type["Policy"]], type["Policy"]]:
    def deco(cls: type["Policy"]) -> type["Policy"]:
        cls.type_name = type_name
        _REGISTRY[type_name] = cls
        return cls

    return deco


def get_policy_class(type_name: str) -> type["Policy"]:
    try:
        return _REGISTRY[type_name]
    except KeyError:
        known = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"Unknown policy type {type_name!r}. Known: {known}") from None


def registered_policies() -> dict[str, type["Policy"]]:
    return dict(_REGISTRY)


class Policy:
    type_name: ClassVar[str] = "policy"
    checkpoints: ClassVar[frozenset[Checkpoint]] = frozenset(Checkpoint)

    def __init__(self, name: str | None = None, **_: Any):
        self.name = name or self.type_name

    def applies_to(self, action: Action) -> bool:
        return action.checkpoint in self.checkpoints

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:  # pragma: no cover
        raise NotImplementedError

    def on_executed(self, action: Action, state: SessionState) -> None:
        """Hook called after an allowed TOOL_CALL actually ran (for stateful policies)."""

    # -- helpers for subclasses -------------------------------------------------
    def allow(self, reason: str = "") -> Decision:
        return Decision(Verdict.ALLOW, self.name, reason)

    def deny(self, reason: str) -> Decision:
        return Decision(Verdict.DENY, self.name, reason)

    def require_approval(self, reason: str) -> Decision:
        return Decision(Verdict.REQUIRE_APPROVAL, self.name, reason)

    def modify(self, action: Action, reason: str) -> Decision:
        return Decision(Verdict.MODIFY, self.name, reason, modified=action)

    def __repr__(self) -> str:
        return f"<{type(self).__name__} name={self.name!r}>"


def matches_any(name: str | None, patterns: Iterable[str]) -> bool:
    """Glob match, e.g. ``shell_*`` or ``*delete*``."""
    if name is None:
        return False
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def tool_selected(action: Action, tools: Iterable[str] = (), tags: Iterable[str] = ()) -> bool:
    """True when the action's tool matches one of the patterns or carries one of the tags."""
    tags = set(tags)
    return matches_any(action.tool, tools) or bool(tags & action.tags)
