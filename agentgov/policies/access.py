"""Who may call which tool, and with which arguments."""

from __future__ import annotations

import posixpath
import re
from typing import Any
from urllib.parse import urlparse

from ..policy import Policy, matches_any, register_policy
from ..types import Action, Checkpoint, Decision, SessionState


@register_policy("tool_access")
class ToolAccessPolicy(Policy):
    """Allow-list / deny-list of tool names (glob patterns) and tags.

    Deny rules win. If ``allow`` is given, anything not matching it is denied
    (default-deny), which is the recommended posture for production agents.
    """

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def __init__(self, allow: list[str] | None = None, deny: list[str] | None = None,
                 deny_tags: list[str] | None = None, **kw: Any):
        super().__init__(**kw)
        self.allow = allow
        self.deny_patterns = deny or []
        self.deny_tags = set(deny_tags or [])

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:
        if matches_any(action.tool, self.deny_patterns):
            return self.deny(f"tool '{action.tool}' is on the deny list")
        if self.deny_tags & action.tags:
            return self.deny(f"tool '{action.tool}' has forbidden tag(s) {sorted(self.deny_tags & action.tags)}")
        if self.allow is not None and not matches_any(action.tool, self.allow):
            return self.deny(f"tool '{action.tool}' is not on the allow list")
        return None


@register_policy("argument_rules")
class ArgumentRulesPolicy(Policy):
    """Per-tool argument constraints.

    Supported constraint keys (combine freely)::

        min / max            numeric bounds
        allowed_values       value must be one of the list
        pattern              value must fully match the regex
        deny_pattern         value must NOT contain a match for the regex
        path_within          filesystem path must resolve inside this directory
        domain_allowlist     URL / email domain must be in the list (subdomains ok)
    """

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def __init__(self, rules: dict[str, dict[str, dict[str, Any]]], **kw: Any):
        super().__init__(**kw)
        self.rules = rules

    def evaluate(self, action: Action, state: SessionState) -> Decision | None:
        for tool_pattern, arg_rules in self.rules.items():
            if not matches_any(action.tool, [tool_pattern]):
                continue
            for arg, constraint in arg_rules.items():
                if arg not in action.args:
                    continue
                problem = self._check(action.args[arg], constraint)
                if problem:
                    return self.deny(f"{action.tool}.{arg}: {problem}")
        return None

    @staticmethod
    def _check(value: Any, c: dict[str, Any]) -> str | None:
        if "min" in c or "max" in c:
            try:
                num = float(value)
            except (TypeError, ValueError):
                return f"expected a number, got {value!r}"
            if "min" in c and num < c["min"]:
                return f"{num} is below the minimum {c['min']}"
            if "max" in c and num > c["max"]:
                return f"{num} exceeds the maximum {c['max']}"
        if "allowed_values" in c and value not in c["allowed_values"]:
            return f"{value!r} is not one of {c['allowed_values']}"
        text = str(value)
        if "pattern" in c and not re.fullmatch(c["pattern"], text):
            return f"{text!r} does not match required pattern"
        if "deny_pattern" in c and re.search(c["deny_pattern"], text):
            return f"{text!r} matches a forbidden pattern"
        if "path_within" in c:
            root = posixpath.normpath(c["path_within"])
            resolved = posixpath.normpath(posixpath.join(root, text))
            if resolved != root and not resolved.startswith(root.rstrip("/") + "/"):
                return f"path {text!r} escapes {root}"
        if "domain_allowlist" in c:
            domain = _domain_of(text)
            allowed = [d.lower() for d in c["domain_allowlist"]]
            if not domain or not any(domain == d or domain.endswith("." + d) for d in allowed):
                return f"domain {domain or text!r} is not allow-listed"
        return None


def _domain_of(value: str) -> str:
    if "@" in value and "://" not in value:
        return value.rsplit("@", 1)[1].strip().lower()
    host = urlparse(value if "://" in value else "//" + value).hostname
    return (host or "").lower()
