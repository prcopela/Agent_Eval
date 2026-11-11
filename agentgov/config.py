"""Governance-as-code: build a ControlLayer from a YAML (or dict) policy file.

Example::

    mode: enforce              # or "monitor" for shadow mode
    audit_log: audit/run.jsonl # optional
    tools:                     # governance metadata about tools, by name
      send_email: {tags: [egress]}
      delete_records: {tags: [destructive]}
    policies:
      - type: tool_access
        deny: ["run_shell"]
      - type: approval
        tags: [destructive]
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from . import policies as _builtin  # noqa: F401  (registers built-in policies)
from .audit import AuditLog
from .engine import ControlLayer
from .policy import get_policy_class


def load_config(source: str | Path | dict[str, Any], **overrides: Any) -> ControlLayer:
    if isinstance(source, dict):
        cfg = source
    else:
        cfg = yaml.safe_load(Path(source).read_text()) or {}

    policies = []
    for i, spec in enumerate(cfg.get("policies", [])):
        spec = dict(spec)
        type_name = spec.pop("type", None)
        if not type_name:
            raise ValueError(f"policies[{i}] is missing 'type'")
        if spec.pop("enabled", True) is False:
            continue
        policies.append(get_policy_class(type_name)(**spec))

    tool_tags = {name: list(meta.get("tags", [])) for name, meta in (cfg.get("tools") or {}).items()}
    kwargs: dict[str, Any] = {
        "mode": cfg.get("mode", "enforce"),
        "tool_tags": tool_tags,
        "audit": AuditLog(cfg["audit_log"]) if cfg.get("audit_log") else None,
    }
    kwargs.update(overrides)
    return ControlLayer(policies, **kwargs)
