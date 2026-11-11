"""A minimal, framework-neutral tool description.

Any callable can be a tool. Wrapping it in :class:`Tool` lets you attach
governance metadata (tags such as ``egress`` or ``destructive``) and an optional
JSON schema so model adapters can expose it to an LLM.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class Tool:
    name: str
    fn: Callable[..., Any]
    description: str = ""
    tags: frozenset[str] = frozenset()
    input_schema: dict[str, Any] = field(default_factory=dict)

    def __call__(self, **kwargs: Any) -> Any:
        return self.fn(**kwargs)

    def schema(self) -> dict[str, Any]:
        """JSON schema for the tool's input (inferred from the signature if not given)."""
        if self.input_schema:
            return self.input_schema
        props: dict[str, Any] = {}
        required: list[str] = []
        type_map = {int: "integer", float: "number", bool: "boolean", str: "string", dict: "object", list: "array"}
        for p in inspect.signature(self.fn).parameters.values():
            ann = p.annotation if p.annotation is not inspect.Parameter.empty else str
            if isinstance(ann, str):  # postponed annotations
                ann = {"int": int, "float": float, "bool": bool, "dict": dict, "list": list}.get(ann, str)
            props[p.name] = {"type": type_map.get(ann, "string")}
            if p.default is inspect.Parameter.empty:
                required.append(p.name)
        return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def tool(name: str | None = None, *, tags: list[str] | tuple[str, ...] = (), description: str | None = None,
         input_schema: dict[str, Any] | None = None) -> Callable[[Callable[..., Any]], Tool]:
    """Decorator: ``@tool(tags=["egress"])`` turns a function into a :class:`Tool`."""

    def deco(fn: Callable[..., Any]) -> Tool:
        return Tool(
            name=name or fn.__name__,
            fn=fn,
            description=description or (inspect.getdoc(fn) or "").strip(),
            tags=frozenset(tags),
            input_schema=input_schema or {},
        )

    return deco


def as_tools(tools: Any, tag_map: dict[str, list[str]] | None = None) -> dict[str, Tool]:
    """Normalise a list/dict of callables or Tools into ``{name: Tool}``.

    ``tag_map`` (usually from the governance YAML) adds tags to tools by name.
    """
    tag_map = tag_map or {}
    items = tools.items() if isinstance(tools, dict) else ((getattr(t, "name", None) or t.__name__, t) for t in tools)
    out: dict[str, Tool] = {}
    for name, t in items:
        if not isinstance(t, Tool):
            t = Tool(name=name, fn=t, description=(inspect.getdoc(t) or "").strip())
        extra = frozenset(tag_map.get(t.name, ()))
        if extra:
            t = Tool(t.name, t.fn, t.description, t.tags | extra, t.input_schema)
        out[t.name] = t
    return out
