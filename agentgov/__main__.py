"""Command line: ``python -m agentgov <command>``.

    eval SUITE [--policy FILE] [--baseline] [--agent claude] [--md OUT] [--json OUT]
    verify-audit FILE
    policies
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import AuditLog
from .config import load_config
from .engine import ControlLayer
from .policy import registered_policies


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentgov")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("eval", help="run an evaluation suite")
    e.add_argument("suite")
    e.add_argument("--policy", help="governance YAML (default: no policies)")
    e.add_argument("--baseline", action="store_true", help="also run ungoverned for comparison")
    e.add_argument("--agent", choices=["scenario", "claude"], default="scenario",
                   help="'claude' replaces every scripted agent with a real Claude agent")
    e.add_argument("--model", default="claude-opus-5-5")
    e.add_argument("--only", nargs="*", help="scenario ids to run")
    e.add_argument("--md", help="write a markdown report here")
    e.add_argument("--json", help="write a JSON report here")
    e.add_argument("--min-safety", type=float, default=None, help="exit 1 if safety score is below this")
    e.add_argument("--min-utility", type=float, default=None, help="exit 1 if utility score is below this")

    v = sub.add_parser("verify-audit", help="verify an audit log's hash chain")
    v.add_argument("path")

    sub.add_parser("policies", help="list registered policy types")

    args = p.parse_args(argv)

    if args.cmd == "policies":
        for name, cls in sorted(registered_policies().items()):
            doc = (cls.__doc__ or "").strip().splitlines()[0] if cls.__doc__ else ""
            print(f"{name:18} {doc}")
        return 0

    if args.cmd == "verify-audit":
        ok, msg = AuditLog(args.path).verify()
        print(("OK: " if ok else "TAMPERED: ") + msg)
        return 0 if ok else 1

    from .evals import run_suite, to_console, to_json, to_markdown

    factory = None
    if args.agent == "claude":
        from .adapters.anthropic import ClaudeAgent

        factory = lambda spec: ClaudeAgent(model=args.model)  # noqa: E731

    runs = []
    if args.baseline:
        runs.append(run_suite(args.suite, ControlLayer([]), "ungoverned", factory, args.only))
    layer = load_config(args.policy) if args.policy else ControlLayer([])
    governed = run_suite(args.suite, layer, "governed", factory, args.only)
    runs.append(governed)

    print(to_console(*runs))
    if args.md:
        Path(args.md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md).write_text(to_markdown(*runs))
        print(f"\nmarkdown report: {args.md}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(to_json(*runs))
        print(f"json report: {args.json}")

    m = governed.metrics
    if args.min_safety is not None and m["safety_score"] < args.min_safety:
        print(f"FAIL: safety {m['safety_score']:.0%} < {args.min_safety:.0%}", file=sys.stderr)
        return 1
    if args.min_utility is not None and m["utility_score"] < args.min_utility:
        print(f"FAIL: utility {m['utility_score']:.0%} < {args.min_utility:.0%}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
