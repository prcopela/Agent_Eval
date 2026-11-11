"""Human- and machine-readable reports for suite results."""

from __future__ import annotations

import json
import math
from typing import Any

from .harness import SuiteResult


def _pct(x: float) -> str:
    return "n/a" if isinstance(x, float) and math.isnan(x) else f"{x:.0%}"


def to_dict(result: SuiteResult) -> dict[str, Any]:
    return {
        "suite": result.suite,
        "label": result.label,
        "metrics": result.metrics,
        "scenarios": [
            {
                "id": r.id,
                "category": r.category,
                "passed": r.passed,
                "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in r.checks],
                "blocked_calls": r.blocked_calls,
                "approvals_requested": r.approvals_requested,
                "policy_hits": dict(r.policy_hits),
                "output": r.output,
                "error": r.error,
            }
            for r in result.results
        ],
    }


def to_json(*results: SuiteResult) -> str:
    return json.dumps([to_dict(r) for r in results], indent=2, default=str)


def to_markdown(*results: SuiteResult) -> str:
    lines = [f"# Governance evaluation: {results[0].suite}", ""]
    lines += ["| run | pass rate | safety (attacks contained) | utility (benign completed) | blocked calls | approvals |",
              "|---|---|---|---|---|---|"]
    for r in results:
        m = r.metrics
        lines.append(f"| {r.label} | {_pct(m['pass_rate'])} | {_pct(m['safety_score'])} | "
                     f"{_pct(m['utility_score'])} | {m['blocked_tool_calls']} | {m['approvals_requested']} |")
    for r in results:
        lines += ["", f"## {r.label}", "", "| scenario | category | result | failed checks | policies triggered |",
                  "|---|---|---|---|---|"]
        for s in r.results:
            failed = "; ".join(c.name + (f" ({c.detail})" if c.detail else "") for c in s.checks if not c.passed)
            hits = ", ".join(f"{k}x{v}" for k, v in s.policy_hits.items())
            lines.append(f"| {s.id} | {s.category} | {'PASS' if s.passed else 'FAIL'} | {failed or '-'} | {hits or '-'} |")
    return "\n".join(lines) + "\n"


def to_console(*results: SuiteResult) -> str:
    out = []
    ids = [s.id for s in results[0].results]
    width = max(len(i) for i in ids) + 2
    header = "scenario".ljust(width) + "category  " + "".join(r.label[:12].ljust(14) for r in results)
    out += [header, "-" * len(header)]
    for i, sid in enumerate(ids):
        row = sid.ljust(width) + results[0].results[i].category.ljust(10)
        for r in results:
            row += ("PASS" if r.results[i].passed else "FAIL").ljust(14)
        out.append(row)
    out.append("-" * len(header))
    for key, name in [("safety_score", "safety"), ("utility_score", "utility"), ("pass_rate", "overall")]:
        out.append(f"{name}:".ljust(width + 10) + "".join(_pct(r.metrics[key]).ljust(14) for r in results))
    return "\n".join(out)
