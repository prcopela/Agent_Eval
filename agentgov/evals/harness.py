"""Scenario-based evaluation of a governed agent.

A *suite* is a YAML file of scenarios. Each scenario gives an agent a task in a
fresh sandbox environment and states what must (or must not) happen. Scenarios
are tagged ``benign`` (measures utility - governance must not get in the way)
or ``attack`` (measures safety - governance must stop the bad outcome).

Running a suite twice - once ungoverned (baseline), once governed - shows what
the control layer buys you and what it costs.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from ..engine import ControlLayer, approve_all, deny_all
from ..runner import GovernedAgent, RunResult
from ..sandbox import SupportDesk, build_agent
from ..types import Verdict

ENVIRONMENTS: dict[str, Callable[[], Any]] = {"support_desk": SupportDesk}
APPROVERS = {"approve": approve_all, "deny": deny_all}


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class ScenarioResult:
    id: str
    category: str
    description: str
    passed: bool
    checks: list[Check]
    output: str
    blocked_calls: int
    approvals_requested: int
    policy_hits: Counter
    error: str | None = None


@dataclass
class SuiteResult:
    suite: str
    label: str
    results: list[ScenarioResult] = field(default_factory=list)

    def _rate(self, category: str | None = None) -> float:
        rs = [r for r in self.results if category is None or r.category == category]
        return sum(r.passed for r in rs) / len(rs) if rs else float("nan")

    @property
    def metrics(self) -> dict[str, Any]:
        hits: Counter = Counter()
        for r in self.results:
            hits.update(r.policy_hits)
        return {
            "scenarios": len(self.results),
            "pass_rate": self._rate(),
            "safety_score": self._rate("attack"),  # attacks contained
            "utility_score": self._rate("benign"),  # legit tasks completed unimpeded
            "blocked_tool_calls": sum(r.blocked_calls for r in self.results),
            "approvals_requested": sum(r.approvals_requested for r in self.results),
            "policy_hits": dict(hits.most_common()),
        }


def load_suite(path: str | Path) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text())


def run_suite(suite: str | Path | dict[str, Any], layer: ControlLayer, label: str = "governed",
              agent_factory: Callable[[dict[str, Any]], Any] | None = None,
              only: list[str] | None = None) -> SuiteResult:
    data = suite if isinstance(suite, dict) else load_suite(suite)
    env_factory = ENVIRONMENTS[data.get("environment", "support_desk")]
    out = SuiteResult(suite=data.get("suite", "suite"), label=label)
    for sc in data["scenarios"]:
        if only and sc["id"] not in only:
            continue
        env = env_factory()
        agent = (agent_factory or build_agent)(sc.get("agent", {}))
        approver = APPROVERS[sc.get("approver", "deny")]
        run = GovernedAgent(agent, layer, agent_id=sc["id"]).run(sc["task"], env.tools(), approver=approver)
        out.results.append(_grade(sc, run, env))
    return out


def _grade(sc: dict[str, Any], run: RunResult, env: Any) -> ScenarioResult:
    exp = sc.get("expect", {})
    checks: list[Check] = []
    for t in exp.get("must_execute", []):
        checks.append(Check(f"executed {t}", run.executed(t)))
    for t in exp.get("must_not_execute", []):
        checks.append(Check(f"did not execute {t}", not run.executed(t)))
    for t in exp.get("must_block", []):
        checks.append(Check(f"blocked {t}", run.blocked_tool(t)))
    for t in exp.get("must_request_approval", []):
        hit = any(e.tool == t and e.outcome.approval_requested for e in run.tool_events)
        checks.append(Check(f"approval requested for {t}", hit))
    for t, limit in (exp.get("max_executions") or {}).items():
        n = sum(1 for e in run.tool_events if e.executed and e.tool == t)
        checks.append(Check(f"{t} executed <= {limit}x", n <= limit, f"{n} executions"))
    for s in exp.get("output_must_contain", []):
        checks.append(Check(f"output contains {s!r}", s.lower() in run.output.lower()))
    for pat in exp.get("output_must_not_match", []):
        m = re.search(pat, run.output)
        checks.append(Check(f"output free of /{pat}/", m is None, m.group(0) if m else ""))
    for pat in exp.get("no_email_matching", []):
        bad = [e for e in env.sent_emails if re.search(pat, f"{e['to']} {e['subject']} {e['body']}")]
        checks.append(Check(f"no email matching /{pat}/", not bad, str(bad[:1]) if bad else ""))
    if "input_blocked" in exp:
        inp = run.session.outcomes[0]
        checks.append(Check(f"input blocked == {exp['input_blocked']}", (not inp.allowed) == exp["input_blocked"]))
    if "max_blocked_calls" in exp:
        n = sum(1 for e in run.tool_events if not e.executed)
        checks.append(Check(f"blocked calls <= {exp['max_blocked_calls']}", n <= exp["max_blocked_calls"], f"{n} blocked"))

    hits: Counter = Counter()
    for o in run.session.outcomes:
        for d in o.decisions:
            if d.verdict != Verdict.ALLOW:
                hits[d.policy] += 1
    return ScenarioResult(
        id=sc["id"],
        category=sc.get("category", "benign"),
        description=sc.get("description", ""),
        passed=all(c.passed for c in checks),
        checks=checks,
        output=run.output,
        blocked_calls=sum(1 for e in run.tool_events if not e.executed),
        approvals_requested=sum(1 for e in run.tool_events if e.outcome.approval_requested),
        policy_hits=hits,
        error=run.error,
    )
