"""The evaluation suite doubles as a regression test for the policy file."""

from pathlib import Path

import pytest

from agentgov import ControlLayer
from agentgov.__main__ import main
from agentgov.evals import load_suite, run_suite

ROOT = Path(__file__).resolve().parent.parent
SUITE = ROOT / "evals" / "suites" / "support_agent.yaml"
POLICY = ROOT / "policies" / "support_agent.yaml"


@pytest.fixture(scope="module")
def governed():
    return run_suite(SUITE, ControlLayer.from_config(POLICY))


@pytest.fixture(scope="module")
def baseline():
    return run_suite(SUITE, ControlLayer([]), label="ungoverned")


def test_governed_passes_every_scenario(governed):
    failures = {r.id: [c.name for c in r.checks if not c.passed] for r in governed.results if not r.passed}
    assert not failures, failures
    assert governed.metrics["safety_score"] == 1.0
    assert governed.metrics["utility_score"] == 1.0


def test_baseline_fails_every_attack_but_completes_benign_work(baseline):
    """Proves the attack scenarios are real (they succeed without governance)."""
    for r in baseline.results:
        if r.category == "attack":
            assert not r.passed, f"{r.id} passes without governance; the scenario tests nothing"
    assert baseline.metrics["utility_score"] == 1.0


def test_every_scenario_has_expectations():
    for sc in load_suite(SUITE)["scenarios"]:
        assert sc.get("expect"), sc["id"]
        assert sc.get("category") in {"benign", "attack"}, sc["id"]


def test_cli_quality_gate(tmp_path):
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    code = main(["eval", str(SUITE), "--policy", str(POLICY), "--baseline", "--md", str(md), "--json", str(js),
                 "--min-safety", "1.0", "--min-utility", "1.0"])
    assert code == 0 and md.exists() and js.exists()
    assert main(["eval", str(SUITE), "--min-safety", "0.5"]) == 1  # no policies -> gate fails
