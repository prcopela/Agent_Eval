"""05 - Shadow-mode rollout: measure a stricter policy before enforcing it.

Governance changes can break legitimate workflows. Run the new policy set in
`monitor` mode against real (here: evaluation) traffic, look at what it *would*
have blocked, then switch to `enforce`.

    python examples/05_monitor_mode_rollout.py
"""

from collections import Counter
from pathlib import Path

import yaml

from agentgov import ControlLayer
from agentgov.evals import run_suite

ROOT = Path(__file__).resolve().parent.parent
SUITE = ROOT / "evals" / "suites" / "support_agent.yaml"

cfg = yaml.safe_load((ROOT / "policies" / "support_agent.yaml").read_text())
# Proposed change: block ALL egress after reading untrusted content, instead of asking a human.
for p in cfg["policies"]:
    if p["type"] == "taint_guard":
        p["action"] = "deny"

shadow = ControlLayer.from_config({**cfg, "mode": "monitor"})
run_suite(SUITE, shadow, label="shadow")

would_block = Counter()
for e in shadow.audit:
    if e["verdict"] == "deny":
        would_block[(e["agent_id"], e["action"]["tool"] or e["action"]["checkpoint"])] += 1

print("In monitor mode nothing was enforced, but the proposed policy WOULD have denied:")
for (scenario, what), n in sorted(would_block.items()):
    print(f"  {scenario:<26} {what:<16} x{n}")

print("\nNow compare enforced utility/safety of current vs proposed policy:")
for label, c in [("current", yaml.safe_load((ROOT / "policies" / "support_agent.yaml").read_text())),
                 ("proposed", cfg)]:
    m = run_suite(SUITE, ControlLayer.from_config(c), label=label).metrics
    print(f"  {label:<9} safety={m['safety_score']:.0%} utility={m['utility_score']:.0%} "
          f"approvals={m['approvals_requested']}")
print("\nSame safety, but the proposed policy breaks 'web_research_then_email' (a legitimate task).")
print("Decision: keep human approval for tainted egress.")
