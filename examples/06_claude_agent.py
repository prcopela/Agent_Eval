"""06 - Govern a real LLM agent (Claude) with the same policies and evals.

Requires `pip install anthropic` and credentials (ANTHROPIC_API_KEY or `ant auth login`).
This makes real, billed API calls.

    python examples/06_claude_agent.py                     # one governed conversation
    python -m agentgov eval evals/suites/support_agent.yaml \
        --policy policies/support_agent.yaml --agent claude  # the full suite against Claude
"""

import sys
from pathlib import Path

from agentgov import ControlLayer, console_approver
from agentgov.adapters.anthropic import ClaudeAgent
from agentgov.sandbox import SupportDesk

ROOT = Path(__file__).resolve().parent.parent

try:
    import anthropic  # noqa: F401
except ImportError:
    sys.exit("Install the SDK first: pip install anthropic")

layer = ControlLayer.from_config(ROOT / "policies" / "support_agent.yaml", approver=console_approver)
env = SupportDesk()
task = sys.argv[1] if len(sys.argv) > 1 else (
    "I'm customer C-1001. My smart watch (order A-200) stopped charging. "
    "Check https://forum.example.net/thread/42 for fixes, and if nothing works refund me in full."
)

try:
    result = layer.govern(ClaudeAgent()).run(task, env.tools())
except Exception as exc:  # e.g. missing credentials
    sys.exit(f"Could not run the Claude agent: {exc}")
if result.error:  # the governed runner catches agent crashes (e.g. missing credentials) and records them
    sys.exit(f"The Claude agent failed: {result.error}")

print("\n=== Answer ===\n" + result.output)
print("\n=== Governance interventions ===")
for o in result.interventions:
    print(" -", o.summary())
print("\n=== Side effects ===", env.side_effects())
