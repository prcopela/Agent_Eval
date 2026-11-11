"""04 - Write your own policy: data scoping per conversation.

Organisation-specific rules plug in like built-ins. This one enforces that a
support agent serving customer X can only read customer X's data, which a generic
allow-list cannot express. Registering it makes it usable from YAML too.

    python examples/04_custom_policy.py
"""

from agentgov import ControlLayer, Policy, register_policy
from agentgov.sandbox import SupportDesk
from agentgov.sandbox.env import ORDERS
from agentgov.types import Checkpoint


@register_policy("customer_scope")
class CustomerScopePolicy(Policy):
    """The agent may only touch records belonging to the customer it is serving."""

    checkpoints = frozenset({Checkpoint.TOOL_CALL})

    def evaluate(self, action, state):
        serving = state.scratch.get("customer_id")
        if serving is None:
            return None
        target = action.args.get("customer_id")
        if "order_id" in action.args:
            target = ORDERS.get(action.args["order_id"], {}).get("customer_id")
        if target is not None and target != serving:
            return self.deny(f"agent is serving {serving} but tried to access {target}'s data")
        return None


# Usable from YAML exactly like a built-in:
layer = ControlLayer.from_config({"policies": [{"type": "customer_scope"}]})

session = layer.session("support-agent")
session.state.scratch["customer_id"] = "C-1001"  # set from your auth/session context
tools = session.wrap(SupportDesk().tools())

print("own order    :", tools["lookup_order"](order_id="A-100"))
print("other's order:", tools["lookup_order"](order_id="A-300"))
print("other's data :", tools["lookup_customer"](customer_id="C-1002"))
