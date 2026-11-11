"""01 - Quickstart: put a control layer in front of plain Python tools.

No agent framework, no LLM, no YAML: just policies in code, so you can see
each verdict (ALLOW / MODIFY / REQUIRE_APPROVAL / DENY) and the audit trail.

    python examples/01_quickstart.py
"""

from agentgov import ControlLayer, tool
from agentgov.policies import (
    ApprovalPolicy,
    ArgumentRulesPolicy,
    SensitiveDataPolicy,
    ToolAccessPolicy,
)


@tool(tags=["read"])
def get_balance(account: str) -> dict:
    return {"account": account, "balance": 1250.00}


@tool(tags=["financial"])
def transfer(account: str, to: str, amount: float) -> dict:
    return {"ok": True, "from": account, "to": to, "amount": amount}


@tool(tags=["destructive"])
def close_account(account: str) -> dict:
    return {"ok": True, "closed": account}


layer = ControlLayer(
    policies=[
        ToolAccessPolicy(allow=["get_balance", "transfer", "close_account"]),
        ArgumentRulesPolicy(rules={"transfer": {"amount": {"min": 0.01, "max": 10_000}}}),
        ApprovalPolicy(tags=["destructive"], conditions={"transfer": {"amount": {"gt": 500}}}),
        SensitiveDataPolicy(scan=["output"], detectors=["ssn", "credit_card"]),
    ],
    # Simulated human: approves transfers, never approves account closure.
    approver=lambda action, decisions: action.tool == "transfer",
)

session = layer.session(agent_id="banking-bot")
tools = session.wrap([get_balance, transfer, close_account])


def show(label, result):
    print(f"{label:<38} -> {result}")


show("get_balance", tools["get_balance"](account="ACC-1"))
show("transfer $200 (auto-allowed)", tools["transfer"](account="ACC-1", to="ACC-2", amount=200))
show("transfer $900 (needs approval: yes)", tools["transfer"](account="ACC-1", to="ACC-2", amount=900))
show("transfer $50k (argument rule)", tools["transfer"](account="ACC-1", to="ACC-9", amount=50_000))
show("close_account (needs approval: no)", tools["close_account"](account="ACC-1"))

out = session.check_output("Your SSN on file is 123-45-6789.")
show("final answer with an SSN", out.action.content)

print("\nAudit trail:")
for e in layer.audit:
    what = e["action"]["tool"] or ""
    why = "; ".join(d["reason"] for d in e["decisions"]) or "-"
    if e["approval_requested"]:
        why += f" [human {'approved' if e['approved'] else 'declined'}]"
    print(f"  #{e['seq']:<2} {e['action']['checkpoint']:<12} {e['verdict']:<7} {what:<14} {why}")
print("\nIntegrity:", layer.audit.verify())
