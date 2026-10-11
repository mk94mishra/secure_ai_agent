
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from agents.state import AgentState
from agents.approval import human_approval_node


def main():
    graph_builder = StateGraph(AgentState)

    graph_builder.add_node("approval", human_approval_node)
    graph_builder.add_edge(START, "approval")
    graph_builder.add_edge("approval", END)

    graph = graph_builder.compile(
        checkpointer=InMemorySaver()
    )

    config = {
        "configurable": {
            "thread_id": "approval-audit-test-001"
        }
    }

    initial_state = {
        "tenant_id": "default",
        "alert": {
            "alert_id": "APPROVAL-AUDIT-TEST-001",
            "tenant_id": "default",
            "title": "Mock high-risk security alert",
        },
        "risk": "HIGH",
        "confidence": 0.95,
        "recommended_action": "TAG_RESOURCE",
        "findings": ["Mock suspicious activity"],
        "evidence": [],
    }

    print("1. Starting approval workflow...")

    result = graph.invoke(initial_state, config=config)

    if not result.get("__interrupt__"):
        raise RuntimeError(
            "Expected an approval interrupt, but none occurred."
        )

    print("2. Approval interrupt received.")

    decision = {
        "status": "REJECTED",
        "approved_by": "soc-analyst-001",
        "reason": "Mock rejection test",
    }

    print("3. Resuming with REJECTED decision...")

    result = graph.invoke(
        Command(resume=decision),
        config=config,
    )

    print("4. Final result:")
    print("Approval status:", result.get("approval_status"))
    print("Approved by:", result.get("approved_by"))
    print("Approval reason:", result.get("approval_reason"))

    assert result.get("approval_status") == "REJECTED"

    print("\nPASS: Approval rejection workflow completed.")
    print("No EC2 or GuardDuty action was executed.")


if __name__ == "__main__":
    main()
