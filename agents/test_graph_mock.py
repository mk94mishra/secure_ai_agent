
import asyncio
from unittest.mock import AsyncMock, patch

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import StateGraph, START, END
from langgraph.types import Command

from agents.state import AgentState
from agents.approval import human_approval_node
from agents.action import action_controller_node
from agents.action_executor import action_executor_node


def mock_planner(state: AgentState):
    return {"query": "Mock investigation for suspicious EC2 activity"}


def mock_rag(state: AgentState):
    return {
        "context": [
            {
                "content": "Mock security knowledge",
                "source": "mock-test",
                "score": 0.95,
            }
        ]
    }


def mock_investigation(state: AgentState):
    return {
        "findings": ["Mock suspicious EC2 activity"],
        "evidence": [
            {
                "source": "mock",
                "status": "success",
                "finding": "Suspicious activity simulated",
            }
        ],
    }


def mock_risk(state: AgentState):
    return {
        "risk": "HIGH",
        "confidence": 0.95,
        "requires_approval": True,
        "recommended_action": "TAG_RESOURCE",
        "findings": ["Mock suspicious EC2 activity"],
        "final_response": "Mock high-risk assessment",
    }


def route_after_approval(state: AgentState):
    if state.get("approval_status") == "APPROVED":
        return "controller"
    return "end"


def route_after_controller(state: AgentState):
    if state.get("action_status") == "PENDING":
        return "executor"
    return "end"


def route_after_executor(state: AgentState):
    if state.get("action_status") == "SUCCESS":
        return "success"
    return "failed"


def build_mock_graph():
    builder = StateGraph(AgentState)

    builder.add_node("planner", mock_planner)
    builder.add_node("rag", mock_rag)
    builder.add_node("investigation", mock_investigation)
    builder.add_node("risk", mock_risk)
    builder.add_node("approval", human_approval_node)
    builder.add_node("action_controller", action_controller_node)
    builder.add_node("action_executor", action_executor_node)

    builder.add_edge(START, "planner")
    builder.add_edge("planner", "rag")
    builder.add_edge("rag", "investigation")
    builder.add_edge("investigation", "risk")
    builder.add_edge("risk", "approval")

    builder.add_conditional_edges(
        "approval",
        route_after_approval,
        {
            "controller": "action_controller",
            "end": END,
        },
    )

    builder.add_conditional_edges(
        "action_controller",
        route_after_controller,
        {
            "executor": "action_executor",
            "end": END,
        },
    )

    builder.add_conditional_edges(
        "action_executor",
        route_after_executor,
        {
            "success": END,
            "failed": END,
        },
    )

    return builder.compile(checkpointer=InMemorySaver())


def initial_state():
    return {
        "tenant_id": "default",
        "alert": {
            "alert_id": "GRAPH-MOCK-001",
            "tenant_id": "default",
            "source": "Mock",
            "severity": "HIGH",
            "title": "Mock suspicious EC2 activity",
            "description": "Graph orchestration test only",
            "instance_id": "i-mock123456789",
        },
        "findings": [],
        "evidence": [],
        "investigation_iterations": 0,
    }


async def run_rejection_test(graph, execute_mock):
    print("Test 1: HIGH risk -> REJECTED")

    config = {
        "configurable": {
            "thread_id": "graph-mock-rejected-001"
        }
    }

    result = await graph.ainvoke(initial_state(), config=config)

    assert result.get("__interrupt__"), (
        "Expected human approval interrupt"
    )

    result = await graph.ainvoke(
        Command(
            resume={
                "status": "REJECTED",
                "approved_by": "soc-analyst-001",
                "reason": "Mock rejection test",
            }
        ),
        config=config,
    )

    assert result.get("approval_status") == "REJECTED"
    assert result.get("action_status") is None
    execute_mock.assert_not_awaited()

    print("PASS: Rejection stopped the graph before execution.")


async def run_approval_test(graph, execute_mock):
    print("\nTest 2: HIGH risk -> APPROVED -> policy -> executor")

    config = {
        "configurable": {
            "thread_id": "graph-mock-approved-001"
        }
    }

    result = await graph.ainvoke(initial_state(), config=config)

    assert result.get("__interrupt__"), (
        "Expected human approval interrupt"
    )

    execute_mock.return_value = {
        "status": "SUCCESS",
        "message": "Mock execution completed",
        "mcp_status": "MOCK",
    }

    result = await graph.ainvoke(
        Command(
            resume={
                "status": "APPROVED",
                "approved_by": "soc-analyst-001",
                "reason": "Approved for mock graph test",
            }
        ),
        config=config,
    )

    assert result.get("approval_status") == "APPROVED"
    assert result.get("action_status") == "SUCCESS"
    assert result.get("action_type") == "TAG_RESOURCE"
    execute_mock.assert_awaited_once()

    print("Action status:", result.get("action_status"))
    print("Action result:", result.get("action_result"))

    assert result.get("action_status") == "SUCCESS"
    assert execute_mock.await_count == 1

    print("PASS: Approved path reached the mocked executor.")
    
    print("Action status:", result["action_status"])
    print("PASS: Approved path reached the mocked executor.")


async def main():
    graph = build_mock_graph()

    # No real audit writes or AWS remediation during this test.
    with (
        patch("agents.approval.record_audit_event"),
        patch("agents.action.record_audit_event"),
        patch(
            "agents.action_executor.execute_action",
            new_callable=AsyncMock,
        ) as execute_mock,
    ):
        await run_rejection_test(graph, execute_mock)
        await run_approval_test(graph, execute_mock)

    print("\nALL GRAPH MOCK TESTS PASSED")
    print("No real AWS remediation was executed.")


if __name__ == "__main__":
    asyncio.run(main())
