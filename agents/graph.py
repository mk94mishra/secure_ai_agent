from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver

from agents.state import AgentState

from agents.planner import planner_node
from agents.rag_node import rag_node

from agents.investigation import (
    investigation_node,
    create_investigation_tool_node,
    route_investigation,
)

from agents.risk import risk_node
from agents.approval import human_approval_node
from agents.action import action_controller_node
from agents.action_executor import action_executor_node


# ============================================================
# Route after Risk Assessment
# ============================================================

def route_after_risk(
    state: AgentState,
):
    """
    LOW / MEDIUM
        -> END

    HIGH / CRITICAL
        -> Human Approval
    """

    risk = state.get(
        "risk",
        "LOW",
    )

    if risk in {
        "HIGH",
        "CRITICAL",
    }:
        return "approval"

    return "end"


# ============================================================
# Route after Human Approval
# ============================================================

def route_after_approval(
    state: AgentState,
):
    """
    APPROVED
        -> Action Controller

    REJECTED
        -> END
    """

    approval_status = state.get(
        "approval_status"
    )

    if approval_status == "APPROVED":
        return "approved"

    return "rejected"


# ============================================================
# Route after Action Controller
# ============================================================

def route_after_action(
    state: AgentState,
):
    """
    Action Controller result:

    PENDING
        -> Action Executor

    DENIED / FAILED
        -> END
    """

    action_status = state.get(
        "action_status"
    )

    if action_status == "PENDING":
        return "execute"

    return "end"


# ============================================================
# Route after Action Executor
# ============================================================

def route_after_execution(
    state: AgentState,
):
    """
    Final action execution result.

    SUCCESS
        -> END

    FAILED
        -> END

    DENIED
        -> END
    """

    action_status = state.get(
        "action_status"
    )

    if action_status == "SUCCESS":
        return "success"

    return "failed"


# ============================================================
# Create Security Graph
# ============================================================

async def create_security_graph():

    # --------------------------------------------------------
    # Read-only Investigation MCP tools
    # --------------------------------------------------------

    mcp_tool_node = (
        await create_investigation_tool_node()
    )

    # --------------------------------------------------------
    # Graph
    # --------------------------------------------------------

    builder = StateGraph(
        AgentState
    )

    # ========================================================
    # Register Nodes
    # ========================================================

    builder.add_node(
        "planner",
        planner_node,
    )

    builder.add_node(
        "rag",
        rag_node,
    )

    builder.add_node(
        "investigation",
        investigation_node,
    )

    builder.add_node(
        "mcp_tools",
        mcp_tool_node,
    )

    builder.add_node(
        "risk",
        risk_node,
    )

    builder.add_node(
        "approval",
        human_approval_node,
    )

    builder.add_node(
        "action_controller",
        action_controller_node,
    )

    builder.add_node(
        "action_executor",
        action_executor_node,
    )

    # ========================================================
    # START
    # ========================================================

    builder.add_edge(
        START,
        "planner",
    )

    # ========================================================
    # Planner -> RAG
    # ========================================================

    builder.add_edge(
        "planner",
        "rag",
    )

    # ========================================================
    # RAG -> Investigation
    # ========================================================

    builder.add_edge(
        "rag",
        "investigation",
    )

    # ========================================================
    # Investigation -> MCP / Risk
    # ========================================================

    builder.add_conditional_edges(
        "investigation",
        route_investigation,
        {
            "tools": "mcp_tools",
            "__end__": "risk",
        },
    )

    # ========================================================
    # MCP -> Investigation
    # ========================================================

    builder.add_edge(
        "mcp_tools",
        "investigation",
    )

    # ========================================================
    # Risk -> Approval / END
    # ========================================================

    builder.add_conditional_edges(
        "risk",
        route_after_risk,
        {
            "approval": "approval",
            "end": END,
        },
    )

    # ========================================================
    # Approval -> Action Controller / END
    # ========================================================

    builder.add_conditional_edges(
        "approval",
        route_after_approval,
        {
            "approved": "action_controller",
            "rejected": END,
        },
    )

    # ========================================================
    # Action Controller -> Action Executor / END
    # ========================================================

    builder.add_conditional_edges(
        "action_controller",
        route_after_action,
        {
            "execute": "action_executor",
            "end": END,
        },
    )

    # ========================================================
    # Action Executor -> END
    # ========================================================

    builder.add_conditional_edges(
        "action_executor",
        route_after_execution,
        {
            "success": END,
            "failed": END,
        },
    )

    # ========================================================
    # Checkpointer
    # ========================================================

    checkpointer = InMemorySaver()

    # ========================================================
    # Compile
    # ========================================================

    graph = builder.compile(
        checkpointer=checkpointer
    )

    return graph