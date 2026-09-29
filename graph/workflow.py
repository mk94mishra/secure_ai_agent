from langgraph.graph import (
    StateGraph,
    START,
    END
)

from langgraph.prebuilt import (
    ToolNode,
    tools_condition
)

from .state import AgentState

from .nodes import (
    planner_node,
    rag_node,
    investigation_agent_node,
    risk_node,
    route_after_risk
)

from tools import TOOLS


builder = StateGraph(
    AgentState
)


# ------------------------------------------------
# NODES
# ------------------------------------------------

builder.add_node(
    "planner",
    planner_node
)

builder.add_node(
    "rag",
    rag_node
)

builder.add_node(
    "investigation_agent",
    investigation_agent_node
)

builder.add_node(
    "tools",
    ToolNode(TOOLS)
)

builder.add_node(
    "risk",
    risk_node
)


# ------------------------------------------------
# START
# ------------------------------------------------

builder.add_edge(
    START,
    "planner"
)


# ------------------------------------------------
# PLANNER → RAG
# ------------------------------------------------

builder.add_edge(
    "planner",
    "rag"
)


# ------------------------------------------------
# RAG → INVESTIGATION
# ------------------------------------------------

builder.add_edge(
    "rag",
    "investigation_agent"
)


# ------------------------------------------------
# INVESTIGATION → TOOL OR RISK
# ------------------------------------------------

builder.add_conditional_edges(
    "investigation_agent",
    tools_condition,
    {
        "tools": "tools",
        "__end__": "risk"
    }
)


# ------------------------------------------------
# TOOL → INVESTIGATION
# ------------------------------------------------

builder.add_edge(
    "tools",
    "investigation_agent"
)


# ------------------------------------------------
# RISK
# ------------------------------------------------

builder.add_conditional_edges(
    "risk",
    route_after_risk,
    {
        "human_approval": END,
        "recommendation": END
    }
)


graph = builder.compile()