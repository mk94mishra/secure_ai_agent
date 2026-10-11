from typing import TypedDict, Annotated

from langchain_core.messages import BaseMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

from llm import llm
from mcp_client import get_mcp_tools


# ============================================================
# STATE
# ============================================================

class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]


# ============================================================
# CREATE AGENT
# ============================================================

async def create_agent():

    # --------------------------------------------------------
    # Load MCP tools
    # --------------------------------------------------------

    tools = await get_mcp_tools()

    print("\nMCP TOOLS LOADED:")

    for tool in tools:
        print("-", tool.name)

    # --------------------------------------------------------
    # Bind MCP tools to LLM
    # --------------------------------------------------------

    model = llm.bind_tools(tools)

    # --------------------------------------------------------
    # Agent node
    # --------------------------------------------------------

    def agent_node(state: AgentState):

        response = model.invoke(
            state["messages"]
        )

        print("\n--- AGENT RESPONSE ---")

        print("Content:")
        print(response.content)

        print("Tool calls:")
        print(response.tool_calls)

        return {
            "messages": [response]
        }

    # --------------------------------------------------------
    # Tool node
    # --------------------------------------------------------

    tool_node = ToolNode(tools)

    # --------------------------------------------------------
    # Graph
    # --------------------------------------------------------

    builder = StateGraph(AgentState)

    builder.add_node(
        "agent",
        agent_node
    )

    builder.add_node(
        "tools",
        tool_node
    )

    # START → AGENT

    builder.add_edge(
        START,
        "agent"
    )

    # AGENT → TOOL or END

    builder.add_conditional_edges(
        "agent",
        tools_condition,
        {
            "tools": "tools",
            "__end__": END
        }
    )

    # TOOL → AGENT

    builder.add_edge(
        "tools",
        "agent"
    )

    return builder.compile()