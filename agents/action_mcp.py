import os
from typing import Any

from dotenv import load_dotenv
from langchain_mcp_adapters.client import MultiServerMCPClient


# ============================================================
# Environment
# ============================================================

load_dotenv()


ACTION_MCP_SERVER_URL = os.getenv(
    "ACTION_MCP_SERVER_URL",
    "http://127.0.0.1:8001/mcp",
)


# ============================================================
# MCP Client
# ============================================================

action_mcp_client = MultiServerMCPClient(
    {
        "security_action": {
            "transport": "streamable_http",
            "url": ACTION_MCP_SERVER_URL,
        }
    }
)


# ============================================================
# Load Action MCP Tools
# ============================================================

async def get_action_mcp_tools():
    """
    Load all tools exposed by the Action MCP server.
    """

    tools = await action_mcp_client.get_tools()

    return tools


# ============================================================
# Find Tool
# ============================================================

async def get_action_tool(
    tool_name: str,
):
    """
    Find a specific action tool by name.
    """

    tools = await get_action_mcp_tools()

    for tool in tools:

        if tool.name == tool_name:
            return tool

    available_tools = [
        tool.name
        for tool in tools
    ]

    raise RuntimeError(
        f"Action MCP tool '{tool_name}' "
        f"was not found. "
        f"Available tools: {available_tools}"
    )


# ============================================================
# Execute TAG_RESOURCE
# ============================================================

async def execute_tag_resource(
    instance_id: str,
    tag_key: str,
    tag_value: str,
) -> dict[str, Any]:
    """
    Execute the TAG_RESOURCE action through MCP.

    The actual AWS operation is performed by
    mcp_server/action_server.py.
    """

    if not instance_id:
        raise ValueError(
            "instance_id is required."
        )

    if not tag_key:
        raise ValueError(
            "tag_key is required."
        )

    if not tag_value:
        raise ValueError(
            "tag_value is required."
        )

    tool = await get_action_tool(
        "tag_ec2_instance"
    )

    result = await tool.ainvoke(
        {
            "instance_id": instance_id,
            "tag_key": tag_key,
            "tag_value": tag_value,
        }
    )

    return normalize_tool_result(
        result
    )


# ============================================================
# Generic Security Action
# ============================================================

async def execute_security_action(
    action: str,
    resource_id: str,
) -> dict[str, Any]:
    """
    Call the generic execute_security_action MCP tool.

    This currently supports the server-side action
    validation and will only allow enabled actions.
    """

    if not action:
        raise ValueError(
            "action is required."
        )

    if not resource_id:
        raise ValueError(
            "resource_id is required."
        )

    tool = await get_action_tool(
        "execute_security_action"
    )

    result = await tool.ainvoke(
        {
            "action": action,
            "resource_id": resource_id,
        }
    )

    return normalize_tool_result(
        result
    )


# ============================================================
# Health Check
# ============================================================

async def action_mcp_health_check() -> dict[str, Any]:
    """
    Call the Action MCP server health-check tool.
    """

    tool = await get_action_tool(
        "action_health_check"
    )

    result = await tool.ainvoke({})

    return normalize_tool_result(
        result
    )


# ============================================================
# Supported Actions
# ============================================================

async def get_supported_actions() -> dict[str, Any]:
    """
    Get enabled/disabled actions from the Action MCP server.
    """

    tool = await get_action_tool(
        "get_supported_actions"
    )

    result = await tool.ainvoke({})

    return normalize_tool_result(
        result
    )


# ============================================================
# Result Normalization
# ============================================================

def normalize_tool_result(
    result: Any,
) -> dict[str, Any]:
    """
    Normalize MCP tool output into a Python dictionary.

    Different MCP/tool versions can return:
        - dict
        - JSON string
        - list
        - structured content
    """

    if isinstance(
        result,
        dict,
    ):
        return result

    if isinstance(
        result,
        str,
    ):

        import json

        try:

            parsed = json.loads(
                result
            )

            if isinstance(
                parsed,
                dict,
            ):
                return parsed

            return {
                "status": "UNKNOWN",
                "data": parsed,
            }

        except json.JSONDecodeError:

            return {
                "status": "UNKNOWN",
                "message": result,
            }

    if isinstance(
        result,
        list,
    ):

        return {
            "status": "UNKNOWN",
            "data": result,
        }

    return {
        "status": "UNKNOWN",
        "data": str(result),
    }


# ============================================================
# Local Test
# ============================================================

async def main():
    """
    Simple connectivity test.

    Does NOT execute an AWS write operation.
    """

    print(
        "Action MCP Server:"
    )

    print(
        ACTION_MCP_SERVER_URL
    )

    print(
        "\nLoading tools..."
    )

    tools = await get_action_mcp_tools()

    print(
        "\nAvailable Action MCP tools:"
    )

    for tool in tools:
        print(
            f"- {tool.name}"
        )

    print(
        "\nChecking server health..."
    )

    health = await action_mcp_health_check()

    print(
        health
    )

    print(
        "\nSupported actions:"
    )

    actions = await get_supported_actions()

    print(
        actions
    )


if __name__ == "__main__":

    import asyncio

    asyncio.run(
        main()
    )