import os

from dotenv import load_dotenv

from langchain_mcp_adapters.client import (
    MultiServerMCPClient
)


load_dotenv()


MCP_SERVER_URL = os.getenv(
    "MCP_SERVER_URL",
    "http://127.0.0.1:8000/mcp"
)


mcp_client = MultiServerMCPClient(
    {
        "security": {
            "transport": "streamable_http",
            "url": MCP_SERVER_URL
        }
    }
)


async def get_mcp_tools():

    tools = await mcp_client.get_tools()

    return tools