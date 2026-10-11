import asyncio

from langchain_mcp_adapters.client import (
    MultiServerMCPClient
)


async def load_tools():

    client = MultiServerMCPClient(
        {
            "security": {
                "transport": "http",
                "url": "http://localhost:8000/mcp"
            }
        }
    )

    tools = await client.get_tools()

    for tool in tools:
        print(
            tool.name,
            "=>",
            tool.description
        )

    return tools


if __name__ == "__main__":

    asyncio.run(
        load_tools()
    )