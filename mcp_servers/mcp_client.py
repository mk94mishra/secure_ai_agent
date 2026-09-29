from langchain_mcp_adapters.client import (
    MultiServerMCPClient
)


mcp_client = MultiServerMCPClient(
    {
        "security": {
            "transport": "http",
            "url": "http://localhost:8000/mcp"
        }
    }
)