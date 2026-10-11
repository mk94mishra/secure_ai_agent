import asyncio

from langchain_core.messages import (
    HumanMessage
)

from agents.temp.agent import (
    create_agent
)


async def main():

    # =============================================
    # Create graph
    # =============================================

    graph = await create_agent()

    # =============================================
    # User request
    # =============================================

    message = HumanMessage(
        content="""
        Investigate EC2 instance
        i-0123456789.

        Get its current state,
        instance type and network information.
        """
    )

    # =============================================
    # Run graph
    # =============================================

    result = await graph.ainvoke({

        "messages": [
            message
        ]

    })

    # =============================================
    # Print result
    # =============================================

    print("\n")
    print("=" * 70)
    print("FINAL AGENT RESPONSE")
    print("=" * 70)

    final_message = (
        result["messages"][-1]
    )

    print(
        final_message.content
    )


if __name__ == "__main__":

    asyncio.run(
        main()
    )