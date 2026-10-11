from langchain_core.prompts import ChatPromptTemplate

from agents.llm import llm
from agents.state import AgentState


planner_prompt = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            """
You are a security investigation planner.

Given a security alert, create a concise
investigation query.

Focus on:
- affected resource
- suspicious activity
- AWS API activity
- security findings
- relevant investigation context

Do not perform any action.
Only create the investigation query.
"""
        ),
        (
            "human",
            """
Security Alert:

{alert}

Create the investigation query.
"""
        )
    ]
)


planner_chain = planner_prompt | llm


def planner_node(
    state: AgentState
):

    alert = state["alert"]

    response = planner_chain.invoke(
        {
            "alert": alert
        }
    )

    query = response.content

    return {
        "query": query
    }