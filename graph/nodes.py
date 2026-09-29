from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel

from llm import llm


class InvestigationPlan(BaseModel):

    query: str


planner_prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are an enterprise SOC investigation planner.

        Analyze the security alert and create one concise
        investigation query for retrieving relevant
        security knowledge.

        Do not invent facts.
        """
    ),
    (
        "human",
        """
        Security Alert:

        {alert}
        """
    )
])


planner_chain = (
    planner_prompt
    | llm.with_structured_output(
        InvestigationPlan
    )
)


def planner_node(state):

    alert = state["alert"]

    result = planner_chain.invoke({
        "alert": str(alert)
    })

    return {
        "query": result.query
    }


from rag.hybrid_search import hybrid_rerank_search


def rag_node(state):

    query = state["query"]

    documents = hybrid_rerank_search(
        query=query,
        candidate_k=20,
        top_k=5
    )

    return {
        "context": documents
    }

class InvestigationResult(BaseModel):

    findings: list[str]
    evidence: list[dict]

investigation_prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are an enterprise SOC security analyst.

        Investigate the security alert using ONLY:
        1. The alert
        2. Retrieved security knowledge

        Do not invent evidence.

        Identify:
        - suspicious behavior
        - relevant security findings
        - supporting evidence
        """
    ),
    (
        "human",
        """
        Security Alert:

        {alert}


        Retrieved Knowledge:

        {context}
        """
    )
])


investigation_chain = (
    investigation_prompt
    | llm.with_structured_output(
        InvestigationResult
    )
)


from langchain_core.messages import (
    HumanMessage
)

from llm import llm_with_tools


def investigation_agent_node(state):

    alert = state["alert"]

    context = state.get(
        "context",
        []
    )

    messages = state.get(
        "messages",
        []
    )

    if not messages:

        messages = [
            HumanMessage(
                content=f"""
                    You are an enterprise SOC investigation agent.

                    Investigate the following security alert.

                    You have access to:
                    - RAG security knowledge
                    - AWS investigation tools

                    Use AWS tools when actual AWS
                    environment information is required.

                    Do not invent AWS facts.

                    Security Alert:

                    {alert}

                    Knowledge Base Context:

                    {context}

                    Investigate the incident.
                    """
            )
        ]

    response = llm_with_tools.invoke(
        messages
    )

    return {
        "messages": messages + [
            response
        ]
    }


from typing import Literal


class RiskAssessment(BaseModel):

    risk: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    confidence: float

    recommended_action: str

risk_prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are a senior SOC risk analyst.

        Assess security risk based only on the
        provided alert, findings and evidence.

        Do not invent facts.

        HIGH and CRITICAL incidents may require
        human approval before taking disruptive actions.
        """
    ),
    (
        "human",
        """
        Alert:

        {alert}

        Findings:

        {findings}

        Evidence:

        {evidence}
        """
    )
])


risk_chain = (
    risk_prompt
    | llm.with_structured_output(
        RiskAssessment
    )
)


def risk_node(state):

    result = risk_chain.invoke({
        "alert": str(state["alert"]),
        "findings": str(state["findings"]),
        "evidence": str(state["evidence"])
    })

    requires_approval = result.risk in [
        "HIGH",
        "CRITICAL"
    ]

    return {
        "risk": result.risk,
        "confidence": result.confidence,
        "recommended_action": result.recommended_action,
        "requires_approval": requires_approval
    }

def route_after_risk(state):

    if state["requires_approval"]:
        return "human_approval"

    return "recommendation"

