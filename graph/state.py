from typing import (
    TypedDict,
    List,
    Dict,
    Any
)

from langchain_core.messages import (
    BaseMessage
)


class AgentState(TypedDict, total=False):

    alert: Dict[str, Any]

    query: str

    context: List[Dict[str, Any]]

    findings: List[str]

    evidence: List[Dict[str, Any]]

    risk: str

    confidence: float

    recommended_action: str

    requires_approval: bool

    decision: str

    messages: List[BaseMessage]