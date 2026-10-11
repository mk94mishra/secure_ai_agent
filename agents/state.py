from typing import Any, Annotated, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict, total=False):
    # ============================================================
    # Conversation / LangGraph Messages
    # ============================================================

    messages: Annotated[list[BaseMessage], add_messages]

    # ============================================================
    # Alert
    # ============================================================

    alert: dict[str, Any]

    # ============================================================
    # Planning
    # ============================================================

    query: str

    # ============================================================
    # RAG
    # ============================================================

    context: list[dict[str, Any]]

    # ============================================================
    # Investigation
    # ============================================================

    findings: list[str]

    evidence: list[dict[str, Any]]

    investigation_iterations: int

    # ============================================================
    # Risk Assessment
    # ============================================================

    risk: str

    confidence: float

    recommended_action: str

    requires_approval: bool

    # ============================================================
    # Human Approval
    # ============================================================

    approval_status: str

    approved_by: str

    approval_reason: str

    # ============================================================
    # Action Controller
    # ============================================================

    action_status: str

    action_message: str

    # ============================================================
    # Action Execution
    # ============================================================

    action_type: str

    action_resource_id: str

    action_idempotency_key: str

    action_result: dict[str, Any]

    # ============================================================
    # Final Response
    # ============================================================

    final_response: str