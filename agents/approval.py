
import logging
import os
from typing import Any

from dotenv import load_dotenv
from langgraph.types import interrupt

from agents.state import AgentState
from storage.audit import record_audit_event

load_dotenv()

logger = logging.getLogger(__name__)

AUDIT_ACTOR = os.getenv("AUDIT_ACTOR", "secure-ai-agent")

APPROVED = "APPROVED"
REJECTED = "REJECTED"

ALLOWED_DECISIONS = {APPROVED, REJECTED}
HIGH_RISK_LEVELS = {"HIGH", "CRITICAL"}


def _record_approval_audit(
    *,
    tenant_id: str,
    incident_id: str,
    event_type: str,
    actor: str,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> str | None:
    """Best-effort audit logging; never log secrets or full evidence."""

    try:
        record_audit_event(
            tenant_id=tenant_id,
            event_type=event_type,
            incident_id=incident_id,
            actor=actor,
            status=status,
            message=message,
            details=details or {},
        )
        return None

    except Exception:
        logger.exception(
            "Approval audit write failed: incident=%s event=%s",
            incident_id,
            event_type,
        )
        return "Audit write failed for event " + event_type


def human_approval_node(state: AgentState) -> dict[str, Any]:
    alert = state.get("alert", {})
    risk = state.get("risk", "LOW")

    tenant_id = (
        state.get("tenant_id")
        or alert.get("tenant_id")
        or "default"
    )
    incident_id = alert.get("alert_id", "")

    if risk not in HIGH_RISK_LEVELS:
        return {
            "approval_status": "NOT_REQUIRED",
        }

    if not incident_id:
        raise ValueError("Alert ID is required for approval.")

    approval_request = {
        "type": "SECURITY_APPROVAL",
        "message": (
            "A high-risk security action requires human approval."
        ),
        "alert": alert,
        "risk": risk,
        "confidence": state.get("confidence", 0.0),
        "recommended_action": state.get("recommended_action", ""),
        "findings": state.get("findings", []),
        "evidence": state.get("evidence", []),
        "allowed_decisions": [APPROVED, REJECTED],
    }

    request_audit_error = _record_approval_audit(
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="APPROVAL_REQUESTED",
        actor=AUDIT_ACTOR,
        status="PENDING",
        message="High-risk alert sent for human approval.",
        details={
            "risk": risk,
            "confidence": state.get("confidence", 0.0),
            "recommended_action": state.get(
                "recommended_action", ""
            ),
        },
    )

    # LangGraph pauses here until the caller resumes the graph.
    decision = interrupt(approval_request)

    if not isinstance(decision, dict):
        raise ValueError("Approval decision must be a dictionary.")

    status = decision.get("status")
    approved_by = decision.get("approved_by")
    reason = decision.get("reason")

    if status not in ALLOWED_DECISIONS:
        raise ValueError(
            "Invalid approval status. Use APPROVED or REJECTED."
        )

    if not isinstance(approved_by, str) or not approved_by.strip():
        raise ValueError("approved_by is required.")

    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("Approval/rejection reason is required.")

    decision_audit_error = _record_approval_audit(
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_type="APPROVAL_DECISION",
        actor=approved_by,
        status=status,
        message="Human approval decision recorded.",
        details={
            "risk": risk,
            "reason": reason,
            "recommended_action": state.get(
                "recommended_action", ""
            ),
        },
    )

    result = {
        "approval_status": status,
        "approved_by": approved_by,
        "approval_reason": reason,
    }

    audit_errors = [
        error
        for error in (request_audit_error, decision_audit_error)
        if error
    ]

    if audit_errors:
        result["audit_errors"] = audit_errors

    return result


if __name__ == "__main__":
    print("SecureAI Guard approval node loaded.")
    print("Audit events: APPROVAL_REQUESTED, APPROVAL_DECISION")
