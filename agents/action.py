
import logging
import os
from dataclasses import asdict, dataclass
from typing import Any, Literal

from dotenv import load_dotenv

from agents.state import AgentState
from policy.engine import evaluate_action, PolicyResult
from storage.audit import record_audit_event

load_dotenv()

logger = logging.getLogger(__name__)

AUDIT_ACTOR = os.getenv("AUDIT_ACTOR", "secure-ai-agent")

ActionType = Literal[
    "ISOLATE_INSTANCE",
    "BLOCK_IP",
    "DISABLE_ACCESS_KEY",
    "TAG_RESOURCE",
]


@dataclass
class ActionRequest:
    incident_id: str
    tenant_id: str
    action: str
    resource_id: str
    risk: str
    confidence: float
    approved_by: str
    approval_reason: str
    idempotency_key: str


@dataclass
class ActionResult:
    status: str
    message: str
    action: str = ""
    resource_id: str = ""
    idempotency_key: str = ""


def resolve_action(recommended_action: str) -> str | None:
    """
    Map recommendation text to an explicit supported action.
    Never pass arbitrary LLM output directly to AWS.
    """
    if not isinstance(recommended_action, str):
        return None

    text = recommended_action.strip().upper()

    if not text:
        return None

    # Match explicit action names first.
    allowed = {
        "ISOLATE_INSTANCE",
        "BLOCK_IP",
        "DISABLE_ACCESS_KEY",
        "TAG_RESOURCE",
    }

    for action in allowed:
        if action in text:
            return action

    # Only map unambiguous recommendation phrases.
    if "TAG_RESOURCE" in text or (
        "TAG" in text and "INSTANCE" in text
    ):
        return "TAG_RESOURCE"

    if "ISOLATE" in text and "INSTANCE" in text:
        return "ISOLATE_INSTANCE"

    if "BLOCK" in text and "IP" in text:
        return "BLOCK_IP"

    if "DISABLE" in text and "ACCESS KEY" in text:
        return "DISABLE_ACCESS_KEY"

    return None


def resolve_resource_id(
    state: AgentState,
    action: str,
) -> str | None:
    alert = state.get("alert", {})

    if action in {"ISOLATE_INSTANCE", "TAG_RESOURCE"}:
        return alert.get("instance_id")

    # These actions require their own validated resource mapping.
    # Do not guess resource IDs from arbitrary alert text.
    if action == "BLOCK_IP":
        return alert.get("source_ip")

    if action == "DISABLE_ACCESS_KEY":
        return alert.get("access_key_id")

    return None


def build_action_request(
    state: AgentState,
    action: str,
    resource_id: str,
) -> ActionRequest:
    alert = state.get("alert", {})

    incident_id = alert.get("alert_id", "")
    tenant_id = (
        state.get("tenant_id")
        or alert.get("tenant_id")
        or "default"
    )

    idempotency_key = (
        f"{tenant_id}:{incident_id}:{action}:{resource_id}"
    )

    return ActionRequest(
        incident_id=incident_id,
        tenant_id=tenant_id,
        action=action,
        resource_id=resource_id,
        risk=state.get("risk", "LOW"),
        confidence=state.get("confidence", 0.0),
        approved_by=state.get("approved_by", ""),
        approval_reason=state.get("approval_reason", ""),
        idempotency_key=idempotency_key,
    )


def validate_action_request(
    request: ActionRequest,
) -> str | None:
    required = {
        "incident_id": request.incident_id,
        "tenant_id": request.tenant_id,
        "action": request.action,
        "resource_id": request.resource_id,
        "approved_by": request.approved_by,
        "approval_reason": request.approval_reason,
        "idempotency_key": request.idempotency_key,
    }

    for field, value in required.items():
        if not isinstance(value, str) or not value.strip():
            return f"Required field '{field}' is missing."

    if request.action not in {
        "ISOLATE_INSTANCE",
        "BLOCK_IP",
        "DISABLE_ACCESS_KEY",
        "TAG_RESOURCE",
    }:
        return f"Unsupported action '{request.action}'."

    if request.risk not in {"HIGH", "CRITICAL"}:
        return "Only HIGH or CRITICAL risk actions are allowed."

    if (
        not isinstance(request.confidence, (int, float))
        or isinstance(request.confidence, bool)
        or not 0.0 <= request.confidence <= 1.0
    ):
        return "Confidence must be a number between 0.0 and 1.0."

    return None


def action_summary(request: ActionRequest) -> dict[str, Any]:
    return {
        "incident_id": request.incident_id,
        "tenant_id": request.tenant_id,
        "action": request.action,
        "resource_id": request.resource_id,
        "risk": request.risk,
        "confidence": request.confidence,
        "approved_by": request.approved_by,
        "idempotency_key": request.idempotency_key,
    }


def _record_policy_audit(
    request: ActionRequest,
    decision: str,
    reason: str,
) -> str | None:
    """Persist policy decision before allowing execution."""

    try:
        record_audit_event(
            tenant_id=request.tenant_id,
            event_type="POLICY_DECISION",
            incident_id=request.incident_id,
            actor=AUDIT_ACTOR,
            action=request.action,
            resource_id=request.resource_id,
            status=decision,
            message=reason,
            details={
                "risk": request.risk,
                "confidence": request.confidence,
                "approved_by": request.approved_by,
                "idempotency_key": request.idempotency_key,
            },
        )
        return None

    except Exception:
        logger.exception(
            "Policy audit persistence failed for incident %s",
            request.incident_id,
        )
        return "Policy decision could not be persisted to audit storage."


def _deny(
    message: str,
    *,
    action: str = "",
    resource_id: str = "",
) -> dict[str, Any]:
    return {
        "action_status": "DENIED",
        "action_message": message,
        "action_type": action,
        "action_resource_id": resource_id,
    }


def action_controller_node(
    state: AgentState,
) -> dict[str, Any]:
    """
    Deterministic action gate:
    approval -> action mapping -> validation -> policy -> audit -> PENDING.
    Actual execution happens only in action_executor_node.
    """
    alert = state.get("alert", {})
    tenant_id = (
        state.get("tenant_id")
        or alert.get("tenant_id")
        or "default"
    )
    incident_id = alert.get("alert_id", "")

    # Approval must be explicitly granted.
    if state.get("approval_status") != "APPROVED":
        return _deny("Human approval is required.")

    approved_by = state.get("approved_by", "")
    approval_reason = state.get("approval_reason", "")

    if not approved_by or not approval_reason:
        return _deny(
            "Approved analyst identity and approval reason are required."
        )

    recommended_action = state.get("recommended_action", "")
    action = resolve_action(recommended_action)

    if not action:
        return _deny(
            "Recommended action could not be mapped to a supported action."
        )

    resource_id = resolve_resource_id(state, action)

    if not resource_id:
        return _deny(
            f"No valid resource mapping is available for {action}.",
            action=action,
        )

    request = build_action_request(
        state=state,
        action=action,
        resource_id=resource_id,
    )

    validation_error = validate_action_request(request)

    if validation_error:
        # Audit malformed/invalid requests as a denial where possible.
        audit_error = _record_policy_audit(
            request,
            "DENY",
            validation_error,
        )

        result = _deny(
            validation_error,
            action=action,
            resource_id=resource_id,
        )

        if audit_error:
            result["audit_error"] = audit_error

        return result

    # Evaluate deterministic policy; the LLM cannot override this result.
    try:
        policy_result: PolicyResult = evaluate_action(request)
    except Exception:
        logger.exception(
            "Policy evaluation failed for incident %s",
            incident_id,
        )
        return _deny(
            "Policy evaluation failed; action execution is blocked.",
            action=action,
            resource_id=resource_id,
        )

    decision = policy_result.decision
    reason = policy_result.reason

    # Persist the decision before moving to the executor.
    audit_error = _record_policy_audit(
        request,
        decision,
        reason,
    )

    if audit_error:
        return {
            **_deny(
                audit_error,
                action=action,
                resource_id=resource_id,
            ),
            "action_result": {
                "policy_decision": decision,
                "policy_reason": reason,
                "audit_status": "FAILED",
            },
        }

    if decision != "ALLOW":
        return {
            **_deny(
                reason,
                action=action,
                resource_id=resource_id,
            ),
            "action_result": {
                "policy_decision": decision,
                "policy_reason": reason,
                "audit_status": "RECORDED",
            },
        }

    return {
        "action_status": "PENDING",
        "action_message": "Policy allowed the action; ready for execution.",
        "action_type": action,
        "action_resource_id": resource_id,
        "action_idempotency_key": request.idempotency_key,
        "action_result": {
            "policy_decision": decision,
            "policy_reason": reason,
            "request": action_summary(request),
            "audit_status": "RECORDED",
        },
    }


if __name__ == "__main__":
    print("SecureAI Guard action controller loaded.")
    print("Policy audit integration: enabled")
    print("Execution is delegated to agents.action_executor.")
