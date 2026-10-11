import logging
import os
from typing import Any

from dotenv import load_dotenv

from agents.action import ActionRequest
from agents.action_mcp import execute_tag_resource
from agents.state import AgentState

from storage.idempotency import (
    IdempotencyAlreadyCompleted,
    IdempotencyConflict,
    claim_idempotency,
    mark_idempotency_success,
    mark_idempotency_failed,
)

from storage.audit import record_audit_event


load_dotenv()

logger = logging.getLogger(__name__)

AUDIT_ACTOR = os.getenv("AUDIT_ACTOR", "secure-ai-agent")


def _audit(
    request: ActionRequest,
    event_type: str,
    *,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> str | None:
    """
    Best-effort audit logging.

    Audit failure must never cause an already executed AWS action
    to be executed again.
    """
    try:
        record_audit_event(
            tenant_id=request.tenant_id,
            event_type=event_type,
            incident_id=request.incident_id,
            actor=AUDIT_ACTOR,
            action=request.action,
            resource_id=request.resource_id,
            status=status,
            message=message,
            details=details or {},
        )
        return None

    except Exception as exc:
        logger.exception(
            "Audit write failed: event=%s incident=%s",
            event_type,
            request.incident_id,
        )
        return str(exc)


def _result(
    status: str,
    message: str,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "status": status,
        "message": message,
        **extra,
    }


class ActionExecutor:
    """
    Executes policy-approved security actions through Action MCP.

    Safety guarantees:
    - DynamoDB idempotency claim before execution.
    - Completed actions are replayed without another AWS call.
    - Concurrent/in-progress requests are rejected.
    - Audit failures do not trigger AWS action retries.
    """

    async def execute(self, request: ActionRequest) -> dict[str, Any]:
        validation_error = self._validate_request(request)

        if validation_error:
            result = _result(
                "FAILED",
                validation_error,
            )

            audit_error = _audit(
                request,
                "ACTION_FAILED",
                status="FAILED",
                message=validation_error,
                details={"stage": "validation"},
            )

            if audit_error:
                result["audit_error"] = audit_error

            return result

        # Record that the action was requested.
        audit_error = _audit(
            request,
            "ACTION_REQUESTED",
            status="PENDING",
            message="Approved action received by the executor.",
            details={
                "idempotency_key": request.idempotency_key,
                "risk": request.risk,
                "confidence": request.confidence,
                "approved_by": request.approved_by,
            },
        )

        try:
            # Claim the idempotency key BEFORE calling Action MCP.
            claim_idempotency(
                idempotency_key=request.idempotency_key,
                incident_id=request.incident_id,
                tenant_id=request.tenant_id,
                action=request.action,
                resource_id=request.resource_id,
            )

        except IdempotencyAlreadyCompleted as exc:
            # A completed action must never execute again.
            result = _result(
                "SUCCESS",
                "Previously completed action returned; AWS was not called again.",
                idempotent_replay=True,
                mcp_status="NOT_EXECUTED",
                previous_result=getattr(exc, "result", None),
            )

            replay_audit_error = _audit(
                request,
                "ACTION_REQUESTED",
                status="IDEMPOTENT_REPLAY",
                message="Previously completed action returned without re-execution.",
                details={
                    "idempotency_key": request.idempotency_key,
                    "idempotent_replay": True,
                },
            )

            if audit_error or replay_audit_error:
                result["audit_error"] = (
                    replay_audit_error or audit_error
                )

            return result

        except IdempotencyConflict as exc:
            message = (
                "Idempotency conflict: this action is already in progress "
                "or has a non-replayable existing record."
            )

            result = _result(
                "FAILED",
                message,
                idempotency_conflict=True,
            )

            conflict_audit_error = _audit(
                request,
                "ACTION_FAILED",
                status="FAILED",
                message=message,
                details={
                    "idempotency_key": request.idempotency_key,
                    "error_type": type(exc).__name__,
                },
            )

            if audit_error or conflict_audit_error:
                result["audit_error"] = (
                    conflict_audit_error or audit_error
                )

            return result

        except Exception as exc:
            logger.exception(
                "Unable to claim idempotency key for incident %s",
                request.incident_id,
            )

            message = "Unable to claim idempotency key; action was not executed."

            result = _result(
                "FAILED",
                message,
                error_type=type(exc).__name__,
                mcp_status="NOT_EXECUTED",
            )

            failure_audit_error = _audit(
                request,
                "ACTION_FAILED",
                status="FAILED",
                message=message,
                details={"stage": "idempotency_claim"},
            )

            if audit_error or failure_audit_error:
                result["audit_error"] = (
                    failure_audit_error or audit_error
                )

            return result

        # The key has been claimed. Record execution start.
        started_audit_error = _audit(
            request,
            "ACTION_STARTED",
            status="IN_PROGRESS",
            message="Security action execution started.",
            details={
                "idempotency_key": request.idempotency_key,
            },
        )

        try:
            execution_result = await self._dispatch_action(request)
            normalized = self._normalize_result(execution_result)

        except Exception as exc:
            logger.exception(
                "Action execution failed for incident %s",
                request.incident_id,
            )

            normalized = _result(
                "FAILED",
                "Action MCP execution raised an exception.",
                error_type=type(exc).__name__,
            )

        # Persist the result before returning it.
        if normalized["status"] == "SUCCESS":
            try:
                mark_idempotency_success(
                    request.idempotency_key,
                    normalized,
                )

            except Exception as exc:
                # AWS may already have completed the action.
                # Never execute it again just because this write failed.
                logger.exception(
                    "AWS action may have succeeded, but idempotency "
                    "success persistence failed for incident %s",
                    request.incident_id,
                )

                normalized["idempotency_error"] = str(exc)
                normalized["idempotency_persistence"] = "FAILED"

            completed_audit_error = _audit(
                request,
                "ACTION_COMPLETED",
                status="SUCCESS",
                message=normalized.get(
                    "message",
                    "Security action completed successfully.",
                ),
                details={
                    "idempotency_key": request.idempotency_key,
                    "idempotency_persistence": normalized.get(
                        "idempotency_persistence",
                        "SUCCESS",
                    ),
                    "mcp_status": normalized.get("mcp_status"),
                },
            )

            for error in (
                audit_error,
                started_audit_error,
                completed_audit_error,
            ):
                if error:
                    normalized.setdefault("audit_errors", []).append(error)

            return normalized

        # The action returned a failure.
        try:
            mark_idempotency_failed(
                request.idempotency_key,
                normalized,
            )

        except Exception as exc:
            logger.exception(
                "Failed to persist action failure for incident %s",
                request.incident_id,
            )
            normalized["idempotency_error"] = str(exc)

        failed_audit_error = _audit(
            request,
            "ACTION_FAILED",
            status="FAILED",
            message=normalized.get(
                "message",
                "Security action execution failed.",
            ),
            details={
                "idempotency_key": request.idempotency_key,
                "error_type": normalized.get("error_type"),
                "mcp_status": normalized.get("mcp_status"),
            },
        )

        for error in (
            audit_error,
            started_audit_error,
            failed_audit_error,
        ):
            if error:
                normalized.setdefault("audit_errors", []).append(error)

        return normalized

    async def _dispatch_action(
        self,
        request: ActionRequest,
    ) -> dict[str, Any]:
        """
        Allow only explicitly implemented actions.

        Add additional actions here only after their MCP tools,
        validation and safety controls are implemented.
        """
        if request.action == "TAG_RESOURCE":
            return await self._execute_tag_resource(request)

        return _result(
            "FAILED",
            f"Action '{request.action}' is not implemented by the executor.",
            mcp_status="NOT_EXECUTED",
        )

    async def _execute_tag_resource(
        self,
        request: ActionRequest,
    ) -> dict[str, Any]:
        response = await execute_tag_resource(
            instance_id=request.resource_id,
            tag_key="SecurityAction",
            tag_value="AI-REMEDIATED",
        )

        return self._normalize_result(response)

    @staticmethod
    def _normalize_result(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            result = dict(value)
        else:
            result = {
                "message": str(value),
            }

        raw_status = str(result.get("status", "")).upper()

        if raw_status in {"SUCCESS", "SUCCEEDED", "COMPLETED"}:
            result["status"] = "SUCCESS"

        elif raw_status in {"FAILED", "FAILURE", "ERROR", "DENIED"}:
            result["status"] = "FAILED"

        elif result.get("isError") is True:
            result["status"] = "FAILED"

        else:
            # Unknown responses must fail closed.
            result["status"] = "FAILED"
            result.setdefault(
                "message",
                "Action MCP returned an unrecognized result.",
            )

        result.setdefault(
            "message",
            "Action execution completed."
            if result["status"] == "SUCCESS"
            else "Action execution failed.",
        )

        return result

    @staticmethod
    def _validate_request(
        request: ActionRequest,
    ) -> str | None:
        required_fields = {
            "incident_id": request.incident_id,
            "tenant_id": request.tenant_id,
            "action": request.action,
            "resource_id": request.resource_id,
            "approved_by": request.approved_by,
            "approval_reason": request.approval_reason,
            "idempotency_key": request.idempotency_key,
        }

        for field_name, value in required_fields.items():
            if not isinstance(value, str) or not value.strip():
                return f"Required field '{field_name}' is missing."

        if request.risk not in {"HIGH", "CRITICAL"}:
            return "Only HIGH or CRITICAL risk actions are allowed."

        if not isinstance(request.confidence, (int, float)):
            return "Risk confidence must be numeric."

        if not 0.0 <= request.confidence <= 1.0:
            return "Risk confidence must be between 0.0 and 1.0."

        if request.action not in {
            "TAG_RESOURCE",
            "ISOLATE_INSTANCE",
            "BLOCK_IP",
            "DISABLE_ACCESS_KEY",
        }:
            return f"Unsupported action '{request.action}'."

        return None


action_executor = ActionExecutor()


async def execute_action(
    request: ActionRequest,
) -> dict[str, Any]:
    return await action_executor.execute(request)


async def action_executor_node(
    state: AgentState,
) -> dict[str, Any]:
    if state.get("action_status") != "PENDING":
        return {
            "action_status": "FAILED",
            "action_message": "Action is not in PENDING state.",
        }

    if state.get("approval_status") != "APPROVED":
        return {
            "action_status": "DENIED",
            "action_message": "Human approval is required.",
        }

    alert = state.get("alert", {})
    tenant_id = state.get(
        "tenant_id",
        alert.get("tenant_id", "default"),
    )

    request = ActionRequest(
        incident_id=alert.get("alert_id", ""),
        tenant_id=tenant_id,
        action=state.get("action_type", ""),
        resource_id=state.get("action_resource_id", ""),
        risk=state.get("risk", "LOW"),
        confidence=state.get("confidence", 0.0),
        approved_by=state.get("approved_by", ""),
        approval_reason=state.get("approval_reason", ""),
        idempotency_key=state.get("action_idempotency_key", ""),
    )

    result = await execute_action(request)

    return {
        "action_status": result.get("status", "FAILED"),
        "action_message": result.get("message", ""),
        "action_result": result,
    }


if __name__ == "__main__":
    print("SecureAI Guard Action Executor loaded.")
    print("Supported executor action: TAG_RESOURCE")
    print("Audit integration: enabled")
    print("DynamoDB idempotency integration: enabled")
