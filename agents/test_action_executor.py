
import asyncio
from unittest.mock import AsyncMock, patch

from agents.action import ActionRequest
from agents.action_executor import ActionExecutor
from storage.idempotency import (
    IdempotencyAlreadyCompleted,
    IdempotencyConflict,
)


def build_request():
    return ActionRequest(
        incident_id="EXECUTOR-TEST-001",
        tenant_id="default",
        action="TAG_RESOURCE",
        resource_id="i-mock123456789",
        risk="HIGH",
        confidence=0.95,
        approved_by="soc-analyst-001",
        approval_reason="Mock executor test",
        idempotency_key=(
            "default:EXECUTOR-TEST-001:TAG_RESOURCE:i-mock123456789"
        ),
    )


async def test_successful_execution():
    print("Test 1: Successful execution")

    request = build_request()
    executor = ActionExecutor()

    with (
        patch(
            "agents.action_executor.claim_idempotency"
        ) as claim,
        patch(
            "agents.action_executor.execute_tag_resource",
            new_callable=AsyncMock,
        ) as execute_mcp,
        patch(
            "agents.action_executor.mark_idempotency_success"
        ) as mark_success,
        patch(
            "agents.action_executor.mark_idempotency_failed"
        ) as mark_failed,
        patch(
            "agents.action_executor.record_audit_event"
        ),
    ):
        claim.return_value = None
        execute_mcp.return_value = {
            "status": "SUCCESS",
            "message": "Mock tag action completed",
        }

        result = await executor.execute(request)

        assert result["status"] == "SUCCESS", result
        execute_mcp.assert_awaited_once()
        mark_success.assert_called_once()
        mark_failed.assert_not_called()

    print("PASS: MCP called once; success persisted.")


async def test_completed_request_replay():
    print("\nTest 2: Completed request replay")

    request = build_request()
    executor = ActionExecutor()

    previous_result = {
        "status": "SUCCESS",
        "message": "Previously completed",
    }

    with (
        patch(
            "agents.action_executor.claim_idempotency",
            side_effect=IdempotencyAlreadyCompleted(
                previous_result
            ),
        ),
        patch(
            "agents.action_executor.execute_tag_resource",
            new_callable=AsyncMock,
        ) as execute_mcp,
        patch(
            "agents.action_executor.record_audit_event"
        ),
    ):
        result = await executor.execute(request)

        assert result["status"] == "SUCCESS", result
        assert result["idempotent_replay"] is True
        assert result["mcp_status"] == "NOT_EXECUTED"
        execute_mcp.assert_not_awaited()

    print("PASS: Replay returned without calling MCP.")


async def test_in_progress_conflict():
    print("\nTest 3: In-progress idempotency conflict")

    request = build_request()
    executor = ActionExecutor()

    with (
        patch(
            "agents.action_executor.claim_idempotency",
            side_effect=IdempotencyConflict(
                "Request already in progress"
            ),
        ),
        patch(
            "agents.action_executor.execute_tag_resource",
            new_callable=AsyncMock,
        ) as execute_mcp,
        patch(
            "agents.action_executor.record_audit_event"
        ),
    ):
        result = await executor.execute(request)

        assert result["status"] == "FAILED", result
        assert result.get("idempotency_conflict") is True
        execute_mcp.assert_not_awaited()

    print("PASS: Conflict blocked MCP execution.")


async def main():
    await test_successful_execution()
    await test_completed_request_replay()
    await test_in_progress_conflict()

    print("\nAll action executor tests passed.")
    print("No real AWS remediation was executed.")


if __name__ == "__main__":
    asyncio.run(main())
