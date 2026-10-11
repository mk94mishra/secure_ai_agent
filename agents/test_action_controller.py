
from unittest.mock import patch

from agents.action import action_controller_node


def build_state(tenant_id="default"):
    return {
        "tenant_id": tenant_id,
        "alert": {
            "alert_id": "CONTROLLER-TEST-001",
            "tenant_id": tenant_id,
            "instance_id": "i-mock123456789",
        },
        "risk": "HIGH",
        "confidence": 0.95,
        "approval_status": "APPROVED",
        "approved_by": "soc-analyst-001",
        "approval_reason": "Testing action controller",
        "recommended_action": "TAG_RESOURCE",
    }


def main():
    # Test 1: Allowed policy and successful audit write.
    print("Test 1: ALLOW + audit success")

    with patch("agents.action.record_audit_event") as audit:
        result = action_controller_node(build_state())

        print("Action status:", result["action_status"])
        print("Policy:", result["action_result"]["policy_decision"])

        assert result["action_status"] == "PENDING"
        assert result["action_result"]["policy_decision"] == "ALLOW"

        audit.assert_called_once()
        assert audit.call_args.kwargs["event_type"] == "POLICY_DECISION"
        assert audit.call_args.kwargs["status"] == "ALLOW"

    # Test 2: Unknown tenant must be denied.
    print("\nTest 2: DENY + audit success")

    with patch("agents.action.record_audit_event") as audit:
        result = action_controller_node(
            build_state(tenant_id="unknown-tenant")
        )

        print("Action status:", result["action_status"])
        print("Message:", result["action_message"])

        assert result["action_status"] == "DENIED"
        assert result["action_result"]["policy_decision"] == "DENY"

        audit.assert_called_once()
        assert audit.call_args.kwargs["status"] == "DENY"

    # Test 3: Audit failure must fail closed.
    print("\nTest 3: Audit failure")

    with patch(
        "agents.action.record_audit_event",
        side_effect=RuntimeError("Simulated DynamoDB failure"),
    ):
        result = action_controller_node(build_state())

        print("Action status:", result["action_status"])
        print("Message:", result["action_message"])

        assert result["action_status"] == "DENIED"
        assert result["action_result"]["audit_status"] == "FAILED"

    print("\nPASS: Action controller tests completed.")
    print("No AWS remediation was executed.")


if __name__ == "__main__":
    main()
