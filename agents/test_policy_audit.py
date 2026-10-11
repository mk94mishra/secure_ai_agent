
from agents.action import (
    ActionRequest,
    validate_action_request,
)
from policy.engine import evaluate_action


def make_request(**overrides):
    values = {
        "incident_id": "POLICY-TEST-001",
        "tenant_id": "default",
        "action": "TAG_RESOURCE",
        "resource_id": "i-mock123456789",
        "risk": "HIGH",
        "confidence": 0.95,
        "approved_by": "soc-analyst-001",
        "approval_reason": "Testing policy",
        "idempotency_key": (
            "default:POLICY-TEST-001:TAG_RESOURCE:i-mock123456789"
        ),
    }
    values.update(overrides)
    return ActionRequest(**values)


def main():
    print("Testing policy ALLOW...")
    allowed_request = make_request()
    error = validate_action_request(allowed_request)
    assert error is None, error

    result = evaluate_action(allowed_request)
    print("Decision:", result.decision)
    print("Reason:", result.reason)
    assert result.decision == "ALLOW"

    print("\nTesting policy DENY for unknown tenant...")
    denied_request = make_request(tenant_id="unknown-tenant")
    result = evaluate_action(denied_request)
    print("Decision:", result.decision)
    print("Reason:", result.reason)
    assert result.decision == "DENY"

    print("\nPASS: Policy ALLOW and DENY checks passed.")
    print("No AWS remediation was executed.")


if __name__ == "__main__":
    main()
