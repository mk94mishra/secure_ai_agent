
"""Defense-in-depth security checks for SecureAI Guard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


# Only actions with a verified implementation are enabled.
# Currently TAG_RESOURCE is the only implemented AWS write action.
ALLOWED_ACTIONS = frozenset({"TAG_RESOURCE"})

ALLOWED_RISKS = frozenset({
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
})

TENANT_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
)

RESOURCE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:/+=,@-]{0,255}$"
)

IDEMPOTENCY_KEY_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9:._-]{7,255}$"
)


class GuardrailViolation(ValueError):
    """Raised when a security validation fails."""


@dataclass(frozen=True)
class ActionBoundaryPolicy:
    # Development-only allowlist.
    allowed_tenants: frozenset[str] = frozenset({"default"})

    allowed_actions: frozenset[str] = ALLOWED_ACTIONS

    minimum_confidence: float = 0.60

    approval_required_for: frozenset[str] = frozenset({
        "HIGH",
        "CRITICAL",
    })


def _required_string(
    value: Any,
    field: str,
    max_length: int = 512,
) -> str:
    if not isinstance(value, str):
        raise GuardrailViolation(
            f"{field} must be a string"
        )

    value = value.strip()

    if not value or len(value) > max_length:
        raise GuardrailViolation(
            f"{field} is empty or exceeds the allowed length"
        )

    return value


def enforce_action_boundary(
    request: Any,
    *,
    policy: ActionBoundaryPolicy | None = None,
    allowed_resource_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Validate an action request before allowing execution."""

    policy = policy or ActionBoundaryPolicy()

    def get(field: str, default: Any = None) -> Any:
        if isinstance(request, Mapping):
            return request.get(field, default)

        return getattr(request, field, default)

    # 1. Tenant authorization
    tenant_id = _required_string(
        get("tenant_id"),
        "tenant_id",
        64,
    )

    if not TENANT_ID_PATTERN.fullmatch(tenant_id):
        raise GuardrailViolation(
            "Invalid tenant ID format"
        )

    if tenant_id not in policy.allowed_tenants:
        raise GuardrailViolation(
            "Tenant is not authorized"
        )

    # 2. Action allowlist
    action = _required_string(
        get("action"),
        "action",
        64,
    ).upper()

    if action not in policy.allowed_actions:
        raise GuardrailViolation(
            f"Action is not enabled: {action}"
        )

    # 3. Resource identifier validation
    resource_id = _required_string(
        get("resource_id"),
        "resource_id",
        256,
    )

    if not RESOURCE_ID_PATTERN.fullmatch(resource_id):
        raise GuardrailViolation(
            "Invalid resource ID format"
        )

    # Optional caller-provided resource allowlist.
    if (
        allowed_resource_ids is not None
        and resource_id not in allowed_resource_ids
    ):
        raise GuardrailViolation(
            "Resource is not authorized"
        )

    # 4. Risk validation
    risk = _required_string(
        get("risk"),
        "risk",
        16,
    ).upper()

    if risk not in ALLOWED_RISKS:
        raise GuardrailViolation(
            "Invalid risk level"
        )

    # 5. Confidence validation
    confidence = get("confidence")

    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
    ):
        raise GuardrailViolation(
            "Confidence must be numeric"
        )

    confidence = float(confidence)

    if not 0.0 <= confidence <= 1.0:
        raise GuardrailViolation(
            "Confidence must be between 0 and 1"
        )

    if confidence < policy.minimum_confidence:
        raise GuardrailViolation(
            "Confidence is below the minimum threshold"
        )

    # 6. Incident and idempotency validation
    incident_id = _required_string(
        get("incident_id"),
        "incident_id",
        256,
    )

    idempotency_key = _required_string(
        get("idempotency_key"),
        "idempotency_key",
        256,
    )

    if not IDEMPOTENCY_KEY_PATTERN.fullmatch(
        idempotency_key
    ):
        raise GuardrailViolation(
            "Invalid idempotency key format"
        )

    # 7. Human approval validation
    approval_status = get("approval_status")
    approved_by = get("approved_by")
    approval_reason = get("approval_reason")

    if risk in policy.approval_required_for:
        if approval_status != "APPROVED":
            raise GuardrailViolation(
                "HIGH/CRITICAL actions require approval"
            )

        if (
            not isinstance(approved_by, str)
            or not approved_by.strip()
        ):
            raise GuardrailViolation(
                "Approver identity is required"
            )

        if (
            not isinstance(approval_reason, str)
            or not approval_reason.strip()
        ):
            raise GuardrailViolation(
                "Approval reason is required"
            )

    return {
        "tenant_id": tenant_id,
        "action": action,
        "resource_id": resource_id,
        "risk": risk,
        "confidence": confidence,
        "incident_id": incident_id,
        "idempotency_key": idempotency_key,
        "approved_by": (
            approved_by.strip()
            if isinstance(approved_by, str)
            else None
        ),
        "approval_reason": (
            approval_reason.strip()
            if isinstance(approval_reason, str)
            else None
        ),
    }
