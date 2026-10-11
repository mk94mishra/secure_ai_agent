from dataclasses import dataclass
from typing import Literal

from policy.models import ActionRequest


# ============================================================
# POLICY DECISION
# ============================================================

PolicyDecision = Literal[
    "ALLOW",
    "DENY",
]


# ============================================================
# POLICY RESULT
# ============================================================

@dataclass
class PolicyResult:
    """
    Result returned by the Policy Engine.

    The Policy Engine does not execute AWS actions.
    """

    decision: PolicyDecision

    reason: str

    action: str

    resource_id: str

    tenant_id: str

    idempotency_key: str


# ============================================================
# POLICY CONFIGURATION
# ============================================================

# Actions that the platform understands.
#
# Actual AWS execution will be handled by Action MCP.

ALLOWED_ACTIONS = {
    "ISOLATE_INSTANCE",
    "BLOCK_IP",
    "DISABLE_ACCESS_KEY",
    "TAG_RESOURCE",
}


# ============================================================
# HIGH-RISK ACTIONS
# ============================================================

HIGH_RISK_ACTIONS = {
    "ISOLATE_INSTANCE",
    "BLOCK_IP",
    "DISABLE_ACCESS_KEY",
}


# ============================================================
# MINIMUM CONFIDENCE
# ============================================================

MINIMUM_CONFIDENCE = 0.60


# ============================================================
# POLICY ENGINE
# ============================================================

class PolicyEngine:
    """
    Security policy enforcement layer.

    Responsibilities:

    - Validate action
    - Validate tenant
    - Validate approval
    - Validate risk
    - Validate confidence
    - Validate resource
    - Produce ALLOW / DENY decision

    This class NEVER calls AWS.
    """

    def __init__(
        self,
        allowed_tenants: set[str] | None = None,
    ):
        if allowed_tenants is None:

            allowed_tenants = {
                "default",
            }

        self.allowed_tenants = (
            allowed_tenants
        )

    # ========================================================
    # MAIN EVALUATION
    # ========================================================

    def evaluate(
        self,
        request: ActionRequest,
    ) -> PolicyResult:
        """
        Evaluate an ActionRequest.

        Returns:

            PolicyResult(
                decision="ALLOW"
            )

        or:

            PolicyResult(
                decision="DENY"
            )
        """

        # ----------------------------------------------------
        # Tenant validation
        # ----------------------------------------------------

        if not request.tenant_id:

            return self._deny(
                request,
                "Tenant ID is required.",
            )

        if request.tenant_id not in (
            self.allowed_tenants
        ):

            return self._deny(
                request,
                "Tenant is not allowed to perform "
                "security actions.",
            )

        # ----------------------------------------------------
        # Action validation
        # ----------------------------------------------------

        if request.action not in (
            ALLOWED_ACTIONS
        ):

            return self._deny(
                request,
                f"Action '{request.action}' "
                f"is not allowed.",
            )

        # ----------------------------------------------------
        # Resource validation
        # ----------------------------------------------------

        if not request.resource_id:

            return self._deny(
                request,
                "Resource ID is required.",
            )

        # ----------------------------------------------------
        # Risk validation
        # ----------------------------------------------------

        if request.risk not in {
            "HIGH",
            "CRITICAL",
        }:

            return self._deny(
                request,
                (
                    "Security remediation is only "
                    "allowed for HIGH or CRITICAL risk."
                ),
            )

        # ----------------------------------------------------
        # Confidence validation
        # ----------------------------------------------------

        if (
            request.confidence
            < MINIMUM_CONFIDENCE
        ):

            return self._deny(
                request,
                (
                    f"Risk confidence "
                    f"{request.confidence:.2f} is below "
                    f"the minimum required confidence "
                    f"{MINIMUM_CONFIDENCE:.2f}."
                ),
            )

        # ----------------------------------------------------
        # Human approval validation
        # ----------------------------------------------------

        if not request.approved_by:

            return self._deny(
                request,
                "Human approval is required.",
            )

        # ----------------------------------------------------
        # Idempotency validation
        # ----------------------------------------------------

        if not request.idempotency_key:

            return self._deny(
                request,
                "Idempotency key is required.",
            )

        # ----------------------------------------------------
        # High-risk action checks
        # ----------------------------------------------------

        if request.action in (
            HIGH_RISK_ACTIONS
        ):

            if not request.approval_reason:

                return self._deny(
                    request,
                    (
                        "Approval reason is required "
                        "for high-risk actions."
                    ),
                )

        # ----------------------------------------------------
        # ALL CHECKS PASSED
        # ----------------------------------------------------

        return PolicyResult(
            decision="ALLOW",

            reason=(
                "Action passed all policy checks."
            ),

            action=request.action,

            resource_id=request.resource_id,

            tenant_id=request.tenant_id,

            idempotency_key=(
                request.idempotency_key
            ),
        )

    # ========================================================
    # DENY HELPER
    # ========================================================

    @staticmethod
    def _deny(
        request: ActionRequest,
        reason: str,
    ) -> PolicyResult:

        return PolicyResult(
            decision="DENY",

            reason=reason,

            action=request.action,

            resource_id=request.resource_id,

            tenant_id=request.tenant_id,

            idempotency_key=(
                request.idempotency_key
            ),
        )


# ============================================================
# DEFAULT POLICY ENGINE
# ============================================================

policy_engine = PolicyEngine(
    allowed_tenants={
        "default",
    }
)


# ============================================================
# PUBLIC HELPER
# ============================================================

def evaluate_action(
    request: ActionRequest,
) -> PolicyResult:
    """
    Evaluate an action using the default policy engine.
    """

    return policy_engine.evaluate(
        request
    )