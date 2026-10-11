import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any
import math
from decimal import Decimal

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv



def _to_dynamodb_safe(value: Any) -> Any:
    """Convert Python floats recursively for DynamoDB serialization."""

    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Audit data cannot contain NaN or infinity.")
        return Decimal(str(value))

    if isinstance(value, dict):
        return {
            key: _to_dynamodb_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_to_dynamodb_safe(item) for item in value]

    return value


# ============================================================
# Environment
# ============================================================

load_dotenv()

AWS_REGION = os.getenv(
    "AWS_REGION",
    "us-east-1",
)

AUDIT_TABLE_NAME = os.getenv(
    "AUDIT_TABLE_NAME",
    "secure-ai-audit",
)


# ============================================================
# DynamoDB
# ============================================================

dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION,
)

table = dynamodb.Table(
    AUDIT_TABLE_NAME
)


# ============================================================
# Audit Event Types
# ============================================================

AUDIT_EVENT_TYPES = {
    "ALERT_RECEIVED",
    "INVESTIGATION_STARTED",
    "INVESTIGATION_COMPLETED",
    "RISK_ASSESSED",
    "APPROVAL_REQUESTED",
    "APPROVAL_DECISION",
    "POLICY_DECISION",
    "ACTION_REQUESTED",
    "ACTION_STARTED",
    "ACTION_COMPLETED",
    "ACTION_FAILED",
}


# ============================================================
# Audit Store
# ============================================================

class AuditStore:
    """
    DynamoDB-backed security audit trail.

    Table design:

        PK:
            tenant_id

        SK:
            event_id

    Every security event gets a unique event_id.

    Example:

        tenant_id = default

        event_id =
            2026-10-10T12:30:00Z#uuid

    The complete security event is stored as a
    JSON-compatible DynamoDB item.
    """

    def __init__(
        self,
        dynamodb_table=None,
    ):
        self.table = (
            dynamodb_table
            or table
        )

    # ========================================================
    # Create Audit Event
    # ========================================================

    def record(
        self,
        *,
        tenant_id: str,
        event_type: str,
        incident_id: str,
        actor: str,
        action: str | None = None,
        resource_id: str | None = None,
        status: str | None = None,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Write a security audit event.

        This method does not overwrite an existing event because
        every event receives a unique event_id.
        """

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        if not tenant_id:
            raise ValueError(
                "tenant_id is required."
            )

        if not event_type:
            raise ValueError(
                "event_type is required."
            )

        if event_type not in AUDIT_EVENT_TYPES:
            raise ValueError(
                f"Unsupported audit event type: "
                f"{event_type}"
            )

        if not incident_id:
            raise ValueError(
                "incident_id is required."
            )

        if not actor:
            raise ValueError(
                "actor is required."
            )

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        now = datetime.now(
            timezone.utc
        )

        timestamp = (
            now.isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )

        epoch_time = int(
            time.time()
        )

        # ----------------------------------------------------
        # Unique event ID
        # ----------------------------------------------------

        event_id = (
            f"{timestamp}#"
            f"{uuid.uuid4()}"
        )

        # ----------------------------------------------------
        # Build event
        # ----------------------------------------------------

        event = {
            "tenant_id": tenant_id,
            "event_id": event_id,
            "event_type": event_type,
            "incident_id": incident_id,
            "actor": actor,
            "timestamp": timestamp,
            "epoch_time": epoch_time,
        }

        if action is not None:
            event["action"] = action

        if resource_id is not None:
            event["resource_id"] = resource_id

        if status is not None:
            event["status"] = status

        if message is not None:
            event["message"] = message

        if details:
            event["details"] = details

        # ----------------------------------------------------
        # DynamoDB write
        # ----------------------------------------------------

        self.table.put_item(
             Item=_to_dynamodb_safe(event)
        )

        return event

    # ========================================================
    # Get Incident Audit
    # ========================================================

    def get_incident_events(
        self,
        tenant_id: str,
        incident_id: str,
    ) -> list[dict[str, Any]]:
        """
        Retrieve all audit events for an incident.

        Because incident_id is not the primary partition key,
        this uses a FilterExpression.

        For production scale, create a GSI:

            GSI:
                tenant_id
                incident_id#timestamp
        """

        if not tenant_id:
            raise ValueError(
                "tenant_id is required."
            )

        if not incident_id:
            raise ValueError(
                "incident_id is required."
            )

        events: list[dict[str, Any]] = []

        response = self.table.scan(
            FilterExpression=(
                "tenant_id = :tenant_id "
                "AND incident_id = :incident_id"
            ),
            ExpressionAttributeValues={
                ":tenant_id": tenant_id,
                ":incident_id": incident_id,
            },
        )

        events.extend(
            response.get(
                "Items",
                [],
            )
        )

        # ----------------------------------------------------
        # Pagination
        # ----------------------------------------------------

        while (
            "LastEvaluatedKey"
            in response
        ):

            response = self.table.scan(
                FilterExpression=(
                    "tenant_id = :tenant_id "
                    "AND incident_id = :incident_id"
                ),
                ExpressionAttributeValues={
                    ":tenant_id": tenant_id,
                    ":incident_id": incident_id,
                },
                ExclusiveStartKey=(
                    response[
                        "LastEvaluatedKey"
                    ]
                ),
            )

            events.extend(
                response.get(
                    "Items",
                    [],
                )
            )

        # ----------------------------------------------------
        # Sort chronologically
        # ----------------------------------------------------

        events.sort(
            key=lambda item: item.get(
                "timestamp",
                "",
            )
        )

        return events


# ============================================================
# Singleton
# ============================================================

audit_store = AuditStore()


# ============================================================
# Convenience Functions
# ============================================================

def record_audit_event(
    *,
    tenant_id: str,
    event_type: str,
    incident_id: str,
    actor: str,
    action: str | None = None,
    resource_id: str | None = None,
    status: str | None = None,
    message: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:

    return audit_store.record(
        tenant_id=tenant_id,
        event_type=event_type,
        incident_id=incident_id,
        actor=actor,
        action=action,
        resource_id=resource_id,
        status=status,
        message=message,
        details=details,
    )


def get_incident_audit(
    tenant_id: str,
    incident_id: str,
) -> list[dict[str, Any]]:

    return audit_store.get_incident_events(
        tenant_id=tenant_id,
        incident_id=incident_id,
    )


# ============================================================
# Local Test
# ============================================================

def main():

    print(
        "Audit Store loaded successfully."
    )

    print(
        f"Region: {AWS_REGION}"
    )

    print(
        f"Table: {AUDIT_TABLE_NAME}"
    )

    print(
        "Supported events:"
    )

    for event_type in sorted(
        AUDIT_EVENT_TYPES
    ):
        print(
            f"  - {event_type}"
        )


if __name__ == "__main__":
    main()