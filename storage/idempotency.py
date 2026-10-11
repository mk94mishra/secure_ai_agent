import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv


# ============================================================
# Environment
# ============================================================

load_dotenv()

AWS_REGION = os.getenv(
    "AWS_REGION",
    "us-east-1",
)

IDEMPOTENCY_TABLE_NAME = os.getenv(
    "IDEMPOTENCY_TABLE_NAME",
    "secure-ai-idempotency",
)

IDEMPOTENCY_TTL_SECONDS = int(
    os.getenv(
        "IDEMPOTENCY_TTL_SECONDS",
        "86400",
    )
)


# ============================================================
# DynamoDB
# ============================================================

dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION,
)

table = dynamodb.Table(
    IDEMPOTENCY_TABLE_NAME
)


# ============================================================
# Constants
# ============================================================

STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"


# ============================================================
# Exceptions
# ============================================================

class IdempotencyConflict(Exception):
    """
    Raised when another execution already owns
    the idempotency key.
    """

    pass


class IdempotencyAlreadyCompleted(Exception):
    """
    Raised when the same action has already completed.
    """

    def __init__(
        self,
        result: dict[str, Any],
    ):
        self.result = result

        super().__init__(
            "Action has already been executed."
        )


# ============================================================
# Idempotency Store
# ============================================================

class IdempotencyStore:
    """
    DynamoDB-backed idempotency store.

    Table design:

        PK:
            idempotency_key

        Attributes:
            status
            incident_id
            tenant_id
            action
            resource_id
            created_at
            updated_at
            expires_at
            result
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
    # Get Existing Record
    # ========================================================

    def get(
        self,
        idempotency_key: str,
    ) -> dict[str, Any] | None:

        if not idempotency_key:
            raise ValueError(
                "idempotency_key is required."
            )

        response = self.table.get_item(
            Key={
                "idempotency_key": (
                    idempotency_key
                )
            }
        )

        return response.get(
            "Item"
        )

    # ========================================================
    # Claim Execution
    # ========================================================

    def claim(
        self,
        idempotency_key: str,
        incident_id: str,
        tenant_id: str,
        action: str,
        resource_id: str,
    ) -> dict[str, Any]:
        """
        Atomically claim an action for execution.

        Only one worker can successfully create the
        IN_PROGRESS record.

        If the key already exists:

            SUCCESS
                -> raise IdempotencyAlreadyCompleted

            IN_PROGRESS
                -> raise IdempotencyConflict

            FAILED
                -> raise IdempotencyConflict

        This prevents duplicate execution.
        """

        if not idempotency_key:
            raise ValueError(
                "idempotency_key is required."
            )

        now = int(
            time.time()
        )

        expires_at = (
            now
            + IDEMPOTENCY_TTL_SECONDS
        )

        item = {
            "idempotency_key": (
                idempotency_key
            ),
            "status": STATUS_IN_PROGRESS,
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "action": action,
            "resource_id": resource_id,
            "created_at": now,
            "updated_at": now,
            "expires_at": expires_at,
        }

        try:

            self.table.put_item(
                Item=item,
                ConditionExpression=(
                    "attribute_not_exists("
                    "idempotency_key"
                    ")"
                ),
            )

            return item

        except ClientError as exc:

            error_code = (
                exc.response
                .get("Error", {})
                .get("Code")
            )

            if error_code != (
                "ConditionalCheckFailedException"
            ):
                raise

            existing = self.get(
                idempotency_key
            )

            if not existing:

                raise IdempotencyConflict(
                    "Idempotency key already exists."
                )

            status = existing.get(
                "status"
            )

            if status == STATUS_SUCCESS:

                raise IdempotencyAlreadyCompleted(
                    existing.get(
                        "result",
                        existing,
                    )
                )

            raise IdempotencyConflict(
                (
                    "Action is already being "
                    "processed or has previously failed."
                )
            )

    # ========================================================
    # Mark Success
    # ========================================================

    def mark_success(
        self,
        idempotency_key: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Mark an action as successfully executed.
        """

        if not idempotency_key:
            raise ValueError(
                "idempotency_key is required."
            )

        now = int(
            time.time()
        )

        self.table.update_item(
            Key={
                "idempotency_key": (
                    idempotency_key
                )
            },
            UpdateExpression=(
                "SET #status = :status, "
                "#result = :result, "
                "#updated_at = :updated_at"
            ),
            ExpressionAttributeNames={
                "#status": "status",
                "#result": "result",
                "#updated_at": "updated_at",
            },
            ExpressionAttributeValues={
                ":status": STATUS_SUCCESS,
                ":result": result,
                ":updated_at": now,
            },
            ConditionExpression=(
                "attribute_exists("
                "idempotency_key"
                ")"
            ),
        )

        return {
            "status": STATUS_SUCCESS,
            "result": result,
        }

    # ========================================================
    # Mark Failed
    # ========================================================

    def mark_failed(
        self,
        idempotency_key: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Mark an action as failed.

        The record is retained until TTL expiration so
        repeated requests can still see the previous
        execution state.
        """

        if not idempotency_key:
            raise ValueError(
                "idempotency_key is required."
            )

        now = int(
            time.time()
        )

        self.table.update_item(
            Key={
                "idempotency_key": (
                    idempotency_key
                )
            },
            UpdateExpression=(
                "SET #status = :status, "
                "#result = :result, "
                "#updated_at = :updated_at"
            ),
            ExpressionAttributeNames={
                "#status": "status",
                "#result": "result",
                "#updated_at": "updated_at",
            },
            ExpressionAttributeValues={
                ":status": STATUS_FAILED,
                ":result": result,
                ":updated_at": now,
            },
            ConditionExpression=(
                "attribute_exists("
                "idempotency_key"
                ")"
            ),
        )

        return {
            "status": STATUS_FAILED,
            "result": result,
        }

    # ========================================================
    # Check Status
    # ========================================================

    def status(
        self,
        idempotency_key: str,
    ) -> str | None:

        item = self.get(
            idempotency_key
        )

        if not item:
            return None

        return item.get(
            "status"
        )


# ============================================================
# Singleton
# ============================================================

idempotency_store = IdempotencyStore()


# ============================================================
# Convenience Functions
# ============================================================

def get_idempotency_record(
    idempotency_key: str,
) -> dict[str, Any] | None:

    return idempotency_store.get(
        idempotency_key
    )


def claim_idempotency(
    idempotency_key: str,
    incident_id: str,
    tenant_id: str,
    action: str,
    resource_id: str,
) -> dict[str, Any]:

    return idempotency_store.claim(
        idempotency_key=idempotency_key,
        incident_id=incident_id,
        tenant_id=tenant_id,
        action=action,
        resource_id=resource_id,
    )


def mark_idempotency_success(
    idempotency_key: str,
    result: dict[str, Any],
) -> dict[str, Any]:

    return idempotency_store.mark_success(
        idempotency_key=idempotency_key,
        result=result,
    )


def mark_idempotency_failed(
    idempotency_key: str,
    result: dict[str, Any],
) -> dict[str, Any]:

    return idempotency_store.mark_failed(
        idempotency_key=idempotency_key,
        result=result,
    )